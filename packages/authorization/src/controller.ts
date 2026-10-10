// Trust/Policy/Action Controller (L2 §9.1) — the central authority side of
// T02 (`packages/authorization/**`).
//
// Provider adapters and Recipes produce plan PROPOSALS, never raw execution
// authority. The controller:
//   1. validates the proposal at intake (schema, semantic invariants, hash
//      re-derivation — a self-claimed planHash is never trusted),
//   2. re-establishes CURRENT authority/policy state and refuses under
//      unresolvable/non-ACTIVE policy or a proposal formed under a stale
//      policy revision,
//   3. recomputes the EFFECTIVE risk classification per action — the declared
//      class is a floor; policy risk guards may raise it, nothing lowers it
//      (L2 §9.1),
//   4. routes each action through the R0-R3 disposition: durable policy for
//      R0-R2 only when a sufficiently specific rule covers it; explicit
//      approval otherwise; R3 is explicit approval only (L2 §9.2),
//   5. obtains a BOUNDED approval bound to the exact planHash + taskId — a
//      decision for any other plan is void,
//   6. requests grant-backed AuthorizedActions from the AuthorizationAuthority
//      (one grant per distinct required privilege level),
//   7. and gates EVERY effect: `authorizeEffect` re-establishes current
//      authority/policy state immediately before the effect and re-validates
//      the full presentation fail-closed — a policy/authority move, revocation
//      or unreadable currentness record between two effects voids the
//      remaining effects.
//
// The controller performs no execution and no privileged I/O. It never trusts
// caller self-asserted grants: presentations are only ever accepted through
// validateGrantPresentation with the authority's own verifier and freshly
// resolved currentness.

import type { ApprovalPort } from '@shun/contracts';
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizationGrant,
  AuthorizationGrantPresentationSchema,
  type AuthorizationKind,
  type AuthorizedAction,
  AuthorizedActionSchema,
  computePlanHash,
  type GrantValidationResult,
  type PrivilegeLevel,
  pathWithin,
  type RiskClass,
  ShunContractError,
  validateGrantPresentation,
} from '@shun/contracts';
import type { AuthorizationAuthority } from './authority.ts';
import type { ControllerRefusal, RefusalCode } from './failures.ts';
import {
  type DurablePolicyRule,
  maxRiskClass,
  type PolicySnapshotRecord,
  PolicySnapshotRecordSchema,
  type PolicyStateStore,
  RISK_RANK,
  ruleCoversScope,
} from './policy.ts';

/** Default bounded per-action validity; always capped by the grant's own expiry. */
export const DEFAULT_ACTION_TTL_MS = 5 * 60 * 1000;

export interface ActionControllerConfig {
  authority: AuthorizationAuthority;
  /** Same durable policy state the authority writes authority events into. */
  policyState: PolicyStateStore;
  /** Control-surface approval seam (L2 §12); the durable approval record lives in ShunStore. */
  approvals: ApprovalPort;
  clock: () => string;
  actionTtlMs?: number;
}

/** The strongest required disposition across the plan decides the grant kind. */
export interface PlanDisposition {
  kind: AuthorizationKind;
  /** Rule ids that authorized policy-backed actions (empty for explicit approval). */
  ruleIds: string[];
  /** Durable approval record reference when kind is EXPLICIT_APPROVAL. */
  approvalRef?: string;
}

export interface AuthorizedPlan {
  plan: ActionPlan;
  disposition: PlanDisposition;
  /** One grant per distinct required privilege level across the plan's actions. */
  grants: AuthorizationGrant[];
  /** AuthorizedActions, each bound to its privilege group's grant. */
  actions: AuthorizedAction[];
}

export type PlanAuthorizationResult =
  | { ok: true; authorization: AuthorizedPlan }
  | ControllerRefusal;

/** Effective classification of one action plus how its authorization is routed. */
interface ActionRouting {
  actionId: string;
  effectiveRisk: RiskClass;
  /** Present when a sufficiently specific durable rule covers the action. */
  rule?: DurablePolicyRule;
  requiresExplicitApproval: boolean;
}

export class ActionController {
  readonly #config: ActionControllerConfig;
  readonly #actionTtlMs: number;

  constructor(config: ActionControllerConfig) {
    this.#config = config;
    this.#actionTtlMs = config.actionTtlMs ?? DEFAULT_ACTION_TTL_MS;
  }

  /**
   * Authorize a whole plan proposal: intake validation → current-policy
   * check → effective risk classification → disposition (durable rule and/or
   * bounded approval) → grant-backed AuthorizedActions. Expected denials are
   * returned as structured refusals, never thrown; unexpected authority
   * failures (typed ShunContractError from issuance) are converted the same
   * way with their grant code preserved.
   */
  async authorizePlan(input: { plan: unknown }): Promise<PlanAuthorizationResult> {
    const refusal = (code: RefusalCode, detail: string): PlanAuthorizationResult => ({
      ok: false,
      code,
      detail,
    });

    // 1. Intake: schema + semantics + hash re-derivation. The proposal's own
    // planHash claim is verified, never trusted (plan tamper invalidates
    // every downstream approval — U-06 D2-b).
    const parsedPlan = ActionPlanSchema.safeParse(input.plan);
    if (!parsedPlan.success) {
      return refusal('PLAN_INVALID', 'proposed plan is not a valid ActionPlan');
    }
    const plan = parsedPlan.data;
    if (computePlanHash(plan) !== plan.planHash) {
      return refusal(
        'PLAN_INVALID',
        'proposed plan hash does not match the re-derived canonical hash of the plan content',
      );
    }

    // 2. Current policy: fail closed on unresolvable state, non-ACTIVE
    // policy, or a proposal formed under a revision that is no longer
    // current (stale proposals re-plan, they do not downgrade checks).
    const current = await this.#config.authority.currentAuthority();
    if (current.kind === 'UNRESOLVABLE') {
      return refusal('AUTHORIZATION_STATE_UNRESOLVABLE', current.reason);
    }
    if (current.policyStatus === 'REVOKED') {
      return refusal('POLICY_BLOCKED', 'current policy revision is revoked');
    }
    if (current.policyStatus === 'SUPERSEDED') {
      return refusal('POLICY_BLOCKED', 'current policy revision is superseded');
    }
    if (plan.policySnapshotRevision !== current.policySnapshotRevision) {
      return refusal(
        'POLICY_BLOCKED',
        `plan was formed under policy ${plan.policySnapshotRevision} but current policy is ${current.policySnapshotRevision}; re-plan under current policy`,
      );
    }
    const policy = PolicySnapshotRecordSchema.parse(
      await this.#config.policyState.loadCurrentPolicy(),
    );

    // 3+4. Effective risk and per-action routing.
    const routings: ActionRouting[] = plan.actions.map((action) => {
      const guarded = this.#effectiveRisk(action, policy);
      const rule = policy.rules.find(
        (candidate) =>
          candidate.capabilityId === plan.capabilityId &&
          candidate.op === action.op &&
          riskRank(candidate.maxRiskClass) >= riskRank(guarded) &&
          ruleCoversScope(
            {
              privilegeLevel: action.requiredPrivilege,
              filesystem: action.filesystemScope,
              network: action.networkScope,
              registry: action.registryScope,
            },
            candidate,
            pathWithin,
          ),
      );
      return {
        actionId: action.actionId,
        effectiveRisk: guarded,
        rule,
        requiresExplicitApproval: guarded === 'R3' || (guarded !== 'R0' && !rule),
      };
    });
    const unroutedR0 = routings.find(
      (routing) =>
        routing.effectiveRisk === 'R0' && !routing.rule && !routing.requiresExplicitApproval,
    );
    if (unroutedR0) {
      return {
        ok: false,
        code: 'POLICY_BLOCKED',
        detail: `read-only action ${unroutedR0.actionId} has no durable policy rule allowing automatic execution`,
        actionIds: [unroutedR0.actionId],
      };
    }

    // 5. Bounded approval: any approval-requiring action makes the whole
    // plan an explicit-approval authorization bound to the exact planHash.
    let disposition: PlanDisposition;
    if (routings.some((routing) => routing.requiresExplicitApproval)) {
      const decision = await this.#config.approvals.requestApproval({
        taskId: plan.taskId,
        planHash: plan.planHash,
        summary: this.#approvalSummary(plan, routings),
        evidenceRefs: [],
      });
      if (decision.approved !== true) {
        return refusal('APPROVAL_REJECTED', `approval for plan ${plan.planHash} was not granted`);
      }
      // The decision is only valid for the exact plan and task it names.
      if (decision.planHash !== plan.planHash || decision.taskId !== plan.taskId) {
        return refusal(
          'APPROVAL_INVALID',
          `approval decision ${decision.approvalId} does not bind the exact plan/task presented (plan ${plan.planHash}, task ${plan.taskId})`,
        );
      }
      disposition = { kind: 'EXPLICIT_APPROVAL', ruleIds: [], approvalRef: decision.approvalId };
    } else {
      const ruleIds = [
        ...new Set(routings.flatMap((routing) => (routing.rule ? [routing.rule.ruleId] : []))),
      ];
      const allReadonly = routings.every((routing) => routing.effectiveRisk === 'R0');
      disposition = {
        kind: allReadonly ? 'AUTOMATIC' : 'DURABLE_POLICY',
        ruleIds,
      };
    }

    // 6. One grant per distinct required privilege level; the grant scope is
    // the union of the group's declared scopes.
    const groups = this.#groupByPrivilege(plan);
    const grants: AuthorizationGrant[] = [];
    for (const group of groups) {
      try {
        const grant = await this.#config.authority.issue({
          taskId: plan.taskId,
          planHash: plan.planHash,
          policySnapshotRevision: current.policySnapshotRevision,
          actionScope: {
            actionIds: group.actionIds,
            privilegeLevel: group.privilegeLevel,
            ...(group.filesystem ? { filesystem: group.filesystem } : {}),
            ...(group.network ? { network: group.network } : {}),
            ...(group.registry ? { registry: group.registry } : {}),
          },
          authorizationKind: disposition.kind,
          ...(disposition.approvalRef ? { approvalRef: disposition.approvalRef } : {}),
        });
        grants.push(grant);
        group.grant = grant;
      } catch (error) {
        return this.#refusalFromIssuance(error);
      }
    }

    // AuthorizedActions: bounded validity, grant-backed, exact plan identity.
    const now = this.#config.clock();
    const actions: AuthorizedAction[] = plan.actions.map((action) => {
      const group = groups.find((candidate) => candidate.actionIds.includes(action.actionId));
      const grant = group?.grant;
      if (!grant) {
        throw new Error(
          `internal: action ${action.actionId} was not assigned a privilege group grant`,
        );
      }
      return AuthorizedActionSchema.parse({
        taskId: plan.taskId,
        actionId: action.actionId,
        planHash: plan.planHash,
        policySnapshotRevision: plan.policySnapshotRevision,
        authorizationKind: disposition.kind,
        authorizationRef: grant.grantId,
        expiresAt: boundedInstant(grant.expiresAt, Date.parse(now) + this.#actionTtlMs),
        action,
      });
    });

    return { ok: true, authorization: { plan, disposition, grants, actions } };
  }

  /**
   * Per-effect gate (L2 §4.6.1 currentness, §9.1): re-establish CURRENT
   * authority/policy state immediately before the side effect and re-validate
   * the full presentation — authenticity, currentness, expiry, scope and
   * exact plan/action binding — fail-closed. This is what makes a policy
   * move, authority rotation, revocation or corrupt currentness record
   * between two effects void the remaining effects.
   */
  async authorizeEffect(input: {
    plan: ActionPlan;
    action: AuthorizedAction;
    grant: unknown;
  }): Promise<GrantValidationResult> {
    const presented = AuthorizationGrantPresentationSchema.safeParse(input.grant);
    if (!presented.success) {
      return {
        ok: false,
        code: 'GRANT_MALFORMED',
        detail: 'presented grant is not a valid grant presentation',
      };
    }
    const current = await this.#config.authority.currentAuthority();
    return validateGrantPresentation({
      grant: presented.data,
      plan: input.plan,
      action: input.action,
      currentAuthority: current,
      now: this.#config.clock(),
      verifyIntegrity: this.#config.authority.integrityVerifier,
    });
  }

  #effectiveRisk(action: ActionPlan['actions'][number], policy: PolicySnapshotRecord) {
    let risk = action.sideEffectClass;
    for (const guard of policy.riskGuards) {
      const matches =
        (guard.op !== undefined && guard.op === action.op) ||
        (guard.filesystemWritePrefix !== undefined &&
          (action.filesystemScope?.write ?? []).some((p) =>
            pathWithin(p, guard.filesystemWritePrefix as string),
          ));
      if (matches) risk = maxRiskClass(risk, guard.minRiskClass);
    }
    return risk;
  }

  #groupByPrivilege(plan: ActionPlan) {
    interface Group {
      privilegeLevel: PrivilegeLevel;
      actionIds: string[];
      filesystem?: { read: string[]; write: string[] };
      network?: { allowed: boolean; domains?: string[] };
      registry?: { write: string[] };
      grant?: AuthorizationGrant;
    }
    const groups: Group[] = [];
    for (const action of plan.actions) {
      let group = groups.find((candidate) => candidate.privilegeLevel === action.requiredPrivilege);
      if (!group) {
        group = { privilegeLevel: action.requiredPrivilege, actionIds: [] };
        groups.push(group);
      }
      group.actionIds.push(action.actionId);
      if (action.filesystemScope) {
        group.filesystem ??= { read: [], write: [] };
        group.filesystem.read.push(...action.filesystemScope.read);
        group.filesystem.write.push(...action.filesystemScope.write);
      }
      if (action.networkScope?.allowed) {
        group.network ??= { allowed: true, domains: [] };
        group.network.domains = [
          ...(group.network.domains ?? []),
          ...(action.networkScope.domains ?? []),
        ];
      }
      if (action.registryScope) {
        group.registry ??= { write: [] };
        group.registry.write.push(...action.registryScope.write);
      }
    }
    return groups;
  }

  #approvalSummary(plan: ActionPlan, routings: ActionRouting[]): string {
    const parts = plan.actions.map((action) => {
      const routing = routings.find((candidate) => candidate.actionId === action.actionId);
      const risk = routing?.effectiveRisk ?? action.sideEffectClass;
      return `${action.actionId} ${action.op} [${risk}]`;
    });
    return `plan ${plan.capabilityId} for task ${plan.taskId}: ${parts.join('; ')}`;
  }

  #refusalFromIssuance(error: unknown): PlanAuthorizationResult {
    if (error instanceof ShunContractError) {
      return { ok: false, code: error.code, detail: error.message };
    }
    throw error;
  }
}

function riskRank(risk: RiskClass): number {
  return RISK_RANK[risk];
}

/** min(isoInstant, epochMs) as ISO 8601 UTC — bounded action expiry. */
function boundedInstant(isoInstant: string, epochMs: number): string {
  const a = Date.parse(isoInstant);
  return new Date(Math.min(a, epochMs)).toISOString();
}
