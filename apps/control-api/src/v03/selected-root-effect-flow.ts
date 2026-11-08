/**
 * U05-B2 — the one real selected-root effect vertical slice.
 *
 * Binds the Host-selected root (B1 read-only preview + durable human
 * REVIEW_EFFECT approval) to ONE existing `windows.fs.write` action through
 * the EXISTING authority chain, with no second planner, Kernel, approval
 * ledger or storage:
 *   1. the trusted Host derives the concrete write descriptor from the
 *      current evidence-backed preview and canonicalizes it into an
 *      ActionPlan whose planHash is re-derived by the real ActionController
 *      (a self-claimed planHash is never trusted);
 *   2. the independent R2 admission runs through the existing ActionController
 *      with USER_APPROVAL provenance anchored at the durable Guided ledger —
 *      the approval port below is an adapter over that ledger, never a new
 *      authority (the controller still validates the exact planHash/taskId
 *      binding and the USER_APPROVAL origin itself);
 *   3. the HMAC grant issued by the existing AuthorizationAuthority is
 *      durably persisted into the operator's executor authority store
 *      (FilePlanSource/FileGrantSource shapes) — the same store the Windows
 *      effect Host binding reads at effect time;
 *   4. the selected public K receives the frozen `submitWindowsAction` intent
 *      (reference strings only, pair verified first) and mints the ONE effect
 *      Permit; the Windows Host effect-time recheck re-verifies the private
 *      selected-root identity and the exact admitted plan before any effect;
 *   5. the outcome is classified truthfully — only an explicitly terminal,
 *      executed, verified K effect is COMPLETED; refusals stay REFUSED;
 *      everything unresolved stays UNKNOWN. Uncertainty never triggers a
 *      blind retry: the deterministic plan identity makes any second
 *      admission an explicit REFUSED.
 *
 * The bounded HTTP/UI projection carries metadata references only. Absolute
 * root paths, volume/file identity, grant material and plan authority remain
 * Host-private: no caller can construct the OS path, the approval grant, the
 * canonical plan authority or the execution Permit from anything returned
 * here. This module performs no OS effect itself; every physical callback is
 * injected and dry-run in tests.
 */
import { createHash } from 'node:crypto';
import { win32 } from 'node:path';
import {
  type ActionPlan,
  ActionPlanSchema,
  type ApprovalPort,
  type AuthorizationGrant,
  type CurrentAuthorityState,
  computePlanHash,
} from '@shun/contracts';
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import type { SqliteHostSubmitReferenceLedger } from './composition-approval.ts';
import type {
  SelectedRootEffectFacts,
  SelectedRootEffectHostPort,
} from './folder-selection-host.ts';

/** The single concrete write target the Host derives inside the selected root. */
export const SELECTED_ROOT_JOURNAL_FILENAME = 'shun-folder-journal.json';

/** Bounded UI/HTTP projection of the concrete effect proposal (no private paths). */
export interface SelectedRootEffectDescriptor {
  readonly schema: 'shun.host.selected-root-effect-descriptor.v1';
  readonly operation: 'windows.fs.write';
  readonly relativeTarget: string;
  readonly expectedChange: string;
  readonly undo: string;
  readonly risk: 'R2';
  readonly sizeBytes: number;
  readonly evidenceRevision: string;
  readonly expiresAtUnixMs: number;
  readonly executionAuthorized: false;
}

export type SelectedRootEffectDerivation =
  | Readonly<{
      ok: true;
      descriptor: SelectedRootEffectDescriptor;
      plan: ActionPlan;
    }>
  | Readonly<{ ok: false; code: string }>;

/**
 * Deterministically derive the bounded descriptor + the canonical ActionPlan
 * from Host-verified facts. The same durable approved step always produces
 * the same planHash, so the operator-reviewed proposal and the admitted plan
 * are provably one plan, and the replay fence can key on the plan identity.
 * `policySnapshotRevision` is the authority's CURRENT policy at admission
 * time; the descriptor-only proposal path may omit it (the descriptor never
 * carries the revision, and a proposal is a display projection, not a plan).
 */
export function deriveSelectedRootEffect(input: {
  readonly facts: SelectedRootEffectFacts;
  readonly policySnapshotRevision?: string;
}): SelectedRootEffectDerivation {
  const { facts } = input;
  const preview = facts.preview;
  if (
    preview.schema !== 'shun.host.selected-root-plan-preview.v1' ||
    preview.status !== 'PROPOSAL_ONLY' ||
    preview.executionAuthorized !== false ||
    typeof preview.planDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(preview.planDigest) ||
    facts.taskId !== preview.taskId ||
    facts.journeyId !== preview.journeyId ||
    facts.selectionRef !== preview.selectedRootRef ||
    facts.actionPreviewRef !== preview.actionPreviewRef
  ) {
    return { ok: false, code: 'SELECTED_ROOT_EFFECT_FACTS_REFUSED' };
  }
  const content = stableJson({
    schema: 'shun.host.selected-root-journal.v1',
    taskId: facts.taskId,
    journeyId: facts.journeyId,
    caseRef: preview.caseRef,
    originStepId: facts.originStepId,
    selectedRootRef: facts.selectionRef,
    evidenceRevision: preview.evidenceRevision,
    relativeTargets: preview.relativeTargets,
    directoryCount: preview.directoryCount,
    rootFileCount: preview.rootFileCount,
    totalBytes: preview.totalBytes,
  });
  if (content.length > 65_536) {
    return { ok: false, code: 'SELECTED_ROOT_EFFECT_CONTENT_REFUSED' };
  }
  // The binding identity embeds the exact B1 preview digest: the admitted
  // plan is bound to the evidence revision the human actually reviewed, and
  // a stale/changed preview can never authorize this plan.
  const bindingRef = `selected-root-preview-${preview.planDigest.slice(0, 32)}`;
  const actionId = 'windows-fs-write-selected-root-journal';
  const targetPath = win32.join(facts.rootPath, SELECTED_ROOT_JOURNAL_FILENAME);
  const planNoHash: Omit<ActionPlan, 'planHash'> = {
    taskId: facts.taskId,
    capabilityId: 'windows',
    bindingRefs: [bindingRef],
    rankingPolicyRevision: 'shun-v030-selected-root-r2',
    policySnapshotRevision: input.policySnapshotRevision ?? 'shun-v030-selected-root-r2-proposal',
    actions: [
      {
        actionId,
        bindingRef,
        op: 'windows.fs.write',
        parameters: { path: targetPath, content, encoding: 'utf8' },
        sideEffectClass: 'R2',
        requiredPrivilege: 'USER',
        filesystemScope: { read: [facts.rootPath], write: [targetPath] },
        timeoutMs: 30_000,
        expectedState: {
          path: targetPath,
          exists: true,
          sha256: createHash('sha256').update(content, 'utf8').digest('hex'),
        },
      },
    ],
    verificationPlan: {
      verifierId: 'windows.fs.verify',
      verifierRevision: 'v0.3.0',
      checks: [{ checkId: 'selected-root-journal-poststate' }],
      oracle: {
        precommitted: true,
        spec: { op: 'windows.fs.verify', path: targetPath, expectExists: true },
      },
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
      checkpointRef: `undo:windows.fs.delete:${SELECTED_ROOT_JOURNAL_FILENAME}`,
    },
  };
  // The placeholder satisfies the ActionPlan shape for the hash input; the
  // hash itself excludes planHash, and the parsed plan re-validates every
  // semantic invariant before anything downstream trusts it.
  const plan: ActionPlan = ActionPlanSchema.parse({
    ...planNoHash,
    planHash: computePlanHash({ ...planNoHash, planHash: '0'.repeat(64) } as ActionPlan),
  });
  const descriptor: SelectedRootEffectDescriptor = {
    schema: 'shun.host.selected-root-effect-descriptor.v1',
    operation: 'windows.fs.write',
    relativeTarget: SELECTED_ROOT_JOURNAL_FILENAME,
    expectedChange: `create or update one metadata journal file (${content.length} bytes) inside the selected root`,
    undo: `delete the journal file (${SELECTED_ROOT_JOURNAL_FILENAME}) restores the prior state`,
    risk: 'R2',
    sizeBytes: content.length,
    evidenceRevision: preview.evidenceRevision,
    expiresAtUnixMs: preview.expiresAtUnixMs,
    executionAuthorized: false as const,
  };
  return { ok: true, descriptor, plan };
}

/** Canonical JSON: keys sorted at every depth; stable across processes. */
function stableJson(value: unknown): string {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(String(value));
}

/**
 * The R2 approval adapter over the durable Guided ledger. It implements the
 * EXISTING contracts ApprovalPort consumed by the real ActionController; it
 * is not a new approval authority. A USER_APPROVAL decision is returned only
 * when the guided ledger durably holds the human APPROVE terminal (history
 * ACCEPTED) for the exact review-plan step this flow verified — bound to the
 * exact taskId; the controller re-binds the decision to the exact planHash
 * itself and refuses any other origin.
 */
export function createGuidedReviewApprovalPort(input: {
  readonly guided: Pick<HostGuidedService, 'readTrustedContext' | 'state'>;
  readonly expect: {
    readonly taskId: string;
    readonly originStepId: string;
    readonly caseRefJson: string;
    readonly actionPreviewRef: string;
  };
}): ApprovalPort {
  const denied = (request: { planHash: string; taskId: string }, reason: string) => ({
    approved: false as const,
    planHash: request.planHash,
    taskId: request.taskId,
    approvedBy: 'DURABLE_POLICY' as const,
    approvalId: 'guided-review:refused',
    reason,
  });
  return {
    async requestApproval(request) {
      if (request.taskId !== input.expect.taskId) {
        return denied(request, 'approval request names a different task');
      }
      const context = input.guided.readTrustedContext();
      const terminal = input.guided.state().history.at(-1);
      if (
        !context ||
        context.state !== 'CONSUMED' ||
        context.step.kind !== 'REVIEW_EFFECT' ||
        context.step.templateRef.artifactId !== 'shun.guided.review-plan' ||
        context.step.taskId !== input.expect.taskId ||
        context.step.stepId !== input.expect.originStepId ||
        stableJson(context.step.caseRef) !== input.expect.caseRefJson ||
        context.step.actionPreviewRef !== input.expect.actionPreviewRef ||
        terminal?.stepId !== input.expect.originStepId ||
        terminal?.status !== 'ACCEPTED'
      ) {
        return denied(
          request,
          'no durable human REVIEW_EFFECT approval for this exact step binding',
        );
      }
      return {
        approved: true,
        planHash: request.planHash,
        taskId: request.taskId,
        approvedBy: 'USER_APPROVAL',
        approvalId: `guided-review:${input.expect.originStepId}`,
      };
    },
  };
}

/** Composition-injected effect authority (the REAL Shun authorization stack). */
export interface SelectedRootEffectAuthority {
  /** Runs the REAL ActionController R2 route with the Guided approval adapter. */
  authorizePlan(input: {
    readonly plan: ActionPlan;
    readonly expect: {
      readonly taskId: string;
      readonly originStepId: string;
      readonly caseRefJson: string;
      readonly actionPreviewRef: string;
    };
  }): Promise<
    | { ok: true; plan: ActionPlan; grants: AuthorizationGrant[] }
    | { ok: false; code: string; detail: string }
  >;
  readCurrentAuthority(): Promise<CurrentAuthorityState>;
  /** The CURRENT policy revision the plan must be formed under. */
  policySnapshotRevision(): string;
  writePlanRecord(plan: ActionPlan): void;
  writeGrantRecord(grant: AuthorizationGrant): void;
  writeCurrentAuthority(state: CurrentAuthorityState): void;
  hasPlanRecord(planHash: string): boolean;
  /** True only when the executor store's HMAC key matches this stack's secret. */
  hmacKeyCoherent(): boolean;
}

export type SelectedRootEffectSubmitReceipt = Readonly<{
  readonly status: 'COMPLETED' | 'ADMITTED' | 'REFUSED' | 'UNKNOWN';
  readonly code?: string;
  readonly detail?: string;
  readonly sendCalls: 0 | 1;
  readonly refusedAtUnixMs?: number;
  readonly effect?: Readonly<{
    readonly actionRef: string;
    readonly relativeTarget: string;
    readonly operation: 'windows.fs.write';
    readonly expectedChange: string;
    readonly terminal?: unknown;
    readonly recoveryClassification?: unknown;
    readonly postStateVerified?: unknown;
  }>;
}>;

export interface SelectedRootEffectSubmitDeps {
  readonly host: SelectedRootEffectHostPort;
  readonly references: Pick<SqliteHostSubmitReferenceLedger, 'verify'>;
  readonly facade: { readonly send: (payload: unknown) => Promise<unknown> };
  readonly authority: SelectedRootEffectAuthority;
  readonly classifyJourneyKernelResult: (result: unknown) => {
    readonly status: string;
    readonly code?: string;
    readonly sendCalls: number;
    readonly result?: unknown;
  };
  readonly now: () => number;
}

const REFS_BODY_KEYS = ['approvalRef', 'caseId', 'currentnessRef'];
const CASE_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
const REF = /^shun\.(currentness|approval)\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/**
 * The composition-owned one-shot effect admission. The caller supplies
 * reference strings only; every authority-bearing value (plan, grant,
 * permit) is derived Host-side from the durably approved preview.
 */
export function createSelectedRootEffectSubmit(
  deps: SelectedRootEffectSubmitDeps,
): (raw: unknown) => Promise<SelectedRootEffectSubmitReceipt> {
  let attemptCounter = 0;
  const refused = (
    code: string,
    detail: string,
    sendCalls: 0 | 1 = 0,
  ): SelectedRootEffectSubmitReceipt => ({
    status: 'REFUSED',
    code,
    detail,
    sendCalls,
    ...(sendCalls === 0 ? { refusedAtUnixMs: deps.now() } : {}),
  });
  return async (raw: unknown): Promise<SelectedRootEffectSubmitReceipt> => {
    if (
      typeof raw !== 'object' ||
      raw === null ||
      Array.isArray(raw) ||
      Object.keys(raw).sort().join('|') !== REFS_BODY_KEYS.join('|')
    ) {
      return refused(
        'GATEWAY_INPUT_INVALID',
        'submission must be exactly {caseId, currentnessRef, approvalRef} — no path, plan, grant or permit input is accepted',
      );
    }
    const value = raw as Record<string, unknown>;
    if (
      typeof value.caseId !== 'string' ||
      !CASE_ID.test(value.caseId) ||
      typeof value.currentnessRef !== 'string' ||
      !REF.test(value.currentnessRef) ||
      !value.currentnessRef.startsWith('shun.currentness.v1/') ||
      typeof value.approvalRef !== 'string' ||
      !REF.test(value.approvalRef) ||
      !value.approvalRef.startsWith('shun.approval.v1/') ||
      value.currentnessRef === value.approvalRef
    ) {
      return refused('GATEWAY_INPUT_INVALID', 'caseId/reference pair is not well formed');
    }
    const caseId = value.caseId;
    const currentnessRef = value.currentnessRef;
    const approvalRef = value.approvalRef;
    // Post-approval Host readback: the durable APPROVE terminal + preview
    // integrity + fresh native root identity, all verified inside the Host.
    const prepared = await deps.host.prepareSelectedRootEffect();
    if (!prepared.ok) {
      return refused(prepared.code, 'trusted Host refused the effect preparation');
    }
    if (prepared.facts.taskId !== caseId) {
      return refused('HOST_CASE_NOT_CURRENT', 'no approved Case for this caseId');
    }
    const verified = deps.references.verify({
      caseId,
      stepId: prepared.facts.originStepId,
      currentnessRef,
      approvalRef,
    });
    if (verified.status !== 'VALID') {
      return refused(verified.code, 'Host-issued reference pair rejected');
    }
    if (!deps.authority.hmacKeyCoherent()) {
      return refused(
        'SELECTED_ROOT_EFFECT_AUTHORITY_UNAVAILABLE',
        'the executor authority store is not provisioned for this authorization stack',
      );
    }
    const derived = deriveSelectedRootEffect({
      facts: prepared.facts,
      policySnapshotRevision: deps.authority.policySnapshotRevision(),
    });
    if (!derived.ok)
      return refused(
        derived.code,
        'the concrete effect plan could not be derived from the approved preview',
      );
    const { plan, descriptor } = derived;
    // Durable replay fence keyed on the deterministic canonical plan
    // identity: a second admission (double click, replay, blind retry of an
    // UNKNOWN) refuses before any authority work or K send.
    if (deps.authority.hasPlanRecord(plan.planHash)) {
      return refused(
        'SELECTED_ROOT_EFFECT_REPLAY_REFUSED',
        'this approved review step already admitted its effect plan; uncertain outcomes are reconciled, never retried',
      );
    }
    const authorized = await deps.authority.authorizePlan({
      plan,
      expect: {
        taskId: prepared.facts.taskId,
        originStepId: prepared.facts.originStepId,
        caseRefJson: prepared.facts.caseRefJson,
        actionPreviewRef: prepared.facts.actionPreviewRef,
      },
    });
    if (!authorized.ok) return refused(authorized.code, authorized.detail);
    const grant = authorized.grants[0];
    if (!grant) {
      return refused(
        'SELECTED_ROOT_EFFECT_GRANT_UNAVAILABLE',
        'the authority issued no grant for the admitted plan',
      );
    }
    const action = plan.actions[0];
    if (!action) {
      return refused('SELECTED_ROOT_EFFECT_PLAN_INVALID', 'the admitted plan carries no action');
    }
    // Persist the exact admitted plan + HMAC grant + current authority into
    // the operator's executor authority store (FilePlanSource/FileGrantSource
    // shapes), then the durable Host admission binding the K permit to the
    // private root identity. A crash after this point leaves the records
    // without a K send; the replay fence turns any retry into REFUSED.
    try {
      deps.authority.writePlanRecord(plan);
      deps.authority.writeGrantRecord(grant);
      deps.authority.writeCurrentAuthority(await deps.authority.readCurrentAuthority());
      deps.host.recordSelectedRootEffectAdmission({
        taskId: prepared.facts.taskId,
        journeyId: prepared.facts.journeyId,
        caseRefJson: prepared.facts.caseRefJson,
        originStepId: prepared.facts.originStepId,
        selectionRef: prepared.facts.selectionRef,
        actionPreviewRef: prepared.facts.actionPreviewRef,
        previewPlanDigest: prepared.facts.preview.planDigest,
        planHash: plan.planHash,
        relativeTarget: SELECTED_ROOT_JOURNAL_FILENAME,
        expiresAtUnixMs: Math.min(
          prepared.facts.expiresAtUnixMs,
          prepared.facts.preview.expiresAtUnixMs,
        ),
      });
    } catch {
      return refused(
        'SELECTED_ROOT_EFFECT_AUTHORITY_DURABILITY_UNKNOWN',
        'the authority store rejected the admitted records',
      );
    }
    let kernelResult: unknown;
    try {
      kernelResult = await deps.facade.send({
        intentType: 'submitWindowsAction',
        instanceKey: caseId,
        messageId: `msg-sre-${plan.planHash.slice(0, 24)}-${++attemptCounter}`,
        input: {
          actionRef: action.actionId,
          planRef: plan.planHash,
          grantRef: grant.grantId,
          taskId: caseId,
        },
      });
    } catch {
      return {
        status: 'UNKNOWN',
        code: 'SEND_OUTCOME_UNKNOWN',
        sendCalls: 1,
        effect: effectProjection(action.actionId, descriptor),
      };
    }
    const classified = deps.classifyJourneyKernelResult(kernelResult);
    if (classified.status === 'COMPLETED') {
      return {
        status: 'COMPLETED',
        sendCalls: 1,
        effect: effectProjection(action.actionId, descriptor, classified.result),
      };
    }
    if (classified.status === 'REFUSED' || classified.status === 'KERNEL_REFUSED') {
      return {
        status: 'REFUSED',
        code: classified.code ?? 'KERNEL_REFUSED',
        sendCalls: 1,
        effect: effectProjection(action.actionId, descriptor),
      };
    }
    if (classified.status === 'ADMITTED') {
      // The K accepted the submission but no terminal effect outcome exists
      // yet: ADMITTED is honest — never a success, never a retry trigger.
      return {
        status: 'ADMITTED',
        sendCalls: 1,
        effect: effectProjection(action.actionId, descriptor),
      };
    }
    return {
      status: 'UNKNOWN',
      code: classified.code ?? 'EFFECT_RESULT_UNKNOWN',
      sendCalls: 1,
      effect: effectProjection(action.actionId, descriptor),
    };
  };
}

function effectProjection(
  actionRef: string,
  descriptor: SelectedRootEffectDescriptor,
  kernelResult?: unknown,
): SelectedRootEffectSubmitReceipt['effect'] {
  // Only the closed Host receipt vocabulary survives into the projection.
  const output = extractEffectOutput(kernelResult);
  return Object.freeze({
    actionRef,
    relativeTarget: descriptor.relativeTarget,
    operation: descriptor.operation,
    expectedChange: descriptor.expectedChange,
    ...(output
      ? {
          terminal: output.terminal,
          recoveryClassification: output.recoveryClassification,
          postStateVerified: output.postStateVerified,
        }
      : {}),
  });
}

function extractEffectOutput(kernelResult: unknown):
  | {
      readonly terminal: unknown;
      readonly recoveryClassification: unknown;
      readonly postStateVerified: unknown;
    }
  | undefined {
  if (typeof kernelResult !== 'object' || kernelResult === null) return undefined;
  const effects = (kernelResult as { admitted?: { effects?: unknown[] } }).admitted?.effects;
  const effect = Array.isArray(effects) ? effects[0] : undefined;
  const output = (effect as { output?: { outcome?: { output?: unknown } } } | undefined)?.output
    ?.outcome?.output;
  if (typeof output !== 'object' || output === null) return undefined;
  const record = output as Record<string, unknown>;
  return {
    terminal: record.terminal,
    recoveryClassification: record.recoveryClassification,
    postStateVerified: record.postStateVerified,
  };
}
