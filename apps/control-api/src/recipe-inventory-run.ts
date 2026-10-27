// T08 C07R: one CLOSED-WORLD, host-owned, read-only system.inventory Recipe.
// The HTTP caller can provide neither a plan, authority, grant nor JS source.
// Reuses T03 immutable digest checks, the real T02 ActionController and T06.
// Missing specific operator-provisioned R0 policy => no collector invocation.
import { randomUUID } from 'node:crypto';
import type { ActionController } from '@shun/authorization';
import { ActionPlanSchema, computePlanHash } from '@shun/contracts';
import type { SystemInventoryResult } from '@shun/vertical-system';
import {
  BUILTIN_INVENTORY_RECIPE_ID,
  type BuiltinInventoryReadResult,
} from './inventory-recipe.ts';

type ControllerPort = Pick<ActionController, 'authorizePlan' | 'authorizeEffect'>;

export type AuthorizedInventoryRecipeResult =
  | {
      ok: true;
      status: 'VERIFIED_READONLY_OBSERVATION';
      recipeId: string;
      revisionSha256: string;
      planHash: string;
      snapshot: Extract<SystemInventoryResult, { ok: true }>['snapshot'];
      recipeExecuted: true;
      modelCalls: 0;
      externalDisclosures: readonly [];
    }
  | {
      ok: false;
      code:
        | 'RECIPE_NOT_SAVED'
        | 'RECIPE_AUTHORITY_UNAVAILABLE'
        | 'RECIPE_PLAN_REFUSED'
        | 'RECIPE_AUTHORIZATION_REFUSED'
        | 'RECIPE_OBSERVATION_UNVERIFIED';
    };

export type InventoryRecipeRunHost = Readonly<{
  /** Always re-reads trusted T03 SQLite; callers cannot submit a SHA/source. */
  readCandidate: () => BuiltinInventoryReadResult;
  /** Reads independently issued registry currentness plus real T02 policy. */
  current: () => Promise<
    { kind: 'CURRENT'; policyRevision: string; registryRevision: string } | { kind: 'UNRESOLVABLE' }
  >;
  controller: ControllerPort;
  /** Only fixed T06 collector, not caller-provided shell or process selector. */
  collect: () => SystemInventoryResult;
}>;

function refuse(code: Extract<AuthorizedInventoryRecipeResult, { ok: false }>['code']) {
  return { ok: false as const, code };
}

/** Private trusted-host composition only; never injected from HTTP or Recipe. */
export async function runAuthorizedInventoryRecipe(
  host: InventoryRecipeRunHost,
): Promise<AuthorizedInventoryRecipeResult> {
  try {
    const candidate = host.readCandidate();
    if (
      !candidate.ok ||
      !candidate.saved ||
      candidate.state !== 'PERSISTED_CANDIDATE_ONLY' ||
      candidate.recipeId !== BUILTIN_INVENTORY_RECIPE_ID ||
      !candidate.revisionSha256 ||
      !/^[a-f0-9]{64}$/.test(candidate.revisionSha256) ||
      candidate.executionAuthorized !== false ||
      candidate.modelCalls !== 0
    ) {
      return refuse('RECIPE_NOT_SAVED');
    }

    const current = await host.current();
    if (current.kind !== 'CURRENT') return refuse('RECIPE_AUTHORITY_UNAVAILABLE');
    const taskId = `shun-inventory-recipe-${randomUUID()}`;
    const planWithoutHash = {
      taskId,
      capabilityId: 'system.inventory',
      bindingRefs: ['binding/shun-local-system-inventory'],
      recipeRef: `${candidate.recipeId}@${candidate.revisionSha256}`,
      rankingPolicyRevision: current.registryRevision,
      policySnapshotRevision: current.policyRevision,
      actions: [
        {
          actionId: 'read-system-inventory',
          bindingRef: 'binding/shun-local-system-inventory',
          op: 'system.inventory',
          parameters: { includeProcesses: false },
          sideEffectClass: 'R0',
          requiredPrivilege: 'USER',
        },
      ],
      verificationPlan: {
        verifierId: 'verifier.system-inventory.local-readonly',
        verifierRevision: '1',
        checks: [{ checkId: 'real-windows-local-snapshot-schema' }],
      },
      recoveryPlan: {
        classificationStrategy: 'JOURNAL_AND_POST_STATE',
        reconcileBeforeRetry: true,
        retryAllowedWhen: 'DECLARED_IDEMPOTENT',
      },
    } as const;
    // Validate the entire host-owned plan against the actual contract before
    // deriving the final canonical hash; no unsafe assertion is necessary.
    const proposed = ActionPlanSchema.safeParse({
      ...planWithoutHash,
      planHash: '0'.repeat(64),
    });
    if (!proposed.success) return refuse('RECIPE_PLAN_REFUSED');
    const parsed = ActionPlanSchema.safeParse({
      ...proposed.data,
      planHash: computePlanHash(proposed.data),
    });
    if (!parsed.success) return refuse('RECIPE_PLAN_REFUSED');
    const plan = parsed.data;

    // First gate: real T02 checks exact durable operator rule.
    const admitted = await host.controller.authorizePlan({ plan });
    if (!admitted.ok) return refuse('RECIPE_AUTHORIZATION_REFUSED');
    const grantAction = admitted.authorization.actions.find(
      (item) => item.actionId === 'read-system-inventory',
    );
    const grant = admitted.authorization.grants.find(
      (item) => item.grantId === grantAction?.authorizationRef,
    );
    if (
      admitted.authorization.plan.planHash !== plan.planHash ||
      !grantAction ||
      !grant ||
      admitted.authorization.actions.length !== 1 ||
      admitted.authorization.grants.length !== 1 ||
      grantAction.planHash !== plan.planHash ||
      grantAction.action.op !== 'system.inventory' ||
      grantAction.action.sideEffectClass !== 'R0' ||
      grantAction.authorizationKind !== 'AUTOMATIC'
    ) {
      return refuse('RECIPE_AUTHORIZATION_REFUSED');
    }

    // Second gate: fresh externally issued currentness BEFORE the actual
    // T06 read. A policy or registry move cannot be masked by a valid old grant.
    const fresh = await host.current();
    if (
      fresh.kind !== 'CURRENT' ||
      fresh.policyRevision !== current.policyRevision ||
      fresh.registryRevision !== current.registryRevision
    ) {
      return refuse('RECIPE_AUTHORITY_UNAVAILABLE');
    }
    const allowed = await host.controller.authorizeEffect({
      plan,
      action: grantAction,
      grant,
    });
    if (!allowed.ok) return refuse('RECIPE_AUTHORIZATION_REFUSED');

    // Only after real plan + per-effect private grant approval may this run.
    const result = host.collect();
    if (!result.ok) return refuse('RECIPE_OBSERVATION_UNVERIFIED');
    const snapshot = result.snapshot;
    if (
      snapshot.schema !== 'shun.system-inventory.v02' ||
      snapshot.platform !== 'win32' ||
      snapshot.localOnly !== true ||
      snapshot.externalDisclosures.length !== 0 ||
      snapshot.provenance !== 'node:os+node:fs:statfs' ||
      !Number.isSafeInteger(snapshot.cpuLogicalCount) ||
      snapshot.cpuLogicalCount < 1 ||
      !Number.isFinite(snapshot.memoryTotalBytes) ||
      !Number.isFinite(snapshot.memoryFreeBytes) ||
      snapshot.memoryTotalBytes <= 0 ||
      snapshot.memoryFreeBytes < 0 ||
      snapshot.memoryFreeBytes > snapshot.memoryTotalBytes ||
      !Number.isFinite(snapshot.diskTotalBytes) ||
      !Number.isFinite(snapshot.diskFreeBytes) ||
      snapshot.diskTotalBytes <= 0 ||
      snapshot.diskFreeBytes < 0 ||
      snapshot.diskFreeBytes > snapshot.diskTotalBytes
    ) {
      return refuse('RECIPE_OBSERVATION_UNVERIFIED');
    }
    return {
      ok: true,
      status: 'VERIFIED_READONLY_OBSERVATION',
      recipeId: candidate.recipeId,
      revisionSha256: candidate.revisionSha256,
      planHash: plan.planHash,
      snapshot,
      recipeExecuted: true,
      modelCalls: 0,
      externalDisclosures: [],
    };
  } catch {
    // No grant, policy, key or raw OS error ever appears in the HTTP response.
    return refuse('RECIPE_AUTHORITY_UNAVAILABLE');
  }
}
