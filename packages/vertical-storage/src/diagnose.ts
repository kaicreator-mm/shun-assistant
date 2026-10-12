// Loop C orchestration (L2 §14.3): R0 observation → evidence-backed
// attribution → fail-closed classification → R2 plan/preview/checkpoint →
// approval → authorization → bounded action → reclaimed-space +
// protected-asset verification, emitting the frozen C-003 output.
//
// Authority stays external to this vertical: approval flows through the
// ApprovalPort, grants are issued by the AuthorizationPort, and the executor
// re-verifies the presentation itself. The seams are injected, so the real
// controller packages (T02/T03/T04) can replace the test doubles without any
// change here (mock-seams-first per the DAG row).
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import type { ActionController, AuthorizedPlan } from '@shun/authorization';
import {
  type AuthorizedAction,
  type CurrentAuthorityState,
  type ExecutionReceipt,
  type GrantIntegrityVerifier,
  R2_GATE_PHASES,
  R2GateRecordSchema,
  type StorageDiagnoseInput,
  StorageDiagnoseInputSchema,
  type StorageDiagnoseOutput,
  StorageDiagnoseOutputSchema,
  type VerificationInput,
} from '@shun/contracts';
import { attributeGrowth } from './attribute.ts';

import { StorageVerticalError } from './errors.ts';
import { executeBoundedCleanup } from './execute.ts';
import { measureDirectoryNow, observeStorage } from './observe.ts';
import { buildCleanupPlan, type CleanupPlanProposal } from './plan.ts';
import { type ResolvedScope, resolveScope, type StorageScope } from './scope.ts';
import { fingerprintPath, VERIFIER_ID, VERIFIER_REVISION, verifyStorageCleanup } from './verify.ts';

/** Control-surface seams this vertical consumes; concrete implementations live in their own packages. */
export interface StorageDiagnosePorts {
  requestApproval(request: {
    taskId: string;
    planHash: string;
    summary: string;
    evidenceRefs: string[];
  }): Promise<{ approvalId: string; approved: boolean; reason?: string }>;
  issueGrant(request: {
    taskId: string;
    planHash: string;
    policySnapshotRevision: string;
    actionScope: {
      actionIds: string[];
      privilegeLevel: 'NONE' | 'USER' | 'ELEVATED';
      filesystem?: { read: string[]; write: string[] };
      network?: { allowed: boolean };
    };
    authorizationKind: 'EXPLICIT_APPROVAL';
    approvalRef: string;
  }): Promise<unknown>;
  currentAuthority(): Promise<CurrentAuthorityState>;
  verifyIntegrity: GrantIntegrityVerifier;
}

export type StorageActionController = Pick<ActionController, 'authorizePlan' | 'authorizeEffect'>;

export interface StorageDiagnoseRuntime {
  /**
   * Legacy/reference seam retained for package tests and compatibility.
   * T10 production integration must use controller instead.
   */
  ports?: StorageDiagnosePorts;
  /** Real production authorization path: plan intake + per-effect currentness gate. */
  controller?: StorageActionController;
  /** Declared disposable-candidate roots on the target volume (bounded scope policy). */
  scope: StorageScope;
  /** Local directory for observation/journal/checkpoint evidence (never leaves the machine). */
  evidenceDir: string;
  policySnapshotRevision: string;
  rankingPolicyRevision: string;
  environmentId: string;
  providerId: string;
  providerVersion: string;
  clock: () => string;
  /**
   * Benchmark-only (L2 §4.2): precommitted protected-asset baseline hashes
   * keyed by DECLARED path, supplied exclusively by the benchmark envelope
   * entry. Production callers must leave this undefined.
   */
  benchmarkBaselines?: Record<string, string>;
}

export interface StorageDiagnoseResult {
  output: StorageDiagnoseOutput;
  /** Readable R2 preview (PLAN/PREVIEW phase artifact); present when a plan was proposed. */
  preview: string | null;
  proposal: CleanupPlanProposal | null;
  scope: ResolvedScope;
  receipts: ExecutionReceipt[];
}

/**
 * Production entry. Accepts ONLY the frozen production input: the benchmark
 * envelope (growth fixture, precommitted canary hashes) is structurally
 * rejected here by the strict schema — hidden harness truth cannot leak into
 * the runtime path (L2 §4.2).
 */
export async function runStorageDiagnose(
  runtime: StorageDiagnoseRuntime,
  rawInput: unknown,
): Promise<StorageDiagnoseResult> {
  const input: StorageDiagnoseInput = StorageDiagnoseInputSchema.parse(rawInput);
  const legacyPorts = runtime.ports;
  const controller = runtime.controller;
  if ((legacyPorts === undefined) === (controller === undefined)) {
    throw new StorageVerticalError(
      'R2_GATE_MISSING',
      'storage runtime requires exactly one authorization wiring: legacy ports or ActionController',
    );
  }
  const scope = await resolveScope(input.targetVolume, runtime.scope);
  await fsp.mkdir(runtime.evidenceDir, { recursive: true });

  const protectedRealPaths = await resolveProtectedRealPaths(input);
  // Pre-action protected fingerprints: the production verification baseline
  // (snapshot BEFORE any action — content hashes, metadata only).
  const preActionFingerprints = new Map<string, string>();
  for (const p of protectedRealPaths) {
    preActionFingerprints.set(p, await fingerprintPath(p));
  }

  // ---- R0 observation + evidence. ----
  const observation = await observeStorage(scope, runtime.clock);
  const observationFile = path.join(
    runtime.evidenceDir,
    `observation-${sanitize(input.taskId)}.json`,
  );
  await fsp.writeFile(observationFile, JSON.stringify(observation, null, 2), 'utf8');
  const observationEvidenceRef = `evidence://${sanitize(input.taskId)}/${path.basename(observationFile)}`;

  // ---- Attribution + classification. ----
  const attribution = attributeGrowth({
    observation,
    eligibleCategories: input.cleanupPolicy.eligibleCategories,
    classificationPolicy: { protectedRealPaths, scopeRoots: scope.roots },
    observationEvidenceRef,
  });

  // ---- PLAN + PREVIEW + CHECKPOINT. ----
  const proposal = await buildCleanupPlan({
    taskId: input.taskId,
    targetVolume: input.targetVolume,
    attribution,
    observation,
    observationEvidenceRef,
    scope,
    protectedRealPaths,
    eligibleCategories: input.cleanupPolicy.eligibleCategories,
    policySnapshotRevision: runtime.policySnapshotRevision,
    rankingPolicyRevision: runtime.rankingPolicyRevision,
    environmentId: runtime.environmentId,
    evidenceDir: runtime.evidenceDir,
    clock: runtime.clock,
  });

  const noActionResult = async (): Promise<StorageDiagnoseResult> => {
    const verifiedProtected = await verifyNoActionProtectedAssets(
      input,
      protectedRealPaths,
      preActionFingerprints,
    );
    const output = StorageDiagnoseOutputSchema.parse({
      taskId: input.taskId,
      attribution: {
        growthSourcePath: attribution.growthSourcePath,
        classifiedAs: attribution.classifiedAs,
        evidenceRefs: attribution.evidenceRefs,
      },
      cleanupPlan: null,
      protectedAssetVerification: verifiedProtected,
    });
    return { output, preview: proposal.preview, proposal, scope, receipts: [] };
  };

  // ---- AUTHORIZATION. Production mode delegates the complete plan to the
  // real ActionController; legacy ports remain only for package tests/reference
  // composition and are not T10 integration evidence. ----
  let controllerAuthorization: AuthorizedPlan | undefined;
  let legacyGrant: unknown;
  let r2ApprovedBy: 'USER_APPROVAL' | 'DURABLE_POLICY' = 'USER_APPROVAL';

  if (controller) {
    const authorization = await controller.authorizePlan({ plan: proposal.plan });
    if (!authorization.ok) {
      if (authorization.code === 'APPROVAL_REJECTED') {
        return noActionResult();
      }
      throw new StorageVerticalError(
        'R2_GATE_MISSING',
        `ActionController refused storage plan: ${authorization.code} — ${authorization.detail}`,
      );
    }
    controllerAuthorization = authorization.authorization;
    if (controllerAuthorization.plan.planHash !== proposal.plan.planHash) {
      throw new StorageVerticalError(
        'R2_GATE_MISSING',
        'ActionController returned authorization for a different plan hash',
      );
    }
    if (controllerAuthorization.disposition.kind === 'AUTOMATIC') {
      throw new StorageVerticalError(
        'R2_GATE_MISSING',
        'destructive storage R2 plan cannot execute under AUTOMATIC authorization',
      );
    }
    r2ApprovedBy =
      controllerAuthorization.disposition.kind === 'DURABLE_POLICY'
        ? 'DURABLE_POLICY'
        : 'USER_APPROVAL';
  } else {
    if (!legacyPorts) {
      throw new StorageVerticalError(
        'R2_GATE_MISSING',
        'legacy storage authorization is not wired',
      );
    }
    const approval = await legacyPorts.requestApproval({
      taskId: input.taskId,
      planHash: proposal.plan.planHash,
      summary: proposal.preview,
      evidenceRefs: attribution.evidenceRefs,
    });

    if (!approval.approved) {
      return noActionResult();
    }

    legacyGrant = await legacyPorts.issueGrant({
      taskId: input.taskId,
      planHash: proposal.plan.planHash,
      policySnapshotRevision: runtime.policySnapshotRevision,
      actionScope: {
        actionIds: proposal.plan.actions.map((a) => a.actionId),
        privilegeLevel: 'USER',
        filesystem: {
          read: proposal.targets.map((t) => t.path),
          write: proposal.targets.map((t) => t.path),
        },
        network: { allowed: false },
      },
      authorizationKind: 'EXPLICIT_APPROVAL',
      approvalRef: approval.approvalId,
    });
  }

  // ---- EXECUTE per bounded target (one AuthorizedAction per target). ----
  const journalPath = path.join(runtime.evidenceDir, `journal-${sanitize(input.taskId)}.jsonl`);
  const receipts: ExecutionReceipt[] = [];
  const perActionReclaim = new Map<string, number>();
  for (const planAction of proposal.plan.actions) {
    let authorizedAction: AuthorizedAction;
    let grant: unknown;
    let controllerGate:
      | ((gateInput: {
          grant: unknown;
          plan: typeof proposal.plan;
          action: AuthorizedAction;
        }) => ReturnType<StorageActionController['authorizeEffect']>)
      | undefined;

    if (controllerAuthorization && controller) {
      const action = controllerAuthorization.actions.find(
        (candidate) => candidate.actionId === planAction.actionId,
      );
      if (!action || action.planHash !== proposal.plan.planHash) {
        throw new StorageVerticalError(
          'R2_GATE_MISSING',
          `ActionController did not authorize exact storage action ${planAction.actionId}`,
        );
      }
      const matchingGrant = controllerAuthorization.grants.find(
        (candidate) => candidate.grantId === action.authorizationRef,
      );
      if (!matchingGrant) {
        throw new StorageVerticalError(
          'R2_GATE_MISSING',
          `ActionController authorization for ${planAction.actionId} has no matching grant`,
        );
      }
      authorizedAction = action;
      grant = matchingGrant;
      controllerGate = (gateInput) => controller.authorizeEffect(gateInput);
    } else {
      if (!legacyPorts || legacyGrant === undefined) {
        throw new StorageVerticalError(
          'R2_GATE_MISSING',
          'legacy storage grant is unavailable at execution boundary',
        );
      }
      authorizedAction = {
        taskId: input.taskId,
        actionId: planAction.actionId,
        planHash: proposal.plan.planHash,
        policySnapshotRevision: runtime.policySnapshotRevision,
        authorizationKind: 'EXPLICIT_APPROVAL',
        authorizationRef: (legacyGrant as { grantId: string }).grantId,
        action: planAction,
      };
      grant = legacyGrant;
    }

    let authorizationBoundary:
      | { validatePresentation: NonNullable<typeof controllerGate> }
      | {
          currentAuthority: Awaited<ReturnType<StorageDiagnosePorts['currentAuthority']>>;
          verifyIntegrity: StorageDiagnosePorts['verifyIntegrity'];
        };
    if (controllerGate) {
      authorizationBoundary = { validatePresentation: controllerGate };
    } else {
      if (!legacyPorts) {
        throw new StorageVerticalError(
          'R2_GATE_MISSING',
          'legacy storage authorization disappeared before the effect boundary',
        );
      }
      authorizationBoundary = {
        currentAuthority: await legacyPorts.currentAuthority(),
        verifyIntegrity: legacyPorts.verifyIntegrity,
      };
    }

    const result = await executeBoundedCleanup({
      authorizedAction,
      plan: proposal.plan,
      grant,
      ...authorizationBoundary,
      now: runtime.clock(),
      scopeRoots: scope.roots,
      protectedRealPaths,
      eligibleCategories: input.cleanupPolicy.eligibleCategories,
      journalPath,
      environmentId: runtime.environmentId,
      providerId: runtime.providerId,
      providerVersion: runtime.providerVersion,
    });
    receipts.push(result.receipt);
    const target = result.targets[planAction.actionId];
    if (target) perActionReclaim.set(planAction.actionId, target.reclaimedBytes);
  }

  // ---- VERIFY (semantic; never trusts the receipt alone). ----
  const growthSource = attribution.growthSourcePath;
  const postMeasurement = await measureDirectoryNow(growthSource);
  const grossBytes = [...perActionReclaim.values()].reduce((a, b) => a + b, 0);
  const oracleInputs = {
    scopeRoots: [...scope.roots],
    reclaimed: { grossBytes, postActionStateBytes: postMeasurement.bytes },
    protectedBaselines: Object.fromEntries(preActionFingerprints),
  };
  const verificationInput: VerificationInput = {
    taskId: input.taskId,
    verificationPlan: proposal.plan.verificationPlan,
    executionReceipt: pickPrimaryReceipt(receipts),
    oracleInputs,
  };
  const outcome = await verifyStorageCleanup({
    verificationInput,
    storageInput: input,
    protectedRealPaths,
    journal: { path: journalPath },
    postActionStateBytes: postMeasurement.bytes,
    deps: {
      preActionFingerprints,
      baselines: benchmarkBaselinesFor(runtime, input, protectedRealPaths),
    },
    // The verifier sees EVERY receipt: a failed/refused/partial target can
    // never be averaged into a task-level PASS (VS-P1-03).
    receipts,
  });

  if (outcome.receipt.status === 'FAIL') {
    const failedCheck = outcome.receipt.checks.find((c) => c.status === 'FAIL');
    throw new StorageVerticalError(
      'RECLAIM_NOT_VERIFIED',
      `semantic verification failed: ${failedCheck?.checkId ?? 'unknown'} — ${failedCheck?.detail ?? ''}`,
    );
  }

  const output = StorageDiagnoseOutputSchema.parse({
    taskId: input.taskId,
    attribution: {
      growthSourcePath: attribution.growthSourcePath,
      classifiedAs: attribution.classifiedAs,
      evidenceRefs: attribution.evidenceRefs,
    },
    cleanupPlan: {
      bounded: true,
      targets: proposal.targets.map((t) => ({
        path: t.path,
        classification: t.classification,
        expectedReclaimBytes: t.expectedReclaimBytes,
      })),
      r2Gate: R2GateRecordSchema.parse({
        phases: [...R2_GATE_PHASES],
        approvedBy: r2ApprovedBy,
      }),
    },
    executionEvidence: pickPrimaryReceipt(receipts),
    reclaimed: {
      grossBytes: outcome.grossReclaimedBytes,
      postActionStateBytes: postMeasurement.bytes,
    },
    protectedAssetVerification: zipProtectedVerification(input, outcome.protectedVerifications),
  });

  return { output, preview: proposal.preview, proposal, scope, receipts };
}

async function resolveProtectedRealPaths(input: StorageDiagnoseInput): Promise<string[]> {
  const real: string[] = [];
  for (const asset of input.protectedAssets) {
    real.push(await fsp.realpath(asset.path));
  }
  return real;
}

/** Benchmark canaries only: align envelope baselines (declared keys) with canonical realpaths. */
function benchmarkBaselinesFor(
  runtime: StorageDiagnoseRuntime,
  input: StorageDiagnoseInput,
  protectedRealPaths: readonly string[],
): { path: string; baselineSha256: string }[] | undefined {
  if (!runtime.benchmarkBaselines) return undefined;
  return input.protectedAssets
    .map((asset, i) => {
      const sha = runtime.benchmarkBaselines?.[asset.path];
      const real = protectedRealPaths[i];
      return sha && real ? { path: real, baselineSha256: sha } : undefined;
    })
    .filter((b): b is { path: string; baselineSha256: string } => b !== undefined);
}

/** When no action executed, protected verification is still recorded honestly (all unchanged). */
async function verifyNoActionProtectedAssets(
  input: StorageDiagnoseInput,
  protectedRealPaths: readonly string[],
  preActionFingerprints: ReadonlyMap<string, string>,
): Promise<StorageDiagnoseOutput['protectedAssetVerification']> {
  const records: StorageDiagnoseOutput['protectedAssetVerification'] = [];
  for (const [i, declared] of input.protectedAssets.entries()) {
    const real = protectedRealPaths[i];
    if (!real) continue;
    const current = await fingerprintPath(real);
    const expected = preActionFingerprints.get(real);
    records.push({
      path: declared.path,
      unchanged: expected === undefined ? false : current === expected,
    });
  }
  return records;
}

function zipProtectedVerification(
  input: StorageDiagnoseInput,
  verifications: { path: string; unchanged: boolean }[],
): StorageDiagnoseOutput['protectedAssetVerification'] {
  return input.protectedAssets.map((declared, index) => {
    const real = verifications[index];
    return { path: declared.path, unchanged: real ? real.unchanged : false };
  });
}

function pickPrimaryReceipt(receipts: ExecutionReceipt[]): ExecutionReceipt {
  const first = receipts[0];
  if (!first) {
    throw new StorageVerticalError('R2_GATE_MISSING', 'execution produced no receipt');
  }
  return first;
}

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]+/g, '_');
}

export { VERIFIER_ID, VERIFIER_REVISION };
