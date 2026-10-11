// Loop B — trusted JIT capability lifecycle orchestrator (L2 §14.2).
//
//   C-002 → trusted acquisition candidate → local Windows binding → acquire →
//   task execute + verify → lifecycle-state persistence → R2 remove
//   plan/preview → approval or pre-existing durable JIT policy →
//   remove/reconcile → protected/user-asset verification
//
// Authority rules honored here (L2 §3.1):
//   - provenance is gated BEFORE any approval surface is consulted, and a
//     trust failure cannot be overridden by a simple approval click;
//   - every side effect flows ActionPlan → grant → AuthorizedAction →
//     privileged backend, with the boundary re-validating the presentation
//     itself against the trusted plan ledger;
//   - any removal is R2 and runs the observable six-phase gate;
//   - recovery classifications derive only from the phase journal plus
//     independent post-state verification.
import {
  type ActionPlan,
  type ApprovalPort,
  type AuthorizationGrant,
  type AuthorizationPort,
  type AuthorizedAction,
  CurrentAuthorityStateSchema,
  type EnvironmentBackend,
  type ExecutionBackend,
  ExecutionReceiptSchema,
  type JitBenchmarkInput,
  JitBenchmarkInputSchema,
  type JitLifecycleInput,
  type JitLifecycleOutput,
  type PlanAction,
  type PreparedEnvironment,
  type ProviderEnvironmentBinding,
  parseJitLifecycleInput,
  parseJitLifecycleOutput,
  pathWithin,
  type RegistryReadModelPort,
  ShunContractError,
  type StorePort,
  type VerificationPlan,
  type VerificationReceipt,
  type VerifierPort,
} from '@shun/contracts';
import { JitLifecycleError } from './failures.ts';
import { classifyFromJournal, type JournalPort } from './journal.ts';
import { canonicalKey, treeUnder } from './manifest-removal.ts';
import { buildActionPlan, installAction, taskAction, uninstallAction } from './plans.ts';
import type {
  AcquisitionCandidate,
  AcquisitionPort,
  FilesystemPort,
  JitDurablePolicy,
  PlanLedgerPort,
  ProviderInstallLayout,
} from './ports.ts';
import { provenanceRecord, requireTrustedProvider } from './provenance.ts';
import { assertNoProtectedDeletions, classifyResidue, type ResidueCandidate } from './residue.ts';

const INSTALL_TIMEOUT_MS = 15 * 60_000;
const TASK_TIMEOUT_MS = 5 * 60_000;
const UNINSTALL_TIMEOUT_MS = 15 * 60_000;

export interface JitLifecycleDeps {
  readonly registry: RegistryReadModelPort;
  readonly acquisition: AcquisitionPort;
  readonly privileged: ExecutionBackend;
  readonly environment: EnvironmentBackend;
  readonly authorization: ImportableAuthorizationPort;
  readonly approval: ApprovalPort;
  readonly verifier: VerifierPort;
  readonly store: StorePort;
  readonly planLedger: PlanLedgerPort;
  /**
   * Trusted gate the task grant presentation must cross before the
   * environment executes (VJ-P1-03). Typed optional only so non-executable
   * composition type-checks; both public lifecycle entries enforce its
   * presence at runtime — executing argv without a validated presentation
   * is the bypass this gate closes.
   */
  readonly taskPresentationGate?: TaskPresentationGate;
  /** Journal accessor per actionId — transport failures classify from it (L2 §9.4). */
  readonly journals: (actionId: string) => JournalPort;
  readonly fs: FilesystemPort;
  readonly clock: () => string;
  readonly policy: {
    readonly rankingPolicyRevision: string;
    readonly machineScopeInstall: boolean;
    /** Roots that must never enter a deletion scope (user profile, documents, canaries). */
    readonly protectedRoots: readonly string[];
    /** Directory the task step may write into; stdout evidence lands here. */
    readonly taskOutputDir: string;
    /** Pre-existing durable JIT removal policy; absent ⇒ R2 removal needs explicit approval. */
    readonly durableJitPolicy?: JitDurablePolicy;
  };
  /** Observable-gate trace sink (evidence runs record the full sequence). */
  readonly trace?: (event: { at: string; kind: string; detail?: string }) => void;
}

/**
 * The orchestrator needs issued grants to present at the privileged boundary.
 * `AuthorizationPort.issue` already returns the durable grant record; the
 * presentation is that record.
 */
export type ImportableAuthorizationPort = Pick<AuthorizationPort, 'issue' | 'currentAuthority'>;

/**
 * Trusted-boundary validation for the task execution step (VJ-P1-03): the
 * issued grant must be PRESENTED for validation against the trusted plan
 * ledger and CURRENT authority/policy state — the environment backend is
 * never invoked on the caller's say-so. Wired to the same authority that
 * signs grants; both public lifecycle entries refuse to run when it is
 * absent, so an unwired gate is a wiring fault, never a silent fail-open.
 */
export type TaskPresentationGate = {
  validate(input: {
    action: AuthorizedAction;
    grant: unknown;
    plan: ActionPlan;
  }): { ok: true } | { ok: false; code: string; detail: string };
};

function trace(deps: JitLifecycleDeps, kind: string, detail?: string): void {
  deps.trace?.({ at: deps.clock(), kind, ...(detail !== undefined ? { detail } : {}) });
}

async function requireCurrentPolicyRevision(deps: JitLifecycleDeps): Promise<string> {
  const state = CurrentAuthorityStateSchema.safeParse(await deps.authorization.currentAuthority());
  if (!state.success || state.data.kind !== 'CURRENT') {
    throw new JitLifecycleError(
      'POLICY_BLOCKED',
      'current authority/policy state is not CURRENT — refusing to plan any side effect',
    );
  }
  return state.data.policySnapshotRevision;
}

function parsePackageId(source: string): string {
  if (!source.startsWith('winget:')) {
    throw new JitLifecycleError(
      'NO_TRUSTED_PROVIDER',
      `provider acquisition source "${source}" is not a winget official-source reference`,
    );
  }
  const id = source.slice('winget:'.length);
  if (id.trim().length === 0) {
    throw new JitLifecycleError(
      'NO_TRUSTED_PROVIDER',
      'winget source reference carries no package id',
    );
  }
  return id;
}

interface SelectedBinding {
  readonly bindingId: string;
  readonly providerId: string;
  readonly verifierId: string;
  readonly packageId: string;
  readonly license: string;
  readonly elevated: boolean;
  readonly prepared: PreparedEnvironment;
}

async function selectTrustedBinding(
  input: JitLifecycleInput,
  deps: JitLifecycleDeps,
): Promise<SelectedBinding> {
  const capabilities = await deps.registry.listCapabilities();
  const capability = capabilities.find(
    (entry) => entry.capabilityId === input.capabilityRequirement.capabilityId,
  );
  if (!capability) {
    throw new JitLifecycleError(
      'CAPABILITY_UNRESOLVED',
      `capability ${input.capabilityRequirement.capabilityId} is not in the registry`,
    );
  }
  const revision = input.capabilityRequirement.revision;
  const bindings = (await deps.registry.providerCapabilityBindings(capability.capabilityId)).filter(
    (binding) =>
      !revision ||
      (binding.capabilityRevisionRange.min <= revision &&
        (!binding.capabilityRevisionRange.max || revision <= binding.capabilityRevisionRange.max)),
  );
  if (bindings.length === 0) {
    throw new JitLifecycleError(
      'CAPABILITY_UNRESOLVED',
      `no binding serves capability ${capability.capabilityId}${revision ? ` at revision ${revision}` : ''}`,
    );
  }

  const providers = await deps.registry.listProviders();
  const untrusted: string[] = [];
  for (const binding of bindings) {
    // Provenance gate — BEFORE any approval surface. An untrusted provider is
    // skipped with the exact reason; if nothing trusted remains the run fails
    // PROVENANCE_UNKNOWN and no approval can resurrect it (C-002).
    try {
      requireTrustedProvider(providers, binding.providerId);
    } catch (error) {
      if (error instanceof JitLifecycleError) {
        untrusted.push(`${binding.providerId}: ${error.detail}`);
        continue;
      }
      throw error;
    }
    const provider = providers.find((entry) => entry.providerId === binding.providerId);
    if (!provider) continue;
    const feasibility = await deps.environment.canPrepare(binding.environmentRequirements);
    if (!feasibility.feasible) continue;
    const envBindings: ProviderEnvironmentBinding[] =
      await deps.registry.providerEnvironmentBindings(binding.providerId);
    const feasibleEnv = envBindings.find((candidate) => candidate.feasibility.feasible);
    if (!feasibleEnv) continue;
    const prepared = await deps.environment.prepare(feasibleEnv);
    return {
      bindingId: binding.bindingId,
      providerId: provider.providerId,
      verifierId: binding.verifierId,
      packageId: parsePackageId(provider.acquisition.source),
      license: provider.licenseFacts.license,
      elevated: deps.policy.machineScopeInstall,
      prepared,
    };
  }
  if (untrusted.length > 0) {
    throw new JitLifecycleError(
      'PROVENANCE_UNKNOWN',
      `no binding has trusted provenance (C-002 fail-closed; user approval cannot override): ${untrusted.join('; ')}`,
    );
  }
  throw new JitLifecycleError(
    'NO_FEASIBLE_BINDING',
    `capability ${capability.capabilityId} has bindings but none is feasible on this environment`,
  );
}

async function issueGrant(
  deps: JitLifecycleDeps,
  input: {
    taskId: string;
    plan: ActionPlan;
    action: PlanAction;
    authorizationKind: 'AUTOMATIC' | 'EXPLICIT_APPROVAL' | 'DURABLE_POLICY';
    approvalRef?: string;
  },
): Promise<{ grant: AuthorizationGrant; authorized: AuthorizedAction }> {
  const action = input.action;
  const grant = await deps.authorization.issue({
    taskId: input.taskId,
    planHash: input.plan.planHash,
    policySnapshotRevision: input.plan.policySnapshotRevision,
    actionScope: {
      actionIds: [action.actionId],
      privilegeLevel: action.requiredPrivilege,
      ...(action.filesystemScope
        ? {
            filesystem: {
              read: action.filesystemScope.read,
              write: action.filesystemScope.write,
            },
          }
        : {}),
      ...(action.networkScope ? { network: action.networkScope } : {}),
      ...(action.registryScope ? { registry: action.registryScope } : {}),
    },
    authorizationKind: input.authorizationKind,
    ...(input.approvalRef ? { approvalRef: input.approvalRef } : {}),
  });
  const authorized: AuthorizedAction = {
    taskId: input.taskId,
    actionId: action.actionId,
    planHash: input.plan.planHash,
    policySnapshotRevision: input.plan.policySnapshotRevision,
    authorizationKind: input.authorizationKind,
    authorizationRef: grant.grantId,
    expiresAt: grant.expiresAt,
    action,
  };
  return { grant, authorized };
}

async function runPrivileged(
  deps: JitLifecycleDeps,
  input: {
    taskId: string;
    plan: ActionPlan;
    action: PlanAction;
    authorizationKind: 'AUTOMATIC' | 'EXPLICIT_APPROVAL' | 'DURABLE_POLICY';
    approvalRef?: string;
  },
): Promise<{ terminal: string; refusalCode?: string }> {
  const { grant, authorized } = await issueGrant(deps, input);
  try {
    // The issued grant IS the presentation; the boundary re-validates it
    // against the trusted plan ledger (never on the caller's say-so).
    const receipt = ExecutionReceiptSchema.parse(await deps.privileged.execute(authorized, grant));
    return { terminal: receipt.terminal };
  } catch (error) {
    // A typed contract refusal happened at the boundary BEFORE any effect
    // (stale grant, revocation, plan mismatch): surface the frozen code.
    if (error instanceof ShunContractError) {
      return { terminal: 'REFUSED', refusalCode: error.code };
    }
    // Transport-level interruption: the classification comes from the phase
    // journal alone — never from the exception's optimism (L2 §9.4).
    const entries = await deps.journals(input.action.actionId).replay();
    const classification = classifyFromJournal(entries, input.action.actionId);
    const terminal =
      classification === 'MAY_HAVE_EXECUTED_UNCERTAIN'
        ? 'UNCERTAIN'
        : classification === 'COMPLETED_VERIFIED'
          ? 'SUCCEEDED'
          : 'FAILED';
    return { terminal };
  }
}

export async function runJitLifecycle(
  rawInput: unknown,
  deps: JitLifecycleDeps,
): Promise<JitLifecycleOutput> {
  // Production entry: the benchmark envelope (preExistingUserAssets) is
  // hidden-harness truth and is refused here — fixture-only fields are never
  // production inputs (C-002 / L2 §4.2).
  const input: JitLifecycleInput = parseJitLifecycleInput(rawInput);
  requireTaskPresentationGate(deps);
  return runLifecycle(input, deps);
}

/**
 * Executable entries fail closed on the VJ-P1-03 seam: both public entries
 * run argv through the environment backend, so both must present the task
 * grant to the trusted gate. An unwired gate is a wiring fault, never an
 * implicit opt-out — plan-only composition uses the plan seams, not an
 * executable lifecycle entry.
 */
function requireTaskPresentationGate(deps: JitLifecycleDeps): void {
  if (!deps.taskPresentationGate) {
    throw new JitLifecycleError(
      'POLICY_BLOCKED',
      'task presentation gate is not wired — refusing to run an executable JIT lifecycle whose task grant is never validated at the trusted boundary (VJ-P1-03)',
    );
  }
}

/** Preview hints threaded into the R2 residue classification (benchmark only). */
export interface RemovalPreviewHints {
  readonly preExisting?: readonly string[];
  readonly providerOwnedFiles?: readonly string[];
}

/**
 * Benchmark entry (L2 §4.2 envelope): plants the canary user assets declared
 * in the envelope BEFORE the lifecycle runs, threads them into the residue
 * preview, and independently verifies their integrity after the run. Never
 * reachable from the production entry point.
 */
export async function runJitBenchmarkLifecycle(
  rawInput: unknown,
  deps: JitLifecycleDeps,
  options: { providerOwnedFiles?: readonly string[] } = {},
): Promise<JitLifecycleOutput> {
  const input: JitBenchmarkInput = JitBenchmarkInputSchema.parse(rawInput);
  requireTaskPresentationGate(deps);
  const preExisting = input.preExistingUserAssets.map((asset) => asset.path);
  const canaryHashes = new Map<string, string>();
  for (const [index, path] of preExisting.entries()) {
    await deps.fs.writeText(path, `canary ${index} — user asset planted before the lifecycle`);
    canaryHashes.set(path, await deps.fs.sha256File(path));
  }
  const output = await runLifecycle(input, deps, {
    preExisting,
    ...(options.providerOwnedFiles ? { providerOwnedFiles: options.providerOwnedFiles } : {}),
  });
  for (const [path, before] of canaryHashes) {
    if (!(await deps.fs.exists(path)) || (await deps.fs.sha256File(path)) !== before) {
      throw new JitLifecycleError(
        'USER_ASSET_AT_RISK',
        `benchmark canary was altered or deleted: ${path}`,
      );
    }
  }
  return output;
}

async function runLifecycle(
  input: JitLifecycleInput,
  deps: JitLifecycleDeps,
  hints?: RemovalPreviewHints,
): Promise<JitLifecycleOutput> {
  trace(
    deps,
    'INPUT_PARSED',
    `taskId=${input.taskId} retention=${input.lifecyclePolicy.retention}`,
  );

  const binding = await selectTrustedBinding(input, deps);
  trace(deps, 'BINDING_SELECTED', `${binding.bindingId} provider=${binding.providerId}`);

  const candidate: AcquisitionCandidate = await deps.acquisition.resolveExact({
    packageId: binding.packageId,
  });
  if (!candidate.official) {
    throw new JitLifecycleError(
      'PROVENANCE_UNKNOWN',
      `acquisition candidate from "${candidate.source}" is not official — C-002 forbids JIT use of unknown provenance`,
    );
  }
  const provenance = provenanceRecord(
    candidate,
    `${candidate.license ?? binding.license} accepted for task use`,
  );
  trace(deps, 'PROVENANCE_RECORDED', `source=${provenance.source} version=${provenance.version}`);

  // The oracle is precommitted BEFORE execution (C-002 precondition): the
  // task must emit output that names the exact acquired version.
  const verificationPlan: VerificationPlan = {
    verifierId: binding.verifierId,
    verifierRevision: 'r1',
    checks: [
      {
        checkId: 'provider-task-observable',
        description: 'task output matches the precommitted version oracle',
      },
    ],
    oracle: {
      precommitted: true,
      spec: { expectedVersion: provenance.version },
    },
  };

  // ---- Install (R1 privileged) ----
  const scopeRoots = await deps.acquisition.predictScope(
    candidate,
    deps.policy.machineScopeInstall,
  );
  // Snapshot the predicted scope BEFORE any side effect: the install-owned
  // manifest is the post-install tree minus this pre-existing tree, so
  // content that predates the install (user files inside provider roots) can
  // never be claimed as program-owned (VJ-P1-01).
  const preInstallTree = new Set<string>();
  for (const root of scopeRoots) {
    for (const path of await treeUnder(deps.fs, root)) {
      preInstallTree.add(canonicalKey(path));
    }
  }
  const officialSources = await deps.acquisition.officialSources();
  const installActionSpec = installAction({
    actionId: `${input.taskId}-install`,
    bindingId: binding.bindingId,
    packageId: candidate.packageId,
    version: candidate.version,
    installRoots: scopeRoots,
    networkDomains: officialSources.map((source) => hostnameOf(source.url)),
    elevated: binding.elevated,
    timeoutMs: INSTALL_TIMEOUT_MS,
  });
  const installPlan = await buildAndRegisterPlan(deps, {
    taskId: input.taskId,
    capabilityId: input.capabilityRequirement.capabilityId,
    bindingId: binding.bindingId,
    action: installActionSpec,
    verificationPlan,
    recovery: 'PROVEN_NOT_EXECUTED',
  });
  const installRun = await runPrivileged(deps, {
    taskId: input.taskId,
    plan: installPlan,
    action: installActionSpec,
    authorizationKind: 'AUTOMATIC',
  });
  trace(deps, 'INSTALL_EXECUTED', `terminal=${installRun.terminal}`);
  if (installRun.terminal !== 'SUCCEEDED') {
    throw installFailure(installRun.terminal, installActionSpec.actionId, installRun.refusalCode);
  }
  const layout: ProviderInstallLayout = await deps.acquisition.layoutOf(candidate);
  if (!(await providerPresent(deps, layout))) {
    throw new JitLifecycleError(
      'INSTALL_FAILED',
      'install reported success but the provider is not present on disk (post-state check failed)',
      {
        actionId: installActionSpec.actionId,
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        detail: 'post-state verification found no provider files',
      },
    );
  }
  // The exact install-owned manifest, recorded at install time and persisted
  // with the lifecycle state. The removal preview classifies in strict mode
  // against it: any path inside an install or cache root that the installer
  // did not create is USER_CREATED_UNKNOWN and fails closed (VJ-P1-01).
  const ownedManifest = await recordedOwnedManifest(
    deps,
    [...layout.installDirs, ...layout.cacheDirs],
    preInstallTree,
  );

  // ---- Task execute (bounded R1 use of the acquired provider) ----
  const executable = layout.executables[0];
  if (!executable) {
    throw new JitLifecycleError(
      'INSTALL_FAILED',
      'provider layout exposes no executable interface',
    );
  }
  const argv = taskArgv(input);
  const taskActionSpec = taskAction({
    actionId: `${input.taskId}-task`,
    bindingId: binding.bindingId,
    executable,
    argv,
    outputDir: deps.policy.taskOutputDir,
    timeoutMs: TASK_TIMEOUT_MS,
  });
  const taskPlan = await buildAndRegisterPlan(deps, {
    taskId: input.taskId,
    capabilityId: input.capabilityRequirement.capabilityId,
    bindingId: binding.bindingId,
    action: taskActionSpec,
    verificationPlan,
    recovery: 'DECLARED_IDEMPOTENT',
  });
  const { grant: taskGrant, authorized: taskAuthorized } = await issueGrant(deps, {
    taskId: input.taskId,
    plan: taskPlan,
    action: taskActionSpec,
    authorizationKind: 'AUTOMATIC',
  });
  // The task step is an executable step like any other: its grant must be
  // presented at the trusted boundary and re-validated there BEFORE the
  // environment backend runs argv (VJ-P1-03).
  const gateVerdict = deps.taskPresentationGate?.validate({
    action: taskAuthorized,
    grant: taskGrant,
    plan: taskPlan,
  });
  if (gateVerdict && !gateVerdict.ok) {
    throw new JitLifecycleError(
      'TASK_FAILED',
      `task presentation refused at the trusted boundary: ${gateVerdict.code} — ${gateVerdict.detail}`,
      {
        actionId: taskActionSpec.actionId,
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        detail: 'presentation validation precedes any task side effect',
      },
    );
  }
  const taskReceipt = ExecutionReceiptSchema.parse(await deps.environment.execute(taskAuthorized));
  if (taskReceipt.terminal !== 'SUCCEEDED') {
    throw new JitLifecycleError(
      'TASK_FAILED',
      `task execution ended ${taskReceipt.terminal} — removal is not authorized without verified use`,
    );
  }
  const stdout = taskReceipt.stdoutRef ? await deps.fs.readText(taskReceipt.stdoutRef) : '';
  trace(deps, 'TASK_EXECUTED', `exit=${taskReceipt.exitCode ?? 'n/a'}`);

  // ---- Verify against the precommitted oracle ----
  const verification: VerificationReceipt = await deps.verifier.verify({
    taskId: input.taskId,
    verificationPlan,
    executionReceipt: taskReceipt,
    oracleInputs: {
      expectedVersion: provenance.version,
      actualStdout: stdout,
    },
  });
  trace(deps, 'TASK_VERIFIED', `status=${verification.status}`);

  // ---- Lifecycle-state persistence ----
  await persistLifecycle(deps, input, provenance, layout, 'INSTALLED', ownedManifest);

  if (verification.status !== 'PASS') {
    throw new JitLifecycleError(
      'TASK_VERIFY_FAILED',
      'semantic verification failed — JIT_REMOVE_AFTER_VERIFIED_USE is not authorized without verified use',
    );
  }

  if (input.lifecyclePolicy.retention === 'RETAIN') {
    return emit(deps, {
      input,
      selectedBindingId: binding.bindingId,
      provenance,
      verification,
      lifecycleState: {
        providerId: binding.providerId,
        version: provenance.version,
        state: 'RETAINED',
      },
      residueCandidates: [],
      finalState: 'RETAINED',
    });
  }

  // ---- R2 removal gate (any removal is R2, Product C-002) ----
  return runRemovalGate(
    deps,
    input,
    binding,
    candidate,
    layout,
    provenance,
    verification,
    ownedManifest,
    hints,
  );
}

async function buildAndRegisterPlan(
  deps: JitLifecycleDeps,
  input: {
    taskId: string;
    capabilityId: string;
    bindingId: string;
    action: PlanAction;
    verificationPlan: VerificationPlan;
    recovery: 'DECLARED_IDEMPOTENT' | 'PROVEN_NOT_EXECUTED';
  },
): Promise<ActionPlan> {
  const plan = buildActionPlan({
    taskId: input.taskId,
    capabilityId: input.capabilityId,
    bindingId: input.bindingId,
    rankingPolicyRevision: deps.policy.rankingPolicyRevision,
    policySnapshotRevision: await requireCurrentPolicyRevision(deps),
    action: input.action,
    verificationPlan: input.verificationPlan,
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: input.recovery,
    },
  });
  await deps.planLedger.register(plan);
  return plan;
}

// The removal gate is the observable R2 sequence from Product C-002:
// plan → preview → checkpoint → approval → execute → verify.
async function runRemovalGate(
  deps: JitLifecycleDeps,
  input: JitLifecycleInput,
  binding: SelectedBinding,
  candidate: AcquisitionCandidate,
  layout: ProviderInstallLayout,
  provenance: ReturnType<typeof provenanceRecord>,
  verification: VerificationReceipt,
  ownedManifest: readonly string[],
  hints?: RemovalPreviewHints,
): Promise<JitLifecycleOutput> {
  const actionId = `${input.taskId}-uninstall`;
  trace(deps, 'R2_PLAN', `gate opens for ${binding.providerId}`);

  // (1) PLAN — exact uninstall mechanism and candidate filesystem changes.
  const observed = [...(await collectCandidates(deps, layout)), ...(hints?.preExisting ?? [])];
  // Deletion scope is program-owned + cache roots ONLY; configuration is
  // retained (C-002 checkpoint keeps restore possible without any deletion).
  const deleteRoots = [...layout.installDirs, ...layout.cacheDirs];
  const uninstallActionSpec = uninstallAction({
    actionId,
    bindingId: binding.bindingId,
    packageId: candidate.packageId,
    version: candidate.version,
    deleteRoots,
    // The effect is manifest-bound (VJ-P1-01 R4): the privileged executor
    // validates scope exclusivity at effect time and deletes exactly the
    // install-recorded entries, so a post-census injection can never enter
    // the deletion set and an unrecorded asset refuses the whole effect.
    deletionManifest: ownedManifest,
    elevated: binding.elevated,
    timeoutMs: UNINSTALL_TIMEOUT_MS,
  });
  const uninstallPlan = await buildAndRegisterPlan(deps, {
    taskId: input.taskId,
    capabilityId: input.capabilityRequirement.capabilityId,
    bindingId: binding.bindingId,
    action: uninstallActionSpec,
    verificationPlan: {
      verifierId: binding.verifierId,
      verifierRevision: 'r1',
      checks: [{ checkId: 'post-remove-verify', description: 'provider absent after removal' }],
    },
    recovery: 'DECLARED_IDEMPOTENT',
  });

  // (2) PREVIEW — classify every candidate with fail-closed dispositions.
  // Benchmark hints (harness truth) win; the production path classifies in
  // strict mode against the install-time owned manifest recorded above, so
  // any unrecorded nested content is USER_CREATED_UNKNOWN (VJ-P1-01).
  const candidates: ResidueCandidate[] = classifyResidue({
    layout,
    observed,
    protectedRoots: deps.policy.protectedRoots,
    ...(hints?.preExisting ? { preExisting: hints.preExisting } : {}),
    providerOwnedFiles: hints?.providerOwnedFiles ?? ownedManifest,
  });
  assertNoProtectedDeletions(candidates);
  // Fail-closed asset gate (C-002 step 2): anything user-created/unknown or
  // protected that sits inside the deletion scope blocks automatic removal —
  // the provider stays installed and the task needs intervention.
  const atRisk = candidates.filter(
    (candidate) =>
      candidate.disposition === 'RETAIN' &&
      (candidate.classification === 'USER_CREATED_UNKNOWN' ||
        candidate.classification === 'PROTECTED') &&
      deleteRoots.some((root) => pathWithin(candidate.path, root)),
  );
  if (atRisk.length > 0) {
    throw new JitLifecycleError(
      'USER_ASSET_AT_RISK',
      `removal blocked: user-created/protected paths inside the deletion scope must be resolved by a human first: ${atRisk
        .map((candidate) => candidate.path)
        .join(', ')}`,
    );
  }
  trace(
    deps,
    'R2_PREVIEW',
    `candidates=${candidates.length} delete=${candidates.filter((entry) => entry.disposition === 'DELETE').length}`,
  );

  // (3) CHECKPOINT — record exact version/source so reinstall is possible.
  const checkpointRef = await persistLifecycle(
    deps,
    input,
    provenance,
    layout,
    'CHECKPOINT',
    ownedManifest,
  );

  // (4) APPROVAL CONDITION — explicit approval or a sufficiently specific
  // durable policy. Provenance passed earlier; this gate decides removal only.
  let approvedBy: 'USER_APPROVAL' | 'DURABLE_POLICY';
  let approvalRef: string | undefined;
  const durable = deps.policy.durableJitPolicy;
  if (durable?.jitRemoveAfterVerifiedUse && durable.forbidUserAssetDeletion) {
    approvedBy = 'DURABLE_POLICY';
    approvalRef = `policy://${durable.policyId}@${durable.revision}`;
    trace(deps, 'R2_APPROVAL', `durable policy ${durable.policyId}@${durable.revision}`);
  } else {
    const decision = await deps.approval.requestApproval({
      taskId: input.taskId,
      planHash: uninstallPlan.planHash,
      summary: removalSummary(candidate, candidates),
      evidenceRefs: [`evidence://${input.taskId}/verification`, `store://${checkpointRef}`],
    });
    if (!decision.approved) {
      trace(deps, 'R2_APPROVAL', 'declined — provider retained');
      return emit(deps, {
        input,
        selectedBindingId: binding.bindingId,
        provenance,
        verification,
        lifecycleState: {
          providerId: binding.providerId,
          version: provenance.version,
          state: 'INSTALLED',
        },
        residueCandidates: candidates,
        finalState: 'RETAINED',
      });
    }
    approvedBy = decision.approvedBy;
    approvalRef = `approval://${decision.approvalId}`;
  }

  // Effect-boundary strict re-census (VJ-P1-01 post-preview race): the
  // preview census is a PRE-approval snapshot; anything planted during the
  // async approval wait — or between preview and effect under a durable
  // policy — is invisible to it, and a destructive uninstaller would destroy
  // it while the lifecycle reported REMOVED. Immediately before the
  // privileged effect, re-enumerate BOTH deletion-scope root kinds
  // (install + cache) and classify strictly against the install-time owned
  // manifest. Any newly appeared unknown/protected asset refuses the effect
  // with zero deletions (an unrecorded reparse point or mutable drop is
  // exactly such an unknown — it can never be manifest-recorded).
  //
  // This census is the OUTER layer only (VJ-P1-01 R4): caller-reachable
  // seams still follow it (the trace hook below, the async grant issuance
  // inside runPrivileged), so the privileged effect itself is manifest-bound
  // — it re-validates scope exclusivity at effect time inside the trusted
  // executor and deletes exactly the recorded entries, structurally unable
  // to touch anything planted after this point.
  await assertRemovalScopeAtEffectBoundary(deps, layout, ownedManifest);
  trace(deps, 'R2_RECENSUS', 'removal scope re-validated at the effect boundary');
  let run = await runPrivileged(deps, {
    taskId: input.taskId,
    plan: uninstallPlan,
    action: uninstallActionSpec,
    authorizationKind: approvedBy === 'DURABLE_POLICY' ? 'DURABLE_POLICY' : 'EXPLICIT_APPROVAL',
    approvalRef,
  });
  trace(deps, 'R2_EXECUTE', `terminal=${run.terminal}`);
  if (run.terminal === 'UNCERTAIN') {
    const presentAfterInterrupt = await providerPresent(deps, layout);
    if (!presentAfterInterrupt) {
      // Reconcile-first resolution (L2 §9.4): independent post-state proves
      // the removal executed — the uncertain terminal resolves to success.
      trace(deps, 'R2_RECONCILE', 'uncertain interrupted; post-state proves removal executed');
      run = { terminal: 'SUCCEEDED' };
    } else {
      trace(
        deps,
        'R2_RECONCILE',
        'uncertain interrupted; provider still present — retry SAME actionId',
      );
      // The retry is a NEW privileged effect: the same post-preview race
      // applies to the window the first attempt opened, so the removal scope
      // is re-censused again before the retry executes.
      await assertRemovalScopeAtEffectBoundary(deps, layout, ownedManifest);
      run = await runPrivileged(deps, {
        taskId: input.taskId,
        plan: uninstallPlan,
        action: uninstallActionSpec,
        authorizationKind: approvedBy === 'DURABLE_POLICY' ? 'DURABLE_POLICY' : 'EXPLICIT_APPROVAL',
        approvalRef,
      });
    }
  }
  if (run.terminal !== 'SUCCEEDED') {
    throw removalFailure(run.terminal, actionId, run.refusalCode);
  }

  // (6) VERIFY — final provider state and residue disposition.
  if (await providerPresent(deps, layout)) {
    throw new JitLifecycleError(
      'POST_REMOVE_VERIFY_FAILED',
      'removal executed but provider files remain (post-state verification failed)',
      {
        actionId,
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        detail: 'post-state still shows the provider present',
      },
    );
  }
  trace(deps, 'R2_VERIFY', 'provider absent after removal');

  return emit(deps, {
    input,
    selectedBindingId: binding.bindingId,
    provenance,
    verification,
    lifecycleState: {
      providerId: binding.providerId,
      version: provenance.version,
      state: 'REMOVED',
    },
    residueCandidates: candidates,
    finalState: 'REMOVED',
    r2Gate: {
      phases: ['PLAN', 'PREVIEW', 'CHECKPOINT', 'APPROVAL', 'EXECUTE', 'VERIFY'],
      approvedBy,
    },
  });
}

// ---- helpers ----

async function providerPresent(
  deps: JitLifecycleDeps,
  layout: ProviderInstallLayout,
): Promise<boolean> {
  for (const dir of layout.installDirs) {
    if (await deps.fs.exists(dir)) return true;
  }
  return false;
}

/**
 * The exact install-owned manifest: every path — census roots included —
 * that the install created and that was NOT on disk before the install ran,
 * across BOTH install roots and cache roots (VJ-P1-01 cache census: cache
 * roots sit inside the deletion scope, so installer-written cache content
 * must be claimed explicitly, and everything else inside a cache root stays
 * unknown). The provider root claim cannot cover paths the installer never
 * created — pre-existing or later-dropped user content stays unknown, and
 * unknown is never deleted.
 */
async function recordedOwnedManifest(
  deps: JitLifecycleDeps,
  censusRoots: readonly string[],
  preInstallTree: ReadonlySet<string>,
): Promise<string[]> {
  const owned: string[] = [];
  for (const root of censusRoots) {
    if (!preInstallTree.has(canonicalKey(root))) {
      owned.push(root);
    }
    for (const path of await treeUnder(deps.fs, root)) {
      if (!preInstallTree.has(canonicalKey(path))) {
        owned.push(path);
      }
    }
  }
  return owned;
}

async function collectCandidates(
  deps: JitLifecycleDeps,
  layout: ProviderInstallLayout,
): Promise<string[]> {
  const observed: string[] = [];
  for (const root of [...layout.installDirs, ...layout.cacheDirs, ...layout.configDirs]) {
    observed.push(root);
    observed.push(...(await treeUnder(deps.fs, root)));
  }
  return observed;
}

/**
 * Fail-closed re-census of the deletion scope at the privileged effect
 * boundary (VJ-P1-01 post-preview race). The preview census is a snapshot
 * taken before the approval surface is consulted; the approval wait (or the
 * preview→effect gap under a durable policy) is unbounded real time, and a
 * whole-root uninstaller destroys everything inside the scope — including a
 * user asset planted into that gap, which the snapshot never saw. Before the
 * effect runs, BOTH root kinds (install + cache) are re-enumerated and
 * classified STRICTLY against the install-time owned manifest: any path that
 * is present now but not census-recorded is USER_CREATED_UNKNOWN, and any
 * protected-root content is PROTECTED — either one refuses the removal with
 * zero deletions. There is no depth cap and the walk is cycle-guarded, so a
 * planted reparse point or directory junction is traversed and its content
 * enumerated (as unknown when unrecorded) rather than silently skipped.
 */
async function assertRemovalScopeAtEffectBoundary(
  deps: JitLifecycleDeps,
  layout: ProviderInstallLayout,
  ownedManifest: readonly string[],
): Promise<void> {
  const observed: string[] = [];
  for (const root of [...layout.installDirs, ...layout.cacheDirs]) {
    observed.push(root);
    observed.push(...(await treeUnder(deps.fs, root)));
  }
  const reCensus = classifyResidue({
    layout,
    observed,
    protectedRoots: deps.policy.protectedRoots,
    providerOwnedFiles: ownedManifest,
  });
  const atRisk = reCensus.filter(
    (candidate) =>
      candidate.disposition === 'RETAIN' &&
      (candidate.classification === 'USER_CREATED_UNKNOWN' ||
        candidate.classification === 'PROTECTED'),
  );
  if (atRisk.length > 0) {
    throw new JitLifecycleError(
      'USER_ASSET_AT_RISK',
      `effect-boundary re-census blocked the removal: assets inside the deletion scope were never census-recorded by the install (planted after the preview snapshot) and must be resolved by a human first: ${atRisk
        .map((candidate) => candidate.path)
        .join(', ')}`,
    );
  }
}

async function persistLifecycle(
  deps: JitLifecycleDeps,
  input: JitLifecycleInput,
  provenance: ReturnType<typeof provenanceRecord>,
  layout: ProviderInstallLayout,
  state: string,
  providerOwnedFiles?: readonly string[],
): Promise<string> {
  // Each state transition is its own append-only revision: the store's
  // idempotent replay keys on effectId, so a shared identity would let the
  // CHECKPOINT transition be swallowed by the earlier INSTALLED record
  // (VJ-P1-02). The checkpoint the R2 approval gate relies on must be
  // durably recorded in its own right.
  const effectId = `jit:${input.taskId}:lifecycle:${state.toLowerCase()}`;
  const receipt = await deps.store.apply(effectId, {
    recordKind: 'lifecycle_record',
    recordId: effectId,
    payload: {
      taskId: input.taskId,
      providerId: layout.providerId,
      version: provenance.version,
      provenance,
      layout: {
        installDirs: [...layout.installDirs],
        cacheDirs: [...layout.cacheDirs],
        configDirs: [...layout.configDirs],
        executables: [...layout.executables],
      },
      state,
      ...(providerOwnedFiles ? { providerOwnedFiles: [...providerOwnedFiles] } : {}),
      recordedAt: deps.clock(),
    },
  });
  // Read-back validation before any gate step may rely on the record: a
  // replayed (not applied) receipt for a fresh revision identity means the
  // durable store refused the transition — proceeding would run the R2 gate
  // against a checkpoint that was never recorded.
  if (!receipt.applied) {
    throw new JitLifecycleError(
      'POLICY_BLOCKED',
      `durable store returned a replay instead of recording the ${state} lifecycle transition — refusing to continue on an unrecorded state migration`,
    );
  }
  trace(deps, 'LIFECYCLE_PERSISTED', `${state} -> ${receipt.receiptRef}`);
  return receipt.receiptRef;
}

function taskArgv(input: JitLifecycleInput): string[] {
  const parameters = input.targetTask.parameters as { argv?: unknown } | undefined;
  if (Array.isArray(parameters?.argv)) {
    return parameters.argv.filter((entry): entry is string => typeof entry === 'string');
  }
  // Reference "use" of an acquired CLI provider: the observable version echo.
  return ['--version'];
}

function removalSummary(
  candidate: AcquisitionCandidate,
  candidates: readonly ResidueCandidate[],
): string {
  const deletable = candidates.filter((entry) => entry.disposition === 'DELETE');
  const retained = candidates.filter((entry) => entry.disposition === 'RETAIN');
  return [
    `Remove ${candidate.packageId} ${candidate.version} acquired from official ${candidate.source}.`,
    `Will delete ${deletable.length} program-owned/cache paths.`,
    `Will retain ${retained.length} configuration/user-created/protected paths (never auto-deleted).`,
  ].join(' ');
}

function installFailure(
  terminal: string,
  actionId: string,
  refusalCode?: string,
): JitLifecycleError {
  return new JitLifecycleError(
    'INSTALL_FAILED',
    refusalCode
      ? `privileged boundary refused the install presentation: ${refusalCode} (no side effect)`
      : `privileged install ended ${terminal}`,
    {
      actionId,
      // Refusal: the journal stops at RECEIVED (validation precedes any side
      // effect) ⇒ FAILED_BEFORE_EFFECT. UAC_DECLINED carries the NO_EFFECT
      // marker ⇒ NOT_STARTED (L2 §9.4).
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      detail: `install terminal ${terminal}; no automatic retry — a declined elevation or refused grant is a decision, not a transport fault`,
    },
  );
}

function removalFailure(
  terminal: string,
  actionId: string,
  refusalCode?: string,
): JitLifecycleError {
  return new JitLifecycleError(
    'REMOVE_FAILED',
    refusalCode
      ? `privileged boundary refused the removal presentation: ${refusalCode} (no side effect)`
      : `privileged removal ended ${terminal}`,
    {
      actionId,
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      detail: `removal terminal ${terminal}`,
    },
  );
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

interface EmitArgs {
  input: JitLifecycleInput;
  selectedBindingId: string;
  provenance: ReturnType<typeof provenanceRecord>;
  verification: VerificationReceipt;
  lifecycleState: {
    providerId: string;
    version: string;
    state: 'INSTALLED' | 'RETAINED' | 'REMOVED' | 'REMOVE_FAILED';
  };
  residueCandidates: readonly ResidueCandidate[];
  finalState: 'RETAINED' | 'REMOVED';
  r2Gate?: {
    phases: ('PLAN' | 'PREVIEW' | 'CHECKPOINT' | 'APPROVAL' | 'EXECUTE' | 'VERIFY')[];
    approvedBy: 'USER_APPROVAL' | 'DURABLE_POLICY';
  };
}

/** Emit only contract-valid outputs: a broken orchestrator must not silently emit schema-invalid records. */
function emit(deps: JitLifecycleDeps, args: EmitArgs): JitLifecycleOutput {
  const output = {
    taskId: args.input.taskId,
    selectedBindingId: args.selectedBindingId,
    provenance: args.provenance,
    taskResult: {
      status: args.verification.status === 'PASS' ? ('SUCCEEDED' as const) : ('FAILED' as const),
      verification: args.verification,
    },
    lifecycleState: args.lifecycleState,
    residueReport: {
      candidates: args.residueCandidates.map((candidate) => ({
        path: candidate.path,
        classification: candidate.classification,
        disposition: candidate.disposition,
      })),
      unknownOrProtectedDeleted: false as const,
    },
    finalState: args.finalState,
    ...(args.r2Gate ? { r2Gate: args.r2Gate } : {}),
  };
  trace(deps, 'OUTPUT_EMITTED', `finalState=${args.finalState}`);
  return parseJitLifecycleOutput(output);
}
