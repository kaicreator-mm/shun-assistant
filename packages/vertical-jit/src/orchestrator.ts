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
  return runLifecycle(input, deps);
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
  const { authorized: taskAuthorized } = await issueGrant(deps, {
    taskId: input.taskId,
    plan: taskPlan,
    action: taskActionSpec,
    authorizationKind: 'AUTOMATIC',
  });
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
  await persistLifecycle(deps, input, provenance, layout, 'INSTALLED');

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
  return runRemovalGate(deps, input, binding, candidate, layout, provenance, verification, hints);
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
  const candidates: ResidueCandidate[] = classifyResidue({
    layout,
    observed,
    protectedRoots: deps.policy.protectedRoots,
    ...(hints?.preExisting ? { preExisting: hints.preExisting } : {}),
    ...(hints?.providerOwnedFiles ? { providerOwnedFiles: hints.providerOwnedFiles } : {}),
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
  const checkpointRef = await persistLifecycle(deps, input, provenance, layout, 'CHECKPOINT');

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

  // (5) EXECUTE — bounded removal through the privileged boundary only,
  // with reconcile-first recovery on uncertain interruption (L2 §9.4).
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

async function collectCandidates(
  deps: JitLifecycleDeps,
  layout: ProviderInstallLayout,
): Promise<string[]> {
  const observed: string[] = [];
  for (const root of [...layout.installDirs, ...layout.cacheDirs, ...layout.configDirs]) {
    observed.push(root);
    if (await deps.fs.isDirectory(root)) {
      for (const child of await deps.fs.listChildren(root)) {
        observed.push(joinPath(root, child));
      }
    }
  }
  return observed;
}

function joinPath(root: string, child: string): string {
  return `${root.replace(/[\\/]+$/, '')}\\${child}`;
}

async function persistLifecycle(
  deps: JitLifecycleDeps,
  input: JitLifecycleInput,
  provenance: ReturnType<typeof provenanceRecord>,
  layout: ProviderInstallLayout,
  state: string,
): Promise<string> {
  const effectId = `jit:${input.taskId}:lifecycle`;
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
      recordedAt: deps.clock(),
    },
  });
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
      recoveryClassification: terminal === 'UAC_DECLINED' ? 'NOT_STARTED' : 'FAILED_BEFORE_EFFECT',
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
      recoveryClassification: terminal === 'UAC_DECLINED' ? 'NOT_STARTED' : 'FAILED_BEFORE_EFFECT',
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
