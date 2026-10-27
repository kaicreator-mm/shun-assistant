// T10 M02: a real, local-only C-003 ControlBackend.
// Unlike the T08 demo it never fabricates receipts, authorization or results.
// Authorization remains exclusively inside the production ActionController.
// A trusted host config fixes the only writable scope before any Goal arrives.
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { availableParallelism, release, totalmem } from 'node:os';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { promisify } from 'node:util';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import {
  type ActionPlan,
  canonicalJson,
  type GoalRequest,
  GoalRequestSchema,
  type TaskState,
} from '@shun/contracts';
import {
  type RegistrySnapshot,
  resolveGoal,
  ShunRegistry,
  TrustedRecipeReadService,
} from '@shun/resolver';
import {
  ImmutableRecipeRepository,
  ShunStore,
  ShunStoreAuthorizationAdapter,
  ShunStoreUiApprovalBridge,
} from '@shun/store';
import { runStorageDiagnose } from '@shun/vertical-storage';
import {
  readBuiltinInventoryCandidate,
  registerBuiltinInventoryCandidate,
} from '../inventory-recipe.ts';
import type {
  ControlBackend,
  DecisionOutcome,
  Outcome,
  PendingApproval,
  PlanPreview,
  PolicyState,
  ReadableResidue,
  ResidueDetail,
  TaskSnapshot,
} from '../ports.ts';
import { previewForPlan } from '../preview.ts';
import { assertFreshVerifiedTerminalCommit, restoreStorageTask } from './recovery.ts';
import { assertSignedHostFactsCurrent } from './registry-host-facts.ts';
import { verifyRegistryIssuance } from './registry-issuance.ts';
import { verifyPinnedRegistryPublicKey } from './registry-key-pin.ts';
import { createStorageRegistrySnapshot } from './registry-snapshot.ts';

const execFileAsync = promisify(execFile);
const CAPABILITY = 'system.storage.diagnose_bounded_action';
const BINDING = 'binding/shun-storage-local-windows';
const POLICY = 'shun.real-storage.policy-v1';

function isInside(root: string, item: string): boolean {
  const rel = relative(root, item);
  return (
    rel !== '' && !isAbsolute(rel) && !rel.split(/[\\/]/).includes('..') && !rel.startsWith('..')
  );
}

export interface RealStorageConfig {
  /** Explicitly configured operator-owned scan root, never an HTTP Goal parameter. */
  workspace: string;
  /** One or more predeclared canary/user-asset paths; these are never cleanup targets. */
  protectedAssets: string[];
  evidenceDir: string;
  databaseFile: string;
  /** Operator-pinned independent registry/currentness revision.
   * Must be prepared outside the candidate's own snapshot/Goal execution.
   */
  registryRevisionFile: string;
  /** Operator-pinned Ed25519 verification key; signer private key is never loaded by Shun. */
  registryPublicKeyFile: string;
  /** SPKI DER SHA-256 pinned outside the issuer files by a trusted operator. */
  registryPublicKeySha256: string;
  issuanceSecret: string;
  integritySecret: string;
  clock?: () => string;
}

interface RealTask {
  taskId: string;
  title: string;
  createdAt: string;
  state: TaskState;
  progress: TaskSnapshot['progress'];
  plan?: ActionPlan;
  failure?: TaskSnapshot['failure'];
  verification?: TaskSnapshot['verification'];
  execution?: TaskSnapshot['execution'];
  recovery?: TaskSnapshot['recovery'];
}

/** Production controller must be instantiated from trusted local config only.
 * The constructor/factory are intentionally not reachable from a request.
 * No real backend is advertised if Windows, roots or durable authority fail.
 */
export class RealStorageControlBackend implements ControlBackend {
  readonly #store: ShunStore;
  readonly #adapter: ShunStoreAuthorizationAdapter;
  readonly #approvals: ShunStoreUiApprovalBridge;
  readonly #controller: ActionController;
  readonly #authority: AuthorizationAuthority;
  readonly #workspace: string;
  readonly #protected: string[];
  readonly #evidenceDir: string;
  readonly #registryRevisionFile: string;
  readonly #registryPublicKeyFile: string;
  readonly #registryPublicKeySha256: string;
  readonly #clock: () => string;
  readonly #tasks = new Map<string, RealTask>();
  readonly #archivedTasks = new Map<string, TaskSnapshot>();
  #policy: PolicyState = { kind: 'UNKNOWN', reason: 'No verified authority snapshot yet' };

  private constructor(config: RealStorageConfig, workspace: string, protectedAssets: string[]) {
    this.#workspace = workspace;
    this.#protected = protectedAssets;
    this.#evidenceDir = resolve(config.evidenceDir);
    this.#registryRevisionFile = resolve(config.registryRevisionFile);
    this.#registryPublicKeyFile = resolve(config.registryPublicKeyFile);
    this.#registryPublicKeySha256 = config.registryPublicKeySha256;
    this.#clock = config.clock ?? (() => new Date().toISOString());
    this.#store = new ShunStore({ file: config.databaseFile });
    this.#adapter = new ShunStoreAuthorizationAdapter(this.#store);
    this.#approvals = new ShunStoreUiApprovalBridge(this.#store, { clock: this.#clock });
    this.#authority = new AuthorizationAuthority({
      state: this.#adapter,
      grants: this.#adapter,
      integritySecret: config.integritySecret,
      issuanceSecret: config.issuanceSecret,
      clock: this.#clock,
    });
    this.#controller = new ActionController({
      authority: this.#authority,
      policyState: this.#adapter,
      approvals: this.#approvals,
      issuanceSecret: config.issuanceSecret,
      clock: this.#clock,
    });
  }

  static async create(config: RealStorageConfig): Promise<RealStorageControlBackend> {
    if (process.platform !== 'win32') throw new Error('REAL_STORAGE_REQUIRES_WINDOWS');
    if (
      !config.issuanceSecret ||
      !config.integritySecret ||
      config.issuanceSecret === config.integritySecret
    ) {
      throw new Error('REAL_STORAGE_SEPARATE_AUTHORITY_SECRETS_REQUIRED');
    }
    const workspace = resolve(config.workspace);
    const metadata = await fs.lstat(workspace);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error('REAL_STORAGE_UNTRUSTED_ROOT');
    }
    const real = await fs.realpath(workspace);
    if (real.toLowerCase() !== workspace.toLowerCase())
      throw new Error('REAL_STORAGE_ROOT_ALIAS_REFUSED');
    const protectedAssets: string[] = [];
    for (const p of config.protectedAssets) {
      const target = resolve(p);
      if (!isInside(real, target)) throw new Error('REAL_STORAGE_PROTECTED_PATH_OUT_OF_SCOPE');
      const info = await fs.lstat(target);
      if (info.isSymbolicLink()) throw new Error('REAL_STORAGE_PROTECTED_LINK_REFUSED');
      const canonical = await fs.realpath(target);
      if (!isInside(real, canonical)) throw new Error('REAL_STORAGE_PROTECTED_PATH_ALIAS');
      protectedAssets.push(canonical);
    }
    if (protectedAssets.length < 1) throw new Error('REAL_STORAGE_PROTECTED_ASSETS_REQUIRED');
    const evidenceDir = resolve(config.evidenceDir);
    if (evidenceDir === real || isInside(real, evidenceDir)) {
      throw new Error('REAL_STORAGE_EVIDENCE_INSIDE_DESTRUCTIVE_ROOT');
    }
    const registryFile = resolve(config.registryRevisionFile);
    if (registryFile === real || isInside(real, registryFile)) {
      throw new Error('REAL_STORAGE_REGISTRY_REVISION_INSIDE_DESTRUCTIVE_ROOT');
    }
    const publicKeyFile = resolve(config.registryPublicKeyFile);
    if (publicKeyFile === real || isInside(real, publicKeyFile)) {
      throw new Error('REAL_STORAGE_REGISTRY_PUBLIC_KEY_INSIDE_DESTRUCTIVE_ROOT');
    }
    for (const [path, label] of [
      [registryFile, 'ISSUANCE'],
      [publicKeyFile, 'PUBLIC_KEY'],
    ] as const) {
      const fileInfo = await fs.lstat(path);
      if (!fileInfo.isFile() || fileInfo.isSymbolicLink()) {
        throw new Error('REAL_STORAGE_REGISTRY_' + label + '_NOT_TRUSTED_FILE');
      }
      const canonical = await fs.realpath(path);
      if (canonical.toLowerCase() !== path.toLowerCase()) {
        throw new Error('REAL_STORAGE_REGISTRY_' + label + '_ALIAS_REFUSED');
      }
    }
    const databaseFile = resolve(config.databaseFile);
    if (databaseFile === real || isInside(real, databaseFile)) {
      throw new Error('REAL_STORAGE_DATABASE_INSIDE_DESTRUCTIVE_ROOT');
    }
    await fs.mkdir(dirname(databaseFile), { recursive: true });
    await fs.mkdir(evidenceDir, { recursive: true });
    const backend = new RealStorageControlBackend(config, real, protectedAssets);
    try {
      // Never advertise a real ControlBackend if the operator-issued proof
      // is absent, stale or unsigned, even when local authorization initializes.
      await backend.#loadRegistryIssuance();
      await backend.#initializeAuthority();
      return backend;
    } catch (error) {
      await backend.close();
      throw error;
    }
  }

  async #initializeAuthority(): Promise<void> {
    const oldAuthority = await this.#adapter.loadAuthorityRecord();
    const oldPolicy = await this.#adapter.loadCurrentPolicy();
    const now = this.#clock();
    if (oldAuthority === null && oldPolicy === null && !(await this.#adapter.hasAnyGrant())) {
      const inserted = await this.#adapter.compareAndSaveAuthorityRecord(
        {
          authorityId: 'shun.local.storage',
          authorityRevision: 'r1',
          updatedAt: now,
          policyInitialized: true,
          priorAuthorityRevisions: [],
        },
        null,
      );
      if (!inserted) throw new Error('REAL_STORAGE_AUTHORITY_INIT_RACE');
      const policyInserted = await this.#adapter.compareAndSavePolicySnapshot(
        {
          policySnapshotRevision: POLICY,
          status: 'ACTIVE',
          authorityId: 'shun.local.storage',
          authorityRevision: 'r1',
          revokedGrantIds: [],
          priorRevisions: [],
          rules: [],
          riskGuards: [],
          updatedAt: now,
        },
        null,
      );
      if (!policyInserted) throw new Error('REAL_STORAGE_POLICY_INIT_RACE');
    } else if (oldAuthority === null || oldPolicy === null) {
      throw new Error('REAL_STORAGE_PARTIAL_AUTHORITY_REFUSED');
    }
    const current = await this.#authority.currentAuthority();
    if (current.kind !== 'CURRENT' || current.policyStatus !== 'ACTIVE') {
      throw new Error('REAL_STORAGE_CURRENT_AUTHORITY_UNRESOLVABLE');
    }
    this.#policy = { kind: 'ACTIVE', revision: current.policySnapshotRevision };
    for (const row of await this.#store.listRecords('task')) {
      this.#archivedTasks.set(row.recordId, restoreStorageTask(row, this.#workspace));
    }
  }

  /**
   * User-triggered persistence of ONE immutable built-in Recipe candidate.
   * The trusted host owns both the database and the actual ActionController.
   * Preview currentness is deliberately UNRESOLVABLE until T08 integrates a
   * genuine registered `system.inventory` plan; this route never authorizes
   * even an R0 effect, promotes ACTIVE, or runs code.
   */
  saveBuiltinInventoryCandidate() {
    const repo = new ImmutableRecipeRepository(this.#store);
    const controller = this.#controller;
    const service = new TrustedRecipeReadService({
      repository: {
        append: (value) => repo.append(value),
        get: (recipeId, sha) => repo.get(recipeId, sha),
      },
      currentness: () => ({ kind: 'UNRESOLVABLE' as const }),
      loadExpectedPlan: () => {
        throw new Error('RECIPE_NOT_ACTIVE_OR_APPROVED');
      },
      controller: {
        authorizePlan: (input) =>
          controller.authorizePlan(input as Parameters<ActionController['authorizePlan']>[0]),
      },
    });
    return registerBuiltinInventoryCandidate(service);
  }

  /** Read the exact current built-in candidate from real durable SQLite.
   * Existing T03 repository.get verifies payload digest and immutable identity.
   * This route is READ-ONLY and never performs ActionController authorization.
   */
  readBuiltinInventoryCandidate() {
    return readBuiltinInventoryCandidate(new ImmutableRecipeRepository(this.#store));
  }


  meta(): { policy: PolicyState; localOnly: true; simulated: false } {
    return { policy: this.#policy, localOnly: true, simulated: false };
  }

  async submitGoal(raw: GoalRequest): Promise<{ taskId: string }> {
    const request = GoalRequestSchema.parse(raw);
    if (
      request.policyContext.privacyPolicy.localOnly !== true ||
      request.policyContext.privacyPolicy.externalDisclosure !== 'FORBIDDEN' ||
      !request.policyContext.environmentPolicy.allowedBackendKinds.includes('LOCAL_WINDOWS') ||
      request.policyContext.environmentPolicy.allowElevation ||
      request.objects.some(
        (obj) => obj.kind !== 'DIRECTORY' || resolve(obj.ref) !== this.#workspace,
      )
    ) {
      throw new Error('REAL_STORAGE_GOAL_SCOPE_OR_PRIVACY_REFUSED');
    }
    if (!/storage|cache|bounded cleanup/i.test(request.goal)) {
      throw new Error('REAL_STORAGE_ONLY_C003_SUPPORTED');
    }
    if (this.#tasks.has(request.taskId) || this.#archivedTasks.has(request.taskId)) {
      throw new Error('REAL_STORAGE_DUPLICATE_TASK_ID');
    }
    const now = this.#clock();
    // The durable claim is committed before the asynchronous runner starts.
    // A restart or second process can never replay the same taskId and issue
    // another destructive effect from an already-seen human Goal.
    const reservation = await this.#store.apply('real-storage-request-' + request.taskId, {
      recordKind: 'task',
      recordId: request.taskId,
      payload: { status: 'RECEIVED', workspace: this.#workspace, createdAt: now },
    });
    if (!reservation.applied) throw new Error('REAL_STORAGE_TASK_REPLAY_REFUSED');
    const task: RealTask = {
      taskId: request.taskId,
      title: request.goal,
      createdAt: now,
      state: 'RECEIVED',
      progress: [{ at: now, state: 'RECEIVED' }],
    };
    this.#tasks.set(task.taskId, task);
    // The observed facts, resolver, plan and actual execution are all real.
    // This is intentionally asynchronous so UI can inspect and decide before
    // authorizePlan resumes. Failure is recorded, never swallowed as success.
    void this.#execute(task).catch(() => {
      // Once the controller authorized the plan the action could have been
      // reached. No exception by itself proves that a destructive effect
      // did not occur; do not report an ordinary retryable FAILED.
      const uncertain = task.state === 'EXECUTING' || task.state === 'VERIFYING';
      task.failure = {
        code: uncertain ? 'REAL_STORAGE_EFFECT_UNCERTAIN' : 'REAL_STORAGE_FAILED_BEFORE_EFFECT',
        message: uncertain
          ? 'Execution stopped without a verified terminal. Reconcile the journal and actual disk before retrying.'
          : 'This task could not start an authorized effect. Nothing is automatically retried.',
      };
      task.recovery = {
        classification: uncertain ? 'MAY_HAVE_EXECUTED_UNCERTAIN' : 'NOT_STARTED',
        detail: uncertain
          ? 'An authorized effect may have run. The UI cannot assert otherwise.'
          : 'The real ActionController did not begin an authorized effect.',
        reconciled: !uncertain,
      };
      this.#move(task, uncertain ? 'NEEDS_INTERVENTION' : 'FAILED');
    });
    return { taskId: task.taskId };
  }

  #move(task: RealTask, state: TaskState): void {
    task.state = state;
    task.progress.push({ state, at: this.#clock() });
  }

  /** Read-only issuer boundary: the candidate never calculates or writes its
   * own CURRENT revision. Source owns the Ed25519 private key, atomic snapshot,
   * and short issuance lifetime; Windows ACL/identity positive evidence is M03.
   */
  async #loadRegistryIssuance(): Promise<ReturnType<typeof verifyRegistryIssuance>> {
    const [issuanceInfo, keyInfo] = await Promise.all([
      fs.lstat(this.#registryRevisionFile),
      fs.lstat(this.#registryPublicKeyFile),
    ]);
    if (
      !issuanceInfo.isFile() ||
      issuanceInfo.isSymbolicLink() ||
      !keyInfo.isFile() ||
      keyInfo.isSymbolicLink()
    ) {
      throw new Error('REAL_STORAGE_REGISTRY_ISSUANCE_FILE_UNTRUSTED');
    }
    const [issuancePath, keyPath] = await Promise.all([
      fs.realpath(this.#registryRevisionFile),
      fs.realpath(this.#registryPublicKeyFile),
    ]);
    if (
      issuancePath.toLowerCase() !== this.#registryRevisionFile.toLowerCase() ||
      keyPath.toLowerCase() !== this.#registryPublicKeyFile.toLowerCase()
    ) {
      throw new Error('REAL_STORAGE_REGISTRY_ISSUANCE_FILE_ALIAS');
    }
    const [rawJson, keyPem] = await Promise.all([
      fs.readFile(this.#registryRevisionFile, 'utf8'),
      fs.readFile(this.#registryPublicKeyFile, 'utf8'),
    ]);
    verifyPinnedRegistryPublicKey(keyPem, this.#registryPublicKeySha256);
    return verifyRegistryIssuance(
      JSON.parse(rawJson) as unknown,
      keyPem,
      this.#workspace,
      this.#clock(),
    );
  }

  async #observeWindowsEnvironment(): Promise<RegistrySnapshot['environment']> {
    const stats = await fs.statfs(this.#workspace);
    const arch = process.arch === 'x64' ? 'X64' : process.arch === 'arm64' ? 'ARM64' : null;
    if (!arch) throw new Error('REAL_STORAGE_UNSUPPORTED_ARCH');
    const { stdout } = await execFileAsync(
      'C:\\Windows\\System32\\whoami.exe',
      ['/groups', '/fo', 'csv', '/nh'],
      {
        windowsHide: true,
        encoding: 'utf8',
        timeout: 15_000,
      },
    );
    const privilegeMode = /S-1-16-12288/i.test(stdout)
      ? 'ELEVATED_ADMIN'
      : /S-1-5-32-544/i.test(stdout)
        ? 'FILTERED_ADMIN'
        : 'STANDARD_USER';
    return {
      environmentId: 'shun-real-storage-' + process.arch,
      backendKind: 'LOCAL_WINDOWS',
      os: `WINDOWS-${release()}`,
      arch,
      observationRevision: 'host-' + this.#clock(),
      runtimeCapabilities: ['windows-storage-metadata'],
      privilegeMode,
      guiSession: true,
      filesystemCapabilities: ['read', 'write'],
      networkPolicy: 'OFFLINE',
      resources: {
        cpuCores: Math.max(1, availableParallelism()),
        memoryMb: Math.max(1, Math.floor(totalmem() / (1024 * 1024))),
        freeDiskMb: Math.max(0, Math.floor(Number(stats.bavail * stats.bsize) / (1024 * 1024))),
      },
    };
  }

  async #resolveBinding(
    task: RealTask,
  ): Promise<{ environmentId: string; rankingPolicyRevision: string }> {
    this.#move(task, 'RESOLVING');
    const observed = await this.#observeWindowsEnvironment();
    // Dynamic machine facts are observations, not an authority's issuance.
    // Consume the exact short-lived, independently signed source snapshot;
    // refuse every material host drift instead of self-issuing a new digest.
    const signed = await this.#loadRegistryIssuance();
    const environment = signed.snapshot.environment;
    assertSignedHostFactsCurrent(environment, observed);
    const snapshot = createStorageRegistrySnapshot(environment);
    if (canonicalJson(snapshot) !== canonicalJson(signed.snapshot)) {
      throw new Error('REAL_STORAGE_REGISTRY_SIGNED_FACT_CLASSES_MISMATCH');
    }
    const registry = await ShunRegistry.fromAttestedSnapshot(snapshot, {
      // Re-read the independently signed CURRENT revision, so a changed or
      // expired source between snapshot-read and Resolver use fails closed.
      currentnessAuthority: {
        currentRevision: async () => (await this.#loadRegistryIssuance()).currentRevision,
      },
      additionalObjectiveMatchers: {
        [CAPABILITY]: [/bounded cache cleanup/i, /system\.storage\.diagnose_bounded_action/i],
      },
    });
    const result = resolveGoal({
      request: {
        taskId: task.taskId,
        goal: CAPABILITY + ': ' + task.title,
        objects: [{ kind: 'DIRECTORY', ref: this.#workspace }],
        constraints: { other: { offline: true, boundedCleanup: true } },
        policyContext: {
          privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
          environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
        },
      },
      registry,
      objectExists: () => true,
    });
    if (
      result.stage !== 'RESOLUTION' ||
      result.record.selectedBindingId !== BINDING ||
      result.record.hardGateDispositions.some((row) => row.outcome !== 'PASS') ||
      result.record.privacyDisclosurePlan.externalDisclosure !== 'FORBIDDEN'
    ) {
      throw new Error('REAL_STORAGE_RESOLVER_HARD_GATES_FAILED');
    }
    return {
      environmentId: environment.environmentId,
      rankingPolicyRevision: signed.currentRevision,
    };
  }

  async #execute(task: RealTask): Promise<void> {
    const binding = await this.#resolveBinding(task);
    let crossedEffectBoundary = false;
    const controller = {
      authorizePlan: async (input: { plan: unknown }) => {
        const plan = input.plan as ActionPlan;
        task.plan = plan;
        this.#move(task, 'AWAITING_AUTHORIZATION');
        const authorized = await this.#controller.authorizePlan(input);
        // Plan approval alone is not an effect boundary. Keep the durable
        // task at RECEIVED until an effect presentation has been validated
        // and is about to be handed back to the executor. A crash here is
        // therefore provably NOT_STARTED, not MAY_HAVE_EXECUTED_UNCERTAIN.
        return authorized;
      },
      authorizeEffect: async (input: Parameters<ActionController['authorizeEffect']>[0]) => {
        // A stale or rotated issuer cannot silently authorize a later effect
        // with an earlier preview/plan. Require fresh exact-current source.
        const latest = await this.#loadRegistryIssuance();
        if (latest.currentRevision !== binding.rankingPolicyRevision) {
          throw new Error('REAL_STORAGE_REGISTRY_ISSUANCE_CHANGED_BEFORE_EFFECT');
        }
        // Verify observed Windows token/disk/environment again AFTER human
        // consent but BEFORE each R2 effect. The plan's issued facts cannot
        // silently outlive drift on the host.
        assertSignedHostFactsCurrent(
          latest.snapshot.environment,
          await this.#observeWindowsEnvironment(),
        );
        const effectAuthorization = await this.#controller.authorizeEffect(input);
        if (effectAuthorization.ok) {
          // This is the earliest point after which the caller may receive a
          // valid effect authorization and perform the destructive action.
          // Persist the boundary BEFORE returning it. If the process dies
          // after this commit, recovery must conservatively reconcile.
          const boundary = await this.#store.apply(
            'real-storage-effect-authorized-' + task.taskId + '-' + input.action.actionId,
            {
              recordKind: 'task',
              recordId: task.taskId,
              payload: {
                status: 'EFFECT_AUTHORIZED',
                workspace: this.#workspace,
                createdAt: task.createdAt,
                planHash: task.plan?.planHash,
                actionId: input.action.actionId,
              },
            },
          );
          // A successful apply call means the durable boundary is present.
          // If it was already present, ShunStore only returns applied=false
          // for the exact same effect id + record + payload. Treat that as a
          // crossed boundary but refuse to hand a replayed presentation to
          // the executor.
          crossedEffectBoundary = true;
          if (task.state !== 'EXECUTING') this.#move(task, 'EXECUTING');
          if (!boundary.applied) {
            throw new Error('REAL_STORAGE_EFFECT_AUTHORIZATION_REPLAY_REFUSED');
          }
        }
        return effectAuthorization;
      },
    };
    const result = await runStorageDiagnose(
      {
        controller,
        scope: { roots: [this.#workspace] },
        evidenceDir: this.#evidenceDir,
        policySnapshotRevision: POLICY,
        rankingPolicyRevision: binding.rankingPolicyRevision,
        environmentId: binding.environmentId,
        providerId: 'storage.cleaner.local-windows',
        providerVersion: '0.1.0',
        clock: this.#clock,
      },
      {
        taskId: task.taskId,
        targetVolume: this.#workspace.slice(0, 2).toUpperCase(),
        protectedAssets: this.#protected.map((path) => ({ path })),
        cleanupPolicy: { eligibleCategories: ['CACHE'] },
      },
    );
    if (!result.output.cleanupPlan && result.receipts.length === 0) {
      // CANCELLED is only an effect-free terminal while this execution has
      // provably never crossed the durable per-effect authorization boundary.
      // Once crossed, even a no-plan/no-receipt return is ambiguous and must
      // flow through the outer uncertainty path instead of overwriting the
      // EFFECT_AUTHORIZED evidence with an optimistic NOT_STARTED terminal.
      if (crossedEffectBoundary || task.state === 'EXECUTING' || task.state === 'VERIFYING') {
        throw new Error('REAL_STORAGE_CANCEL_AFTER_EFFECT_AUTHORIZATION_REFUSED');
      }
      const cancelled = await this.#store.apply('real-storage-cancel-' + task.taskId, {
        recordKind: 'task',
        recordId: task.taskId,
        payload: {
          status: 'CANCELLED',
          workspace: this.#workspace,
          createdAt: task.createdAt,
          effectBoundaryCrossed: false,
        },
      });
      if (!cancelled.applied) {
        throw new Error('REAL_STORAGE_CANCEL_REPLAY_REFUSED');
      }
      if (task.state !== 'CANCELLED') this.#move(task, 'CANCELLED');
      return;
    }
    if (
      result.receipts.length === 0 ||
      result.receipts.some((row) => row.terminal !== 'SUCCEEDED') ||
      !result.output.reclaimed ||
      result.output.protectedAssetVerification.some((row) => !row.unchanged)
    ) {
      throw new Error('REAL_STORAGE_SEMANTIC_VERIFICATION_INCOMPLETE');
    }
    this.#move(task, 'VERIFYING');
    if (!task.plan) throw new Error('REAL_STORAGE_MISSING_AUTHORIZED_PLAN');
    // Commit the verified terminal before presenting SUCCEEDED to the UI.
    // A failed commit or process death is conservatively uncertain.
    const verifiedTerminal = await this.#store.apply('real-storage-result-' + task.taskId, {
      recordKind: 'task',
      recordId: task.taskId,
      payload: {
        status: 'SUCCEEDED',
        workspace: this.#workspace,
        createdAt: task.createdAt,
        planHash: task.plan.planHash,
        verifiedAt: this.#clock(),
        protectedVerified: true,
        receiptCount: result.receipts.length,
      },
    });
    // A replayed/equivalent receipt is not a freshly committed terminal for
    // this execution. Refuse optimistic UI PASS and enter the uncertainty path
    // while the task is still VERIFYING, even when apply() resolves normally.
    assertFreshVerifiedTerminalCommit(verifiedTerminal);
    task.verification = {
      status: 'PASS',
      checks: [
        { checkId: 'protected-assets-unchanged', status: 'PASS' },
        { checkId: 'reclaimed-bytes-verified', status: 'PASS' },
      ],
    };
    task.recovery = {
      classification: 'COMPLETED_VERIFIED',
      detail: 'Real bounded cleanup verified against the protected asset snapshot and journal',
      reconciled: true,
    };
    task.execution = { terminal: 'SUCCEEDED', finishedAt: this.#clock() };
    this.#move(task, 'SUCCEEDED');
  }

  async listTasks(): Promise<TaskSnapshot[]> {
    return [
      ...this.#archivedTasks.values(),
      ...[...this.#tasks.values()].map((task) => this.#snapshot(task)),
    ];
  }

  async taskSnapshot(taskId: string): Promise<TaskSnapshot | undefined> {
    const task = this.#tasks.get(taskId);
    return task ? this.#snapshot(task) : this.#archivedTasks.get(taskId);
  }

  #snapshot(task: RealTask): TaskSnapshot {
    const approval = this.#approvals.listPending().find((row) => row.taskId === task.taskId);
    return {
      taskId: task.taskId,
      title: task.title,
      state: task.state,
      revision: task.progress.length,
      createdAt: task.createdAt,
      updatedAt: task.progress.at(-1)?.at ?? task.createdAt,
      progress: [...task.progress],
      ...(task.failure ? { failure: task.failure } : {}),
      ...(task.plan
        ? {
            planSummary: {
              planHash: task.plan.planHash,
              capabilityId: task.plan.capabilityId,
              riskClass: 'R2',
              riskStatement: 'Destructive bounded action requiring exact-plan approval',
              actionCount: task.plan.actions.length,
              policySnapshotRevision: task.plan.policySnapshotRevision,
            },
          }
        : {}),
      ...(approval
        ? {
            approval: {
              approvalId: approval.approvalId,
              status: approval.status,
              summary: approval.summary,
              planHash: approval.planHash,
              expiresAt: approval.expiresAt,
            },
          }
        : {}),
      ...(task.execution ? { execution: task.execution } : {}),
      ...(task.verification ? { verification: task.verification } : {}),
      ...(task.recovery ? { recovery: task.recovery } : {}),
      localOnly: { enforced: true, externalDisclosure: 'FORBIDDEN' },
    };
  }

  async taskPreview(taskId: string): Promise<PlanPreview | undefined> {
    const task = this.#tasks.get(taskId);
    if (!task?.plan) return undefined;
    const pending = this.#approvals.listPending().find((row) => row.taskId === taskId);
    return previewForPlan(task.plan, { generatedAt: this.#clock(), expiresAt: pending?.expiresAt });
  }

  async pendingApprovals(): Promise<PendingApproval[]> {
    return this.#approvals.listPending().map((row) => ({
      ...row,
      riskClass: 'R2',
      requiresExplicitApproval: true,
    }));
  }

  async approvalWithPreview(
    approvalId: string,
  ): Promise<{ approval: PendingApproval; preview: PlanPreview } | undefined> {
    const approval = (await this.pendingApprovals()).find((item) => item.approvalId === approvalId);
    if (!approval) return undefined;
    const preview = await this.taskPreview(approval.taskId);
    return preview ? { approval, preview } : undefined;
  }

  async decideApproval(input: {
    approvalId: string;
    approved: boolean;
    seenPlanHash: string;
    reason?: string;
  }): Promise<DecisionOutcome> {
    const saved = this.#approvals.get(input.approvalId);
    if (!saved) return { ok: false, code: 'APPROVAL_NOT_FOUND', detail: 'No approval exists' };
    const task = this.#tasks.get(saved.taskId);
    if (!task?.plan || task.plan.planHash !== saved.planHash) {
      return {
        ok: false,
        code: 'POLICY_STATE_UNKNOWN',
        detail: 'Live plan identity is unavailable',
      };
    }
    if (input.approved) {
      const current = await this.#authority.currentAuthority();
      if (current.kind !== 'CURRENT' || current.policyStatus !== 'ACTIVE') {
        return {
          ok: false,
          code: 'POLICY_STATE_UNKNOWN',
          detail: 'Current policy cannot authorize this plan',
        };
      }
      if (current.policySnapshotRevision !== task.plan.policySnapshotRevision) {
        return {
          ok: false,
          code: 'POLICY_REVISION_DRIFT',
          detail: 'Policy moved; fresh plan required',
        };
      }
    }
    const result = this.#approvals.decide({
      approvalId: input.approvalId,
      taskId: saved.taskId,
      planHash: input.seenPlanHash,
      approved: input.approved,
    });
    if (!result.ok) {
      const code =
        result.code === 'HASH_MISMATCH'
          ? 'PLAN_HASH_MISMATCH'
          : result.code === 'NOT_FOUND'
            ? 'APPROVAL_NOT_FOUND'
            : result.code === 'EXPIRED'
              ? 'APPROVAL_EXPIRED'
              : result.code === 'NOT_LIVE'
                ? 'POLICY_STATE_UNKNOWN'
                : 'APPROVAL_ALREADY_DECIDED';
      return { ok: false, code, detail: 'Exact live approval was refused: ' + result.code };
    }
    if (!input.approved) this.#move(task, 'CANCELLED');
    return { ok: true, value: { decision: result.decision, taskState: task.state } };
  }

  async cancelTask(taskId: string): Promise<Outcome<{ state: TaskState }>> {
    const task = this.#tasks.get(taskId);
    if (!task) return { ok: false, code: 'TASK_NOT_FOUND', detail: 'Unknown task' };
    const approval = this.#approvals.listPending().find((row) => row.taskId === taskId);
    if (approval) {
      this.#approvals.decide({
        approvalId: approval.approvalId,
        taskId,
        planHash: approval.planHash,
        approved: false,
      });
      this.#move(task, 'CANCELLED');
      return { ok: true, value: { state: task.state } };
    }
    return {
      ok: false,
      code: 'CANCEL_UNSUPPORTED',
      detail: 'Real action cannot be cancelled by UI after authorization',
    };
  }

  async answerClarification(): Promise<Outcome<{ state: TaskState }>> {
    return {
      ok: false,
      code: 'CLARIFICATION_NOT_PENDING',
      detail: 'No real clarification is pending',
    };
  }
  async reconcileTask(): Promise<Outcome<{ classification: 'MAY_HAVE_EXECUTED_UNCERTAIN' }>> {
    return {
      ok: false,
      code: 'RECOVERY_NOT_APPLICABLE',
      detail: 'UI cannot reclassify an uncertain real effect',
    };
  }
  async retryTask(): Promise<Outcome<{ state: TaskState }>> {
    return {
      ok: false,
      code: 'RETRY_BLOCKED_UNCERTAIN',
      detail: 'Real destructive retry requires journal/post-state reconciliation',
    };
  }
  async residueSummary(): Promise<ReadableResidue | ResidueDetail | undefined> {
    return undefined;
  }
  async evidence(): Promise<Outcome<{ ref: string; record: unknown }>> {
    return { ok: false, code: 'EVIDENCE_NOT_FOUND', detail: 'No browsable evidence for this ref' };
  }
  async close(): Promise<void> {
    this.#approvals.abortPending();
    await this.#store.close();
  }
}
