// In-memory harness for the Loop B vertical: every port the orchestrator
// consumes, realized against a single memory store, plus fault injection.
//
// The privileged mutation surface (putFile/removeTree) is deliberately NOT
// part of the read-only FilesystemPort — only effect executors (acquisition
// effects, task backend) may touch it, mirroring how the real adapter's side
// effects go through winget processes while the orchestrator only observes.
import { createHash } from 'node:crypto';
import {
  type ApprovalDecision,
  type ApprovalPort,
  type ApprovalRequest,
  type AuthorizedAction,
  type CapabilityDefinition,
  type EnvironmentBackend,
  type EnvironmentFacts,
  type EnvironmentRequirements,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type Feasibility,
  type PreparedEnvironment,
  type ProviderCapabilityBinding,
  type ProviderDefinition,
  type ProviderEnvironmentBinding,
  type RegistryReadModelPort,
  type ShunStoreMutation,
  type StoreApplicationReceipt,
  type StorePort,
} from '@shun/contracts';
import { type JournalPort, MemoryJournal } from './journal.ts';
import { LocalAuthority, MemoryPlanLedger } from './local-authority.ts';
import { LocalPrivilegedBackend, type PrivilegedFault } from './local-backend.ts';
import type { JitLifecycleDeps } from './orchestrator.ts';
import type {
  AcquisitionCandidate,
  AcquisitionPort,
  FilesystemPort,
  ProcessPort,
  ProcessResult,
  ProcessRunSpec,
  ProviderInstallLayout,
} from './ports.ts';
import { AcquisitionError } from './ports.ts';
import { PatternVerifier } from './verifiers.ts';

// ---- filesystem ----

interface FsNode {
  readonly kind: 'dir' | 'file';
  content?: string;
}

export class MemoryFilesystem implements FilesystemPort {
  readonly #nodes = new Map<string, FsNode>();
  /** key → original path spelling (Windows-like: case-insensitive, case-preserving). */
  readonly #display = new Map<string, string>();

  constructor(initial: Record<string, string | null> = {}) {
    for (const [path, content] of Object.entries(initial)) {
      if (content === null) this.#mkdir(path);
      else this.#putFile(path, content);
    }
  }

  // ---- observation port (read-only) ----

  async exists(path: string): Promise<boolean> {
    return this.#nodes.has(this.#key(path));
  }

  async isDirectory(path: string): Promise<boolean> {
    return this.#nodes.get(this.#key(path))?.kind === 'dir';
  }

  async listChildren(path: string): Promise<string[]> {
    const prefix = `${this.#key(path)}/`;
    const children = new Set<string>();
    for (const [key, display] of this.#display) {
      if (!this.#nodes.has(key) || !key.startsWith(prefix)) continue;
      const first = display.slice(prefix.length).split('/')[0];
      if (first) children.add(first);
    }
    return [...children].sort();
  }

  async sha256File(path: string): Promise<string> {
    const node = this.#nodes.get(this.#key(path));
    if (node?.kind !== 'file') throw new Error(`not a file: ${path}`);
    return createHash('sha256')
      .update(node.content ?? '', 'utf8')
      .digest('hex');
  }

  async readText(path: string): Promise<string> {
    const node = this.#nodes.get(this.#key(path));
    if (node?.kind !== 'file') throw new Error(`not a file: ${path}`);
    return node.content ?? '';
  }

  async writeText(path: string, contents: string): Promise<void> {
    this.#putFile(path, contents);
  }

  async sizeBytes(path: string): Promise<number> {
    const node = this.#nodes.get(this.#key(path));
    if (node?.kind !== 'file') throw new Error(`not a file: ${path}`);
    return (node.content ?? '').length;
  }

  // ---- privileged mutation (effect executors only; never via the port) ----

  #key(path: string): string {
    return path.replaceAll('\\', '/').replace(/\/+$/, '').toLowerCase();
  }

  #putFile(path: string, content: string): void {
    const key = this.#key(path);
    this.#nodes.set(key, { kind: 'file', content });
    this.#display.set(
      key,
      path
        .split(/[\\/]+/)
        .filter((segment) => segment.length > 0)
        .join('/'),
    );
  }

  #mkdir(path: string): void {
    // Creating a directory implies its ancestors (real filesystem semantics);
    // every level keeps the caller's spelling, matching is case-insensitive.
    const key = this.#key(path);
    const segments = key.split('/');
    const given = path.split(/[\\/]+/).filter((segment) => segment.length > 0);
    let partial = '';
    for (const [index, segment] of segments.entries()) {
      partial = partial ? `${partial}/${segment}` : segment;
      if (!this.#nodes.has(partial)) {
        this.#nodes.set(partial, { kind: 'dir' });
        this.#display.set(partial, given.slice(0, index + 1).join('/'));
      }
    }
  }

  /** Effect executor surface: plant a directory tree. */
  putTree(paths: readonly string[], files: Record<string, string> = {}): void {
    for (const dir of paths) this.#mkdir(dir);
    for (const [file, content] of Object.entries(files)) this.#putFile(file, content);
  }

  /** Effect executor surface: remove a subtree. */
  removeTree(path: string): void {
    const prefix = `${this.#key(path)}/`;
    for (const key of [...this.#nodes.keys()]) {
      if (key === this.#key(path) || key.startsWith(prefix)) this.#nodes.delete(key);
    }
  }
}

// ---- process (scripted) ----

export class ScriptedProcessPort implements ProcessPort {
  readonly calls: ProcessRunSpec[] = [];
  readonly #script: ((spec: ProcessRunSpec) => ProcessResult | Promise<ProcessResult>)[];

  constructor(script: ((spec: ProcessRunSpec) => ProcessResult | Promise<ProcessResult>)[] = []) {
    this.#script = script;
  }

  async run(spec: ProcessRunSpec): Promise<ProcessResult> {
    this.calls.push(spec);
    const next = this.#script.shift();
    if (!next) return { exitCode: 0, stdout: '', stderr: '', timedOut: false };
    return next(spec);
  }
}

// ---- acquisition ----

export interface MemoryCatalogEntry {
  readonly version: string;
  readonly license: string;
  readonly publisher: string;
  readonly installerSha256: string;
  readonly installDir: string;
  readonly cacheDir?: string;
  readonly configDir?: string;
  readonly executableName: string;
}

/**
 * Memory "official winget": a fixed catalog whose provenance facts are
 * declared by the harness. Installing/uninstalling mutates the shared memory
 * filesystem — these are the R1/R2 effects the privileged backend triggers.
 */
export class MemoryAcquisition implements AcquisitionPort {
  readonly catalog = new Map<string, MemoryCatalogEntry>();
  readonly #fs: MemoryFilesystem;

  constructor(fs: MemoryFilesystem) {
    this.#fs = fs;
  }

  register(packageId: string, entry: MemoryCatalogEntry): void {
    this.catalog.set(packageId, entry);
  }

  async officialSources(): Promise<ReadonlyArray<{ name: string; url: string }>> {
    return [{ name: 'winget', url: 'https://cdn.winget.microsoft.com/cache' }];
  }

  async resolveExact(request: {
    packageId: string;
    version?: string;
  }): Promise<AcquisitionCandidate> {
    const entry = this.catalog.get(request.packageId);
    if (!entry) {
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `${request.packageId} is not in the official source`,
      );
    }
    if (request.version && request.version !== entry.version) {
      throw new AcquisitionError(
        'VERSION_UNAVAILABLE',
        `${request.packageId} has no ${request.version}`,
      );
    }
    return {
      providerId: providerIdFor(request.packageId),
      packageId: request.packageId,
      source: 'winget',
      official: true,
      version: entry.version,
      installerSha256: entry.installerSha256,
      publisher: entry.publisher,
      license: entry.license,
      signature: `authenticode:${entry.publisher}`,
    };
  }

  async predictScope(candidate: AcquisitionCandidate): Promise<readonly string[]> {
    const entry = this.#require(candidate.packageId);
    return [entry.installDir, ...(entry.cacheDir ? [entry.cacheDir] : [])];
  }

  async layoutOf(candidate: AcquisitionCandidate): Promise<ProviderInstallLayout> {
    const entry = this.#require(candidate.packageId);
    return {
      providerId: providerIdFor(candidate.packageId),
      version: entry.version,
      installDirs: [entry.installDir],
      cacheDirs: entry.cacheDir ? [entry.cacheDir] : [],
      configDirs: entry.configDir ? [entry.configDir] : [],
      executables: [`${entry.installDir}\\${entry.executableName}`],
    };
  }

  // ---- effects (privileged backend dispatch target) ----

  installByPlan(packageId: string, version: string): { ok: boolean; note: string } {
    const entry = this.#require(packageId);
    if (version !== entry.version) return { ok: false, note: `version ${version} unavailable` };
    const exe = `${entry.installDir}\\${entry.executableName}`;
    this.#fs.putTree([entry.installDir, ...(entry.cacheDir ? [entry.cacheDir] : [])], {
      [exe]: echoFor(entry),
    });
    return { ok: true, note: `installed ${packageId} ${version}` };
  }

  uninstallByPlan(packageId: string): { ok: boolean; note: string } {
    const entry = this.#require(packageId);
    this.#fs.removeTree(entry.installDir);
    if (entry.cacheDir) this.#fs.removeTree(entry.cacheDir);
    return { ok: true, note: `removed ${packageId}` };
  }

  #require(packageId: string): MemoryCatalogEntry {
    const entry = this.catalog.get(packageId);
    if (!entry) throw new AcquisitionError('PACKAGE_UNKNOWN', `${packageId} unknown`);
    return entry;
  }
}

export function providerIdFor(packageId: string): string {
  const stem = packageId.split('.').slice(-1)[0] ?? packageId;
  return `tool.${stem.toLowerCase()}`;
}

export function echoFor(entry: MemoryCatalogEntry): string {
  return `${entry.executableName.replace(/\.exe$/i, '')}-${entry.version}`;
}

// ---- registry ----

export function jitCapabilityDefinition(capabilityId: string): CapabilityDefinition {
  return {
    capabilityId,
    revision: 'r1',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    sideEffectClass: 'R2',
    allowedInterfaceClasses: ['I0', 'I1', 'I2'],
    verificationContract: {
      verifierId: 'verifier.jit-cli',
      verifierRevision: 'r1',
      checks: [{ checkId: 'provider-task-observable', required: true }],
    },
    requiredPolicyFacts: ['jit.trustedProvenance'],
  };
}

export function trustedProviderDefinition(
  packageId: string,
  entry: MemoryCatalogEntry,
): ProviderDefinition {
  return {
    providerId: providerIdFor(packageId),
    revision: 'r1',
    acquisition: {
      mechanism: 'WINGET',
      source: `winget:${packageId}`,
      official: true,
      version: entry.version,
      hash: entry.installerSha256,
      signature: `authenticode:${entry.publisher}`,
    },
    provenanceFacts: { publisher: entry.publisher, catalog: 'winget-official' },
    licenseFacts: { license: entry.license },
    supportedPlatforms: [{ os: 'WINDOWS', arch: 'X64' }],
    lifecycle: { supportedOperations: ['ACQUIRE', 'CONFIGURE', 'UNINSTALL'] },
    interfaces: [
      {
        interfaceId: 'cli',
        interfaceClass: 'I1',
        invocation: `${entry.executableName.replace(/\.exe$/i, '')} <args>`,
      },
    ],
  };
}

export function untrustedProviderDefinition(
  providerId: string,
  version: string,
): ProviderDefinition {
  return {
    providerId,
    revision: 'r1',
    acquisition: {
      mechanism: 'DIRECT_DOWNLOAD',
      source: 'https://downloads.example.net/sketchy-tool.zip',
      official: false,
      version,
    },
    provenanceFacts: { publisher: 'unknown' },
    licenseFacts: { license: 'unknown' },
    supportedPlatforms: [{ os: 'WINDOWS', arch: 'X64' }],
    lifecycle: { supportedOperations: ['ACQUIRE'] },
    interfaces: [{ interfaceId: 'cli', interfaceClass: 'I1', invocation: 'tool <args>' }],
  };
}

export function windowsFacts(): EnvironmentFacts {
  return {
    environmentId: 'local-windows-1',
    backendKind: 'LOCAL_WINDOWS',
    os: 'Windows 11 Pro 26300',
    arch: 'X64',
    observationRevision: 'obs-r1',
    runtimeCapabilities: ['winget', 'powershell'],
    privilegeMode: 'FILTERED_ADMIN',
    guiSession: true,
    filesystemCapabilities: ['ntfs-acl'],
    networkPolicy: 'POLICY_CONTROLLED',
    resources: { cpuCores: 8, memoryMb: 32768, freeDiskMb: 512_000 },
  };
}

export class MockRegistry implements RegistryReadModelPort {
  readonly #capabilities: CapabilityDefinition[];
  readonly #providers: ProviderDefinition[];
  readonly #bindings: ProviderCapabilityBinding[];
  readonly #envBindings: ProviderEnvironmentBinding[];
  readonly #facts: EnvironmentFacts;

  constructor(config: {
    capabilities?: CapabilityDefinition[];
    providers?: ProviderDefinition[];
    bindings?: ProviderCapabilityBinding[];
    envBindings?: ProviderEnvironmentBinding[];
    facts?: EnvironmentFacts;
  }) {
    this.#capabilities = config.capabilities ?? [];
    this.#providers = config.providers ?? [];
    this.#bindings = config.bindings ?? [];
    this.#envBindings = config.envBindings ?? [];
    this.#facts = config.facts ?? windowsFacts();
  }

  async listCapabilities(): Promise<CapabilityDefinition[]> {
    return this.#capabilities.map((entry) => ({ ...entry }));
  }

  async listProviders(): Promise<ProviderDefinition[]> {
    return this.#providers.map((entry) => ({ ...entry }));
  }

  async providerCapabilityBindings(capabilityId: string): Promise<ProviderCapabilityBinding[]> {
    return this.#bindings.filter((binding) => binding.capabilityId === capabilityId);
  }

  async providerEnvironmentBindings(providerId: string): Promise<ProviderEnvironmentBinding[]> {
    return this.#envBindings.filter((binding) => binding.providerBindingId.startsWith(providerId));
  }

  async observedFacts(): Promise<EnvironmentFacts> {
    return this.#facts;
  }
}

// ---- store ----

export class MemoryStore implements StorePort {
  readonly #applied = new Map<string, StoreApplicationReceipt>();
  readonly records = new Map<string, ShunStoreMutation>();

  async apply(effectId: string, mutation: ShunStoreMutation): Promise<StoreApplicationReceipt> {
    const existing = this.#applied.get(effectId);
    if (existing) return { ...existing, applied: false };
    const receipt: StoreApplicationReceipt = {
      effectId,
      applied: true,
      receiptRef: `store://${mutation.recordKind}/${mutation.recordId}@1`,
    };
    this.#applied.set(effectId, receipt);
    this.records.set(effectId, mutation);
    return receipt;
  }
}

// ---- approval ----

export class MockApproval implements ApprovalPort {
  readonly requests: ApprovalRequest[] = [];
  readonly #mode: 'approve' | 'deny';
  #counter = 0;

  constructor(mode: 'approve' | 'deny' = 'approve') {
    this.#mode = mode;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
    this.requests.push(request);
    this.#counter += 1;
    return {
      approvalId: `approval-${this.#counter}`,
      taskId: request.taskId,
      planHash: request.planHash,
      approved: this.#mode === 'approve',
      approvedBy: 'USER_APPROVAL',
      ...(this.#mode === 'deny' ? { reason: 'user declined the removal preview' } : {}),
    };
  }
}

// ---- environment backend (task execution) ----

export class MemoryTaskBackend implements EnvironmentBackend {
  readonly #fs: MemoryFilesystem;
  readonly #acquisition: MemoryAcquisition;
  readonly #facts: EnvironmentFacts;
  readonly receipts: ExecutionReceipt[] = [];
  #prepared = 0;

  constructor(fs: MemoryFilesystem, acquisition: MemoryAcquisition, facts?: EnvironmentFacts) {
    this.#fs = fs;
    this.#acquisition = acquisition;
    this.#facts = facts ?? windowsFacts();
  }

  async observe(): Promise<EnvironmentFacts> {
    return this.#facts;
  }

  async canPrepare(requirements: EnvironmentRequirements): Promise<Feasibility> {
    const reasons: string[] = [];
    if (requirements.backendKind !== this.#facts.backendKind) {
      reasons.push('BACKEND_KIND_INELIGIBLE');
    }
    if (requirements.os && requirements.os !== 'WINDOWS') {
      reasons.push('PLATFORM_UNSUPPORTED');
    }
    return {
      feasible: reasons.length === 0,
      rejectionReasons: reasons as Feasibility['rejectionReasons'],
    };
  }

  async prepare(_binding: ProviderEnvironmentBinding): Promise<PreparedEnvironment> {
    this.#prepared += 1;
    return {
      preparedEnvironmentId: `prepared-${this.#prepared}`,
      environmentId: this.#facts.environmentId,
    };
  }

  async execute(action: AuthorizedAction): Promise<ExecutionReceipt> {
    const parameters = action.action.parameters as { executable?: unknown };
    const executable = typeof parameters.executable === 'string' ? parameters.executable : '';
    const startedAt = new Date().toISOString();
    if (!executable || !(await this.#fs.exists(executable))) {
      const receipt = ExecutionReceiptSchema.parse({
        actionId: action.actionId,
        environmentId: this.#facts.environmentId,
        providerId: 'unknown',
        providerVersion: 'unknown',
        startedAt,
        finishedAt: new Date().toISOString(),
        terminal: 'FAILED',
        outputRefs: [],
        sideEffectEvidence: {
          sideEffectClass: action.action.sideEffectClass,
          recoveryClassification: 'FAILED_BEFORE_EFFECT',
          postStateVerified: true,
        },
      });
      this.receipts.push(receipt);
      return receipt;
    }
    const body = await this.#fs.readText(executable);
    const stdoutPath = `C:\\work\\jit-task-out\\stdout.txt`;
    this.#fs.putTree(['C:\\work\\jit-task-out'], { [stdoutPath]: body });
    const receipt = ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#facts.environmentId,
      providerId: 'unknown',
      providerVersion: 'unknown',
      startedAt,
      finishedAt: new Date().toISOString(),
      terminal: 'SUCCEEDED',
      exitCode: 0,
      outputRefs: [stdoutPath],
      stdoutRef: stdoutPath,
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        recoveryClassification: 'COMPLETED_VERIFIED',
        postStateVerified: true,
      },
    });
    this.receipts.push(receipt);
    return receipt;
  }

  async cancel(_actionId: string): Promise<void> {
    /* cooperative cancellation is a no-op for in-memory tasks */
  }

  async cleanup(_prepared: PreparedEnvironment): Promise<void> {
    /* nothing to clean in memory */
  }

  /** Which catalog provider does this executable belong to (for provider echo output). */
  echoOf(executablePath: string): string {
    for (const [packageId, entry] of this.#acquisition.catalog) {
      if (
        `${entry.installDir}\\${entry.executableName}`.toLowerCase() ===
        executablePath.toLowerCase()
      ) {
        return `${packageId.split('.').slice(-1)[0]?.toLowerCase()}-${entry.version}`;
      }
    }
    return '';
  }
}

// ---- harness assembly ----

export interface JitHarness {
  readonly deps: JitLifecycleDeps;
  readonly authority: LocalAuthority;
  readonly ledger: MemoryPlanLedger;
  readonly acquisition: MemoryAcquisition;
  readonly approval: MockApproval;
  readonly fs: MemoryFilesystem;
  readonly store: MemoryStore;
  readonly journals: Map<string, MemoryJournal>;
  readonly backend: LocalPrivilegedBackend;
  readonly taskBackend: MemoryTaskBackend;
  readonly verifier: PatternVerifier;
  readonly traces: { at: string; kind: string; detail?: string }[];
  readonly clock: () => string;
}

export interface HarnessOptions {
  readonly fs?: MemoryFilesystem;
  readonly approvalMode?: 'approve' | 'deny';
  readonly backendFaults?: readonly PrivilegedFault[];
  readonly protectedRoots?: readonly string[];
  readonly durableJitPolicy?: JitLifecycleDeps['policy']['durableJitPolicy'];
  readonly taskOutputDir?: string;
}

function buildBackend(
  authority: LocalAuthority,
  journals: (actionId: string) => JournalPort,
  faults: readonly PrivilegedFault[] | undefined,
  acquisition: MemoryAcquisition,
  clock: () => string,
): LocalPrivilegedBackend {
  return new LocalPrivilegedBackend({
    authority,
    clock,
    journals,
    environmentId: 'local-windows-1',
    providerId: (action) =>
      providerIdFor(
        String((action.action.parameters as Record<string, unknown>).packageId ?? 'unknown'),
      ),
    providerVersion: (action) =>
      String((action.action.parameters as Record<string, unknown>).version ?? 'unknown'),
    perform: async (action) => {
      const parameters = action.parameters as { packageId?: unknown; version?: unknown };
      const packageId = String(parameters.packageId ?? '');
      if (action.op === 'software.install') {
        const outcome = acquisition.installByPlan(packageId, String(parameters.version ?? ''));
        return { ok: outcome.ok, note: outcome.note };
      }
      if (action.op === 'software.uninstall') {
        const outcome = acquisition.uninstallByPlan(packageId);
        return { ok: outcome.ok, note: outcome.note };
      }
      return { ok: false, note: `unsupported op ${action.op}` };
    },
    faults,
  });
}

export function buildHarness(options: HarnessOptions = {}): JitHarness {
  const fs = options.fs ?? new MemoryFilesystem();
  const acquisition = new MemoryAcquisition(fs);
  const ledger = new MemoryPlanLedger();
  let tick = 0;
  const clock = (): string =>
    new Date(Date.parse('2026-10-10T08:00:00.000Z') + tick++ * 1000).toISOString();
  const authority = new LocalAuthority({ now: clock, ledger });
  const journals = new Map<string, MemoryJournal>();
  const journalFor = (actionId: string): JournalPort => {
    const existing = journals.get(actionId);
    if (existing) return existing;
    const journal = new MemoryJournal();
    journals.set(actionId, journal);
    return journal;
  };
  const taskBackend = new MemoryTaskBackend(fs, acquisition);
  const backend = buildBackend(authority, journalFor, options.backendFaults, acquisition, clock);
  const approval = new MockApproval(options.approvalMode ?? 'approve');
  const store = new MemoryStore();
  const verifier = new PatternVerifier();
  const traces: { at: string; kind: string; detail?: string }[] = [];
  const taskOutputDir = options.taskOutputDir ?? 'C:\\work\\jit-task-out';

  const deps: JitLifecycleDeps = {
    registry: new MockRegistry({}),
    acquisition,
    privileged: backend,
    environment: taskBackend,
    authorization: authority,
    approval,
    verifier,
    store,
    planLedger: ledger,
    journals: journalFor,
    fs,
    clock,
    policy: {
      rankingPolicyRevision: 'rank-v1',
      machineScopeInstall: false,
      protectedRoots: options.protectedRoots ?? ['C:\\Users\\dev\\Documents'],
      taskOutputDir,
      ...(options.durableJitPolicy ? { durableJitPolicy: options.durableJitPolicy } : {}),
    },
    trace: (event) => traces.push(event),
  };
  return {
    deps,
    authority,
    ledger,
    acquisition,
    approval,
    fs,
    store,
    journals,
    backend,
    taskBackend,
    verifier,
    traces,
    clock,
  };
}

export { MemoryJournal };
