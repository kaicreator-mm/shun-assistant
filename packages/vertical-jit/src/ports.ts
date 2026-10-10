// Typed seams owned by the Loop B vertical (T06). Contracts ports
// (StorePort, AuthorizationPort, ApprovalPort, ExecutionBackend,
// EnvironmentBackend, VerifierPort, RegistryReadModelPort) carry the shared
// authority chain; the seams here are the provider-acquisition and host-
// observation surfaces the vertical needs on top of them.
//
// None of these ports can execute a deletion: destructive effects only ever
// flow through the privileged ExecutionBackend as AuthorizedActions.
import type { ActionPlan } from '@shun/contracts';

/**
 * Host filesystem observation. Read-only by construction: there is no delete
 * or write method. The privileged backend performs effects; the orchestrator
 * only observes post-state.
 */
export interface FilesystemPort {
  exists(path: string): Promise<boolean>;
  isDirectory(path: string): Promise<boolean>;
  listChildren(path: string): Promise<string[]>;
  sha256File(path: string): Promise<string>;
  readText(path: string): Promise<string>;
  writeText(path: string, contents: string): Promise<void>;
  sizeBytes(path: string): Promise<number>;
}

/** One spawned process outcome. Exit codes are transport facts — never recovery truth. */
export interface ProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
}

export interface ProcessRunSpec {
  readonly argv: readonly string[];
  readonly cwd?: string;
  readonly timeoutMs?: number;
  /** Environment additions; secrets pass by reference only at plan level. */
  readonly env?: Readonly<Record<string, string>>;
}

/** Process seam. Real impl spawns without a shell; tests script outcomes. */
export interface ProcessPort {
  run(spec: ProcessRunSpec): Promise<ProcessResult>;
}

/** Typed failure reasons for acquisition (map to frozen C-002 codes upstream). */
export type AcquisitionFailureKind =
  | 'OFFICIAL_SOURCE_UNAVAILABLE'
  | 'PACKAGE_UNKNOWN'
  | 'VERSION_UNAVAILABLE'
  | 'ELEVATION_REQUIRED'
  | 'HASH_MISMATCH'
  | 'INSTALL_FAILED'
  | 'UNINSTALL_FAILED';

export class AcquisitionError extends Error {
  readonly kind: AcquisitionFailureKind;
  readonly exitCode?: number;
  readonly raw?: string;

  constructor(kind: AcquisitionFailureKind, detail: string, exitCode?: number, raw?: string) {
    super(`[${kind}] ${detail}`);
    this.name = 'AcquisitionError';
    this.kind = kind;
    this.exitCode = exitCode;
    this.raw = raw;
  }
}

/**
 * Trusted acquisition candidate resolved from an official source BEFORE any
 * install. `official` is decided by the adapter against the official-source
 * allowlist — callers must not be able to assert it.
 */
export interface AcquisitionCandidate {
  readonly providerId: string;
  readonly packageId: string;
  readonly source: string;
  readonly official: boolean;
  readonly version: string;
  readonly installerSha256?: string;
  readonly publisher?: string;
  readonly license?: string;
  readonly signature?: string;
}

/**
 * Where the provider landed and which roots it owns — the input to residue
 * classification and to install/uninstall filesystem scopes. Roots are
 * exhaustive declarations: anything outside them is not the provider's.
 */
export interface ProviderInstallLayout {
  readonly providerId: string;
  readonly version: string;
  readonly installDirs: readonly string[];
  readonly cacheDirs: readonly string[];
  readonly configDirs: readonly string[];
  /** Executable entry points used by the task step (typed argv targets). */
  readonly executables: readonly string[];
}

export interface AcquisitionPort {
  /**
   * The acquisition sources the adapter is willing to use, with their
   * official endpoints. A source whose endpoint is not on the official
   * allowlist must never appear here.
   */
  officialSources(): Promise<ReadonlyArray<{ name: string; url: string }>>;
  /** Resolve the exact candidate from an official source. Unknown provenance must fail closed here. */
  resolveExact(request: { packageId: string; version?: string }): Promise<AcquisitionCandidate>;
  /**
   * Filesystem roots the install mechanism is expected to touch — declared
   * BEFORE install so the plan's filesystem scope exists prior to any side
   * effect (plan-first, L2 §9.1).
   */
  predictScope(candidate: AcquisitionCandidate, machineScope: boolean): Promise<readonly string[]>;
  /** Observed post-install (or post-removal) layout of the provider. */
  layoutOf(candidate: AcquisitionCandidate): Promise<ProviderInstallLayout>;
}

/**
 * Durable JIT removal policy (Product C-002 gate step 4): a pre-existing
 * durable policy may authorize removal of verified JIT providers after
 * successful task completion — but never deletion of user-created/unknown or
 * protected data, and never removal without verified task success.
 */
export interface JitDurablePolicy {
  readonly policyId: string;
  readonly revision: string;
  readonly jitRemoveAfterVerifiedUse: boolean;
  readonly forbidUserAssetDeletion: true;
}

/**
 * Trusted plan ledger (the ShunStore plan-record seam as seen by the
 * privileged substrate, L2 §9.3): the Action Controller persists every plan
 * BEFORE requesting a grant, and the privileged boundary validates
 * presentations against the ledger's copy — never against a caller-supplied
 * plan surface.
 */
export interface PlanLedgerPort {
  register(plan: ActionPlan): Promise<void>;
  byHash(planHash: string): Promise<ActionPlan | undefined>;
}
