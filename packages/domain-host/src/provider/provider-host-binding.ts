/**
 * R03C — trusted production install seam binding the Host-global Provider
 * first-use flow to the REAL CuratedProvider chain
 * (OWNER_SHUN_V030_R03C_SOURCE_IMPLEMENTATION_APPROVE, #280 comment 6584396368).
 *
 * Provider first use is operator-pinned and Host-global: it is bound to the
 * pinned curator roots, catalog descriptor and provider cache root — never to
 * a currently selected Guided Case. The K capability input carries ONLY a
 * Host-issued requestRef; the durable two-step request ledger
 * (provider-first-use-ledger.ts) owns PREPARED → APPROVED → RUNNING →
 * terminal/UNKNOWN transitions. USER-privilege providers run the unprivileged
 * activation path; an operator-pinned ELEVATED configuration is served only
 * through the existing privileged one-shot UAC backend
 * (effect-host-binding.ts) with the ONE pre-provisioned exact installer
 * action in the authority store — never a model-selected or caller-supplied
 * elevation, never whole-assistant elevation, never a native addon.
 */
import { join } from 'node:path';
import {
  type ActivationResult,
  type ActivationRunOutcome,
  BoundedSpawnProcess,
  CuratedProviderActivator,
  minimalWindowsSpawnEnvironment,
  type ResolvedInvocation,
  type RunEffectDecision,
} from '../../../provider-loader/src/activation.ts';
import { CuratedProviderStager } from '../../../provider-loader/src/staging.ts';
import { CuratedProviderVerifier } from '../../../vertical-jit/src/curated-provider.ts';
import {
  executeTrustedElevatedAction,
  type PrivilegedReceiptSummary,
  previewTrustedElevatedAction,
  type TrustedElevatedActionRef,
} from '../windows/effect-host-binding.ts';
import {
  ProviderFirstUseLedger,
  type ProviderFirstUsePreview,
  type ProviderFirstUseReceipt,
  type ProviderFirstUseRequestRecord,
  type ProviderPrivilegeScope,
} from './provider-first-use-ledger.ts';

/** The one durable, Case-free Host identity of the provider-global lane. */
const PROVIDER_GLOBAL_TASK_ID = 'provider-global';

export interface TrustedProviderBindingConfig {
  /** Operator-owned provider cache root (absolute); staging/active/ledger live under it. */
  readonly cacheRoot: string;
  /** Operator-pinned curator trust roots (production material, not test keys). */
  readonly roots: readonly { readonly keyId: string; readonly publicKeyPem: string }[];
  /** Operator-pinned provider scopes. */
  readonly scopes: readonly unknown[];
  /** The exact signed catalog descriptor admitted for first use. */
  readonly descriptor: unknown;
  /**
   * Legacy R03-INT pinned task identity. The Host-global request flow is
   * Case/task-free (requestRef-only K input, internal `provider-global`
   * identity); the field stays accepted for the existing R02 journey
   * compositions and is not consulted by the request flow.
   */
  readonly taskId?: string;
  /** Pinned revocation epoch the chain requires. */
  readonly revocationEpoch: number;
  /**
   * Operator-pinned declaration that this provider's installer requires
   * elevation: a reference to the ONE pre-provisioned `provider-global`
   * `windows.proc.exec` installer action in the existing authority store.
   * Present = ELEVATED (CLI artifacts only); absent = USER. Prepare refuses
   * every request unless the referenced action resolves with current
   * grant/plan/authority and a pre-existing ProgramPin check inside the
   * existing privileged backend.
   */
  readonly elevatedAction?: TrustedElevatedActionRef;
  /** Trusted-process seam override (tests); defaults to the real artifact fetch. */
  readonly fetchArtifact?: typeof fetch;
  /** Trusted-process seam override (tests); defaults to the real bounded spawn. */
  readonly process?: unknown;
  /**
   * Trusted-process seam override (tests); defaults to the real host facts.
   * The activation chain enforces the catalog's `windows-x64` platform pin,
   * so non-Windows qualification environments inject the pinned facts instead
   * of weakening the pin itself.
   */
  readonly hostFacts?: {
    readonly platform?: string;
    readonly architecture?: string;
    readonly nodeAbi?: string;
  };
}

/** Capability envelope returned to the K (terminal receipts only). */
export type ProviderCapabilityEnvelope =
  | {
      readonly phase: 'terminal';
      readonly externalRef: string;
      readonly outcome:
        | { readonly ok: true; readonly output: Record<string, unknown> }
        | {
            readonly ok: false;
            readonly error: { readonly code: string; readonly message: string };
          };
    }
  | { readonly phase: 'running'; readonly externalRef: string };

let installed:
  | {
      readonly activator: CuratedProviderActivator;
      readonly stager: CuratedProviderStager;
      readonly descriptor: unknown;
      readonly bindingId: string;
      readonly artifactSha256: string;
      readonly providerId: string;
      readonly catalogRevision: string;
      readonly cacheRoot: string;
      readonly privilegeScope: ProviderPrivilegeScope;
      readonly elevatedActionRef: TrustedElevatedActionRef | undefined;
      readonly ledger: ProviderFirstUseLedger;
    }
  | undefined;

export function installTrustedProviderBinding(config: TrustedProviderBindingConfig): void {
  if (installed !== undefined) throw new Error('PROVIDER_HOST_ALREADY_INSTALLED');
  const verifier = new CuratedProviderVerifier(config.roots as never, config.scopes as never);
  const proof = verifier.verify(config.descriptor);
  if (!proof.ok) throw new Error(`PROVIDER_HOST_DESCRIPTOR_UNTRUSTED:${proof.code}`);
  const artifact = proof.artifact;
  // The privilege scope is operator-pinned host configuration, gated on the
  // ONE pre-provisioned `provider-global` installer action in the existing
  // authority store: prepare() refuses every request unless that exact
  // action resolves with current grant/plan/authority. No model- or
  // caller-selected privilege exists; a native addon is never elevated.
  const privilegeScope: ProviderPrivilegeScope =
    config.elevatedAction !== undefined ? 'ELEVATED' : 'USER';
  let elevatedActionRef: TrustedElevatedActionRef | undefined;
  if (privilegeScope === 'ELEVATED') {
    if (artifact.artifactKind !== 'CLI') {
      throw new Error('PROVIDER_HOST_ELEVATION_CLI_ONLY');
    }
    elevatedActionRef = config.elevatedAction;
  }
  const stager = new CuratedProviderStager({
    cacheRoot: config.cacheRoot,
    verifier,
    isOffline: () => false,
    ...(config.fetchArtifact !== undefined ? { fetchArtifact: config.fetchArtifact } : {}),
  });
  const activeRoot = join(config.cacheRoot, 'active', artifact.bindingId, artifact.artifactSha256);
  const under = (value: string, root: string): boolean =>
    value.toLowerCase().startsWith(root.toLowerCase());
  const authorizeRunEffect = (invocation: ResolvedInvocation): Promise<RunEffectDecision> =>
    Promise.resolve(
      invocation.taskId === PROVIDER_GLOBAL_TASK_ID &&
        invocation.bindingId === artifact.bindingId &&
        invocation.artifactSha256 === artifact.artifactSha256 &&
        under(invocation.executablePath, join(activeRoot, 'exec')) &&
        invocation.writeRoots.every((root) => under(root, join(activeRoot, 'sandbox')))
        ? { ok: true, leaseId: `lease-${PROVIDER_GLOBAL_TASK_ID}` }
        : { ok: false, code: 'EFFECT_NOT_AUTHORIZED' },
    );
  const activator = new CuratedProviderActivator({
    verifier,
    stager,
    cacheRoot: config.cacheRoot,
    getAuthorizedCurrentness: () => ({
      kind: 'CURRENT' as const,
      taskId: PROVIDER_GLOBAL_TASK_ID,
      providerId: artifact.providerId,
      bindingId: artifact.bindingId,
      catalogRevision: artifact.catalogRevision,
      artifactSha256: artifact.artifactSha256,
      revocationEpoch: config.revocationEpoch,
      capability: 'PREPARE_PROVIDER' as const,
    }),
    authorizeRunEffect,
    requiredRevocationEpoch: () => config.revocationEpoch,
    hostPlatform: () => config.hostFacts?.platform ?? process.platform,
    hostArchitecture: () => config.hostFacts?.architecture ?? process.arch,
    hostNodeAbi: () => config.hostFacts?.nodeAbi ?? process.versions.modules,
    hostNativeChildRuntime: () => process.execPath,
    hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
    process:
      config.process !== undefined
        ? (config.process as never)
        : (new BoundedSpawnProcess() as never),
  });
  installed = {
    activator,
    stager,
    descriptor: config.descriptor,
    bindingId: artifact.bindingId,
    artifactSha256: artifact.artifactSha256,
    providerId: artifact.providerId,
    catalogRevision: artifact.catalogRevision,
    cacheRoot: config.cacheRoot,
    privilegeScope,
    elevatedActionRef,
    ledger: new ProviderFirstUseLedger(
      join(config.cacheRoot, 'provider-first-use-requests.sqlite'),
    ),
  };
}

/**
 * Sanitized terminal envelope: provider-controlled stdout/stderr are NEVER
 * copied into the returned capability output — only Host-verified identity
 * and bounded execution facts survive.
 */
function envelopeFrom(result: ActivationResult, externalRef: string): ProviderCapabilityEnvelope {
  if (result.ok) {
    return {
      phase: 'terminal',
      externalRef,
      outcome: {
        ok: true,
        output: {
          state: result.state,
          bindingId: result.bindingId,
          digest: result.digest,
          exitCode: result.exitCode,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
        },
      },
    };
  }
  if (result.code === 'ACTIVATION_INTERRUPTED') {
    // Ambiguous execution boundary: never close the K turn optimistically.
    return { phase: 'running', externalRef };
  }
  return {
    phase: 'terminal',
    externalRef,
    outcome: {
      ok: false,
      error: { code: result.code, message: 'trusted Provider Host refused the first use' },
    },
  };
}

const VERSION_TOKEN = /^\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][0-9A-Za-z][0-9A-Za-z._-]{0,31})?$/;
const CANARY_MARKER = 'SHUN-PROVIDER-FIRST-USE';

/**
 * Strict version-token parser over provider stdout: the last whitespace
 * token of the FIRST line, retained only when it is exactly version-shaped.
 * Any other stdout (credentials, paths, free text) yields parsed=false and
 * no text is retained at all.
 */
function parseVersionToken(stdout: string): {
  readonly token: string | undefined;
  readonly parsed: boolean;
} {
  const firstLine = stdout.split(/\r?\n/, 1)[0] ?? '';
  const candidate = firstLine.trim().split(/\s+/).pop() ?? '';
  if (VERSION_TOKEN.test(candidate) && candidate.length <= 64) {
    return { token: candidate, parsed: true };
  }
  return { token: undefined, parsed: false };
}

/** Canary reduction to a closed enum: match semantics of the search exit code. */
function canaryResultFrom(result: ActivationRunOutcome): 'MATCHED' | 'NOT_MATCHED' | 'UNCLEAR' {
  if (result.exitCode === 0) {
    return result.stdout.includes(CANARY_MARKER) ? 'MATCHED' : 'NOT_MATCHED';
  }
  if (result.exitCode === 1) return 'NOT_MATCHED';
  return 'UNCLEAR';
}

/** Closed durable receipt for the ELEVATED leg from the projected summary. */
function elevatedReceipt(
  outcome: 'EXECUTED' | 'REFUSED' | 'UNKNOWN',
  code: string,
  summary: PrivilegedReceiptSummary,
): ProviderFirstUseReceipt {
  return {
    outcome,
    code,
    elevatedTerminal: summary.terminal,
    ...(summary.exitCode !== undefined ? { exitCode: summary.exitCode } : {}),
    ...(summary.timedOut !== undefined ? { timedOut: summary.timedOut } : {}),
    ...(summary.durationMs !== undefined ? { durationMs: summary.durationMs } : {}),
  };
}

function refusalEnvelope(externalRef: string, code: string): ProviderCapabilityEnvelope {
  return {
    phase: 'terminal',
    externalRef,
    outcome: {
      ok: false,
      error: { code, message: 'trusted Provider Host refused the first-use request' },
    },
  };
}

function previewFromPinnedArtifact(
  privilegeScope: ProviderPrivilegeScope,
): Omit<ProviderFirstUsePreview, 'elevatedAction'> | undefined {
  if (installed === undefined) return undefined;
  return {
    providerId: installed.providerId,
    bindingId: installed.bindingId,
    version: installed.catalogRevision,
    artifactSha256: installed.artifactSha256,
    publisherKeyId: `binding:${installed.bindingId}`,
    privilegeScope,
    reason:
      privilegeScope === 'ELEVATED'
        ? 'Operator-pinned provider installer requires elevation before first use'
        : 'Operator-pinned provider first use (unprivileged)',
    expectedChanges:
      privilegeScope === 'ELEVATED'
        ? ['install pinned provider artifacts', 'register provider binding']
        : ['stage verified provider artifacts under the operator cache root'],
  };
}

/**
 * Host surface, step 1: prepare a Host-global first-use request from the
 * PINNED provider identity only. No Guided Case, task, model or caller
 * identity is consulted or stored. The pinned verified artifact is staged
 * into the operator cache root first, so a later confirmed run executes
 * exactly these verified bytes.
 */
export async function prepareProviderFirstUse(): Promise<
  | {
      readonly ok: true;
      readonly requestRef: string;
      readonly preview: ProviderFirstUsePreview;
      readonly expiresAtUnixMs: number;
    }
  | {
      readonly ok: false;
      readonly code: string;
    }
> {
  if (installed === undefined) return { ok: false, code: 'PROVIDER_HOST_NOT_INSTALLED' };
  const staged = await installed.stager.stage(installed.descriptor);
  if (!staged.ok) return { ok: false, code: `PROVIDER_STAGE_FAILED:${staged.code}` };
  const base = previewFromPinnedArtifact(installed.privilegeScope);
  if (base === undefined) return { ok: false, code: 'PROVIDER_HOST_NOT_INSTALLED' };
  let preview: ProviderFirstUsePreview = base;
  if (installed.privilegeScope === 'ELEVATED') {
    if (installed.elevatedActionRef === undefined) {
      return { ok: false, code: 'PROVIDER_HOST_ELEVATED_ACTION_REQUIRED' };
    }
    const elevated = previewTrustedElevatedAction(installed.elevatedActionRef);
    if (elevated === undefined) {
      return { ok: false, code: 'PROVIDER_ELEVATION_PREVIEW_UNAVAILABLE' };
    }
    preview = {
      ...base,
      elevatedAction: {
        program: elevated.program,
        args: [...elevated.args],
        sideEffectClass: elevated.sideEffectClass,
        requiredPrivilege: 'ELEVATED',
      },
    };
  }
  const transition = installed.ledger.prepare(preview);
  if (!transition.ok) return { ok: false, code: transition.code };
  return {
    ok: true,
    requestRef: transition.record.requestRef,
    preview: transition.record.preview,
    expiresAtUnixMs: transition.record.expiresAtUnixMs,
  };
}

/**
 * Host surface, step 2: the explicit human confirmation consumes
 * PREPARED → APPROVED exactly once.
 */
export function confirmProviderFirstUse(requestRef: string):
  | { readonly ok: true; readonly record: ProviderFirstUseRequestRecord }
  | {
      readonly ok: false;
      readonly code: string;
    } {
  if (installed === undefined) return { ok: false, code: 'PROVIDER_HOST_NOT_INSTALLED' };
  const transition = installed.ledger.confirm(requestRef);
  return transition.ok
    ? { ok: true, record: transition.record }
    : { ok: false, code: transition.code };
}

/** Durable request read-back (operator UI/evidence only). */
export function readProviderFirstUseRequest(
  requestRef: string,
): ProviderFirstUseRequestRecord | undefined {
  if (installed === undefined) return undefined;
  return installed.ledger.read(requestRef);
}

/**
 * K→C callback: the pinned provider's genuine first use. The payload carries
 * ONLY the Host-issued requestRef — no caller-supplied taskId, provider path,
 * executable, args, grant, privilege or Case reference is accepted. The
 * APPROVED→RUNNING transition happens exactly once before any execution.
 */
export async function providerFirstUse(
  payload: unknown,
  _dispatchContext: unknown,
): Promise<ProviderCapabilityEnvelope> {
  if (installed === undefined) throw new Error('PROVIDER_HOST_NOT_INSTALLED');
  if (
    typeof payload !== 'object' ||
    payload === null ||
    Array.isArray(payload) ||
    Object.keys(payload).sort().join('|') !== 'requestRef' ||
    typeof (payload as { requestRef: unknown }).requestRef !== 'string'
  ) {
    return refusalEnvelope('provider-first-use', 'PROVIDER_INPUT_REFUSED');
  }
  const requestRef = (payload as { requestRef: string }).requestRef;
  const begun = installed.ledger.begin(requestRef);
  if (!begun.ok) {
    // Wrong/expired/replayed/unknown requestRef refuses before any provider
    // activation or UAC path is touched.
    return refusalEnvelope(requestRef, begun.code);
  }
  if (installed.privilegeScope === 'ELEVATED') {
    if (installed.elevatedActionRef === undefined) {
      installed.ledger.finish(requestRef, 'REFUSED', {
        outcome: 'REFUSED',
        code: 'PROVIDER_HOST_ELEVATION_ACTION_REQUIRED',
      });
      return refusalEnvelope(requestRef, 'PROVIDER_HOST_ELEVATION_ACTION_REQUIRED');
    }
    const elevated = await executeTrustedElevatedAction(installed.elevatedActionRef);
    if (elevated.status === 'COMPLETED') {
      installed.ledger.finish(
        requestRef,
        'COMPLETED',
        elevatedReceipt('EXECUTED', 'PROVIDER_ELEVATION_COMPLETED', elevated.receipt),
      );
    } else if (elevated.status === 'REFUSED') {
      installed.ledger.finish(
        requestRef,
        'REFUSED',
        elevatedReceipt('REFUSED', elevated.code, elevated.receipt),
      );
      return refusalEnvelope(requestRef, elevated.code);
    } else {
      installed.ledger.finish(
        requestRef,
        'UNKNOWN',
        elevatedReceipt('UNKNOWN', elevated.code, elevated.receipt),
      );
      return {
        phase: 'running',
        externalRef: requestRef,
      };
    }
  }
  const probe = await installed.activator.runCli({
    taskId: PROVIDER_GLOBAL_TASK_ID,
    descriptor: installed.descriptor,
    run: { kind: 'VERSION_PROBE' },
  });
  if (!probe.ok) {
    const probeEnvelope = envelopeFrom(probe, requestRef);
    recordActivationOutcome(requestRef, probeEnvelope);
    return probeEnvelope;
  }
  const canary = await installed.activator.runCli({
    taskId: PROVIDER_GLOBAL_TASK_ID,
    descriptor: installed.descriptor,
    run: { kind: 'FILE_SEARCH', pattern: 'SHUN-PROVIDER-FIRST-USE', operands: ['canary.txt'] },
    sandboxFiles: [
      {
        name: 'canary.txt',
        bytes: new TextEncoder().encode('noise\nSHUN-PROVIDER-FIRST-USE matched\n'),
      },
    ],
  });
  if (!canary.ok) {
    const canaryEnvelope = envelopeFrom(canary, requestRef);
    recordActivationOutcome(requestRef, canaryEnvelope);
    return canaryEnvelope;
  }
  // One terminal receipt carrying BOTH real executions as closed facts: the
  // strictly parsed version token (or parsed=false with no text retained)
  // and the enum canary result. Raw provider stdout/stderr are neither
  // returned to the K nor persisted.
  const version = parseVersionToken(probe.stdout);
  const receipt: ProviderFirstUseReceipt = {
    outcome: 'EXECUTED',
    code: 'PROVIDER_FIRST_USE_EXECUTED',
    bindingId: probe.bindingId,
    artifactSha256: installed.artifactSha256,
    ...(version.token !== undefined ? { probeVersion: version.token } : {}),
    probeVersionParsed: version.parsed,
    canaryResult: canaryResultFrom(canary),
    exitCode: canary.exitCode,
    timedOut: canary.timedOut,
    durationMs: probe.durationMs + canary.durationMs,
  };
  installed.ledger.finish(requestRef, 'COMPLETED', receipt);
  return {
    phase: 'terminal',
    externalRef: requestRef,
    outcome: { ok: true, output: receipt },
  };
}

function recordActivationOutcome(requestRef: string, envelope: ProviderCapabilityEnvelope): void {
  if (installed === undefined) return;
  if (envelope.phase === 'running') {
    // Interrupted execution: an uncertain boundary — never retried blindly.
    installed.ledger.finish(requestRef, 'UNKNOWN', {
      outcome: 'UNKNOWN',
      code: 'ACTIVATION_INTERRUPTED',
    });
    return;
  }
  if (!envelope.outcome.ok) {
    installed.ledger.finish(requestRef, 'REFUSED', {
      outcome: 'REFUSED',
      code: envelope.outcome.error.code,
    });
  }
}

/**
 * Graceful-shutdown lifecycle: close the durable ledger and drop the
 * singleton. Also lets a fresh trusted-process composition re-install.
 */
export function closeTrustedProviderBinding(): void {
  if (installed === undefined) return;
  installed.ledger.close();
  installed = undefined;
}

/** Trusted-process evidence accessor. */
export function trustedProviderBindingStatus(): Readonly<{
  installed: boolean;
  bindingId: string | undefined;
  artifactSha256: string | undefined;
  privilegeScope: ProviderPrivilegeScope | undefined;
}> {
  return installed === undefined
    ? {
        installed: false,
        bindingId: undefined,
        artifactSha256: undefined,
        privilegeScope: undefined,
      }
    : {
        installed: true,
        bindingId: installed.bindingId,
        artifactSha256: installed.artifactSha256,
        privilegeScope: installed.privilegeScope,
      };
}
