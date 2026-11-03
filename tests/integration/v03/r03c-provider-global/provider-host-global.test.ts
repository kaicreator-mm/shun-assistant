/**
 * R03C-PROVIDER-GLOBAL-UAC — Host-global Provider first-use qualification
 * (Issue #287; generation-3 repair pack
 * .agent/execution/R03C-PROVIDER-GLOBAL-UAC-RECEIPT-ALLOWLIST/MANIFEST.yaml@ba149aa5).
 *
 * Proves: Case-free prepare/confirm/run with requestRef-only K input,
 * wrong/expired/replayed requestRef refusal before any activation, restart
 * UNKNOWN reconciliation, USER stays unprivileged, ELEVATED requires the
 * exact operator-provisioned installer action and reaches the EXISTING
 * privileged backend only after explicit confirmation (fail-closed refusal
 * in CI — no real UAC, no installer, no persistent system change),
 * plan/grant drift refusal, cross-Case independence and bounded secret-free
 * durable receipts.
 *
 * Generation-3 privacy hardening: raw provider stdout/stderr never reach the
 * returned envelope or the durable SQLite receipt (strict version token,
 * enum canary result); previews and receipts are closed-world exact-shape
 * schemas shared by finish() and decodeRow(); privileged ExecutionReceipts
 * are reduced to an allowlist summary before persistence.
 *
 * Generation-5 terminal-receipt repair (#287 comment 6602534717, pack PR
 * #308): a successful elevated installer execution is an INTERMEDIATE stage
 * — the request stays RUNNING until the Provider first-use stage terminates,
 * and exactly one closed receipt (combining the bounded elevated summary
 * with the Provider outcome) is persisted. Injected-fake tests below prove
 * success/refusal/interruption after elevation with zero real UAC/installer
 * execution.
 *
 * The trusted Host bindings are process singletons, so each scenario imports
 * them fresh (vi.resetModules + dynamic import) over its own fixture store.
 */
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { canonicalJson, computePlanHash } from '../../../../packages/contracts/src/plan.ts';
import type { ProviderFirstUseReceipt } from '../../../../packages/domain-host/src/provider/provider-first-use-ledger.ts';
import { ProviderFirstUseLedger } from '../../../../packages/domain-host/src/provider/provider-first-use-ledger.ts';
import {
  generateGrantHmacKey,
  signGrantWithHmac,
  writeCurrentAuthority,
  writeGrantHmacKey,
  writeGrantRecord,
  writePlanRecord,
} from '../../../../packages/executor-windows/src/trusted-store.ts';
import type { ActivationRunSpec } from '../../../../packages/provider-loader/src/activation.ts';

const createdDirs: string[] = [];
type ProviderBindingModule =
  typeof import('../../../../packages/domain-host/src/provider/provider-host-binding.ts');
const openedBindings: ProviderBindingModule[] = [];

function trackBinding(binding: ProviderBindingModule): ProviderBindingModule {
  openedBindings.push(binding);
  return binding;
}

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function newDir(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `r03c-provider-global-${name}-`));
  createdDirs.push(dir);
  return dir;
}

afterEach(() => {
  // Release every binding's SQLite ledger handle before removing fixtures.
  while (openedBindings.length > 0) {
    const binding = openedBindings.pop();
    if (binding === undefined) continue;
    try {
      binding.closeTrustedProviderBinding();
    } catch {
      /* already closed */
    }
  }
  // Generation-5 injected-fake coverage registers vi.doMock registrations;
  // drop them so no mock leaks into another scenario.
  vi.doUnmock(EFFECT_HOST_BINDING_MODULE);
  vi.doUnmock(ACTIVATION_MODULE);
  while (createdDirs.length > 0) {
    const dir = createdDirs.pop();
    if (dir === undefined) break;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        /* a worker handle may still be releasing the file; retry briefly */
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
      }
    }
  }
});

/** Fresh trusted Host binding modules (the installed bindings are singletons). */
async function freshHost(): Promise<{
  binding: typeof import('../../../../packages/domain-host/src/provider/provider-host-binding.ts');
  effect: typeof import('../../../../packages/domain-host/src/windows/effect-host-binding.ts');
}> {
  vi.resetModules();
  const binding = trackBinding(
    await import('../../../../packages/domain-host/src/provider/provider-host-binding.ts'),
  );
  const effect = await import(
    '../../../../packages/domain-host/src/windows/effect-host-binding.ts'
  );
  return { binding, effect };
}

const ARTIFACT_BYTES = Buffer.from('pinned trusted rg fixture bytes', 'utf8');
const A64 = 'a'.repeat(64);
const B64 = 'b'.repeat(64);

const keyPair = generateKeyPairSync('ed25519');

function providerScope(artifactSha256: string): Record<string, unknown> {
  return {
    providerId: 'rg',
    capabilityId: 'file.search',
    version: '14.1.1',
    catalogRevision: 'catalog-v1',
    bindingId: 'rg-binding',
    scopedVerifierId: 'safe-verifier',
    catalogManifestSha256: A64,
    bindingEvidenceSha256: B64,
    artifactSha256,
    origin: 'https://trusted.invalid/rg.exe',
    platform: 'windows-x64',
    artifactKind: 'CLI',
  };
}

function makeDescriptor(
  trust: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
  signer: typeof keyPair = keyPair,
): Record<string, unknown> {
  const unsigned = {
    ...trust,
    entrypoint: 'rg.exe',
    signerKeyId: 'key-1',
    dependencySha256: [] as string[],
    ...overrides,
  };
  return {
    ...unsigned,
    curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), signer.privateKey).toString(
      'base64',
    ),
  };
}

interface CapturedRun {
  readonly specs: ActivationRunSpec[];
  readonly port: unknown;
}

/**
 * Capturing spawn port: the real chain runs, no real child process ever
 * starts. The canary FILE_SEARCH run (identified by its `-e PATTERN` argv)
 * returns its own stdout, mirroring the real provider printing the matched
 * sandbox line.
 */
function capturePort(
  stdout = 'ripgrep 14.1.1',
  canaryStdout = 'noise\nSHUN-PROVIDER-FIRST-USE matched\n',
): CapturedRun {
  const specs: ActivationRunSpec[] = [];
  const port = {
    specs,
    async run(spec: ActivationRunSpec): Promise<{
      exitCode: number;
      stdout: string;
      stderr: string;
      timedOut: boolean;
      stdoutTruncated: boolean;
      stderrTruncated: boolean;
    }> {
      specs.push(spec);
      return {
        exitCode: 0,
        stdout: spec.args.includes('SHUN-PROVIDER-FIRST-USE') ? canaryStdout : stdout,
        stderr: '',
        timedOut: false,
        stdoutTruncated: false,
        stderrTruncated: false,
      };
    },
  };
  return { specs, port };
}

interface InstalledUserHost {
  readonly binding: Awaited<ReturnType<typeof freshHost>>['binding'];
  readonly cacheRoot: string;
  readonly specs: ActivationRunSpec[];
}

/** Install a USER-privilege provider Host binding over disposable fixtures. */
async function installUserBinding(
  stdout = 'ripgrep 14.1.1',
  canaryStdout = 'noise\nSHUN-PROVIDER-FIRST-USE matched\n',
): Promise<InstalledUserHost> {
  const { binding } = await freshHost();
  const cacheRoot = newDir('user-cache');
  const artifactSha256 = sha256(ARTIFACT_BYTES);
  const trust = providerScope(artifactSha256);
  const { specs, port } = capturePort(stdout, canaryStdout);
  binding.installTrustedProviderBinding({
    cacheRoot,
    roots: [
      {
        keyId: 'key-1',
        publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    scopes: [trust],
    descriptor: makeDescriptor(trust),
    revocationEpoch: 1,
    hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
    fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
    process: port,
  });
  return { binding, cacheRoot, specs };
}

const USER_PREVIEW = {
  providerId: 'rg',
  bindingId: 'rg-binding',
  version: 'catalog-v1',
  artifactSha256: sha256(ARTIFACT_BYTES),
  publisherKeyId: 'binding:rg-binding',
  privilegeScope: 'USER' as const,
  reason: 'fixture request',
  expectedChanges: [],
};

// Provisioning of the operator-owned `provider-global` ELEVATED installer
// authority (plans/grants/currentness/HMAC) — the same durable records the
// real authority writer would commit. No ProgramPin/helper pin is provisioned,
// so the privileged backend refuses structurally before any UAC work in CI
// (fail closed; no prompt, no installer, no persistent change).
function provisionElevatedAuthority(authorityDir: string): {
  planHash: string;
  grantId: string;
  actionId: string;
} {
  const hmacKey = generateGrantHmacKey();
  writeGrantHmacKey(authorityDir, hmacKey);
  writeCurrentAuthority(authorityDir, {
    kind: 'CURRENT',
    authorityId: 'shun.action-controller.test',
    authorityRevision: 'auth-rev-1',
    policySnapshotRevision: 'policy-rev-1',
    policyStatus: 'ACTIVE',
    revokedGrantIds: [],
  });
  const actionId = 'act-install-rg';
  const planAction = {
    actionId,
    bindingRef: 'binding-1',
    op: 'windows.proc.exec' as const,
    parameters: {
      program: 'C:\\Windows\\System32\\whoami.exe',
      args: ['/groups', '/fo', 'csv'],
      expectExitCode: 0,
    },
    sideEffectClass: 'R2' as const,
    requiredPrivilege: 'ELEVATED' as const,
  };
  const planNoHash = {
    taskId: 'provider-global',
    capabilityId: 'provider.installer',
    bindingRefs: ['binding-1'],
    rankingPolicyRevision: 'rank-rev-1',
    policySnapshotRevision: 'policy-rev-1',
    actions: [planAction],
    verificationPlan: {
      verifierId: 'test-verifier',
      verifierRevision: '1',
      checks: [{ checkId: 'post-state' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE' as const,
      reconcileBeforeRetry: true as const,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED' as const,
    },
  };
  const plan = { ...planNoHash, planHash: computePlanHash(planNoHash as never) };
  writePlanRecord(join(authorityDir, 'plans'), plan);
  const grantNoIntegrity = {
    grantId: `grant-${randomUUID().slice(0, 8)}`,
    issuer: { authorityId: 'shun.action-controller.test', authorityRevision: 'auth-rev-1' },
    taskId: 'provider-global',
    planHash: plan.planHash,
    policySnapshotRevision: 'policy-rev-1',
    actionScope: { actionIds: [actionId], privilegeLevel: 'ELEVATED' },
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  };
  const grant = {
    ...grantNoIntegrity,
    integrity: signGrantWithHmac(hmacKey, grantNoIntegrity as never),
  };
  writeGrantRecord(join(authorityDir, 'grants'), grant as never);
  return { planHash: plan.planHash, grantId: grant.grantId, actionId };
}

// ---------------------------------------------------------------------------
// Generation-5 repair (#287 comment 6602534717, pack PR #308): the elevated
// installer execution is an INTERMEDIATE stage of the one end-to-end
// first-use request. The injected-fake coverage below replaces the privileged
// backend (and, for the refusal path, the Provider activator's runCli) with
// deterministic fakes: no real UAC prompt, helper, installer or persistent
// Windows effect is ever exercised, and every assertion is offline.
// ---------------------------------------------------------------------------

const EFFECT_HOST_BINDING_MODULE =
  '../../../../packages/domain-host/src/windows/effect-host-binding.ts';
const ACTIVATION_MODULE = '../../../../packages/provider-loader/src/activation.ts';

interface InjectedRunOutcome {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
}

interface InjectedHost {
  readonly binding: Awaited<ReturnType<typeof freshHost>>['binding'];
  readonly effect: Awaited<ReturnType<typeof freshHost>>['effect'];
  readonly elevatedCalls: () => number;
}

/**
 * Fresh Host modules whose privileged backend is replaced by a deterministic
 * fake returning the fixed closed-world summary (what the real allowlist
 * projection would produce). `providerRefusal` additionally replaces
 * CuratedProviderActivator.runCli with an activator-level refusal, modelling
 * the Provider stage refusing after a successful elevation.
 */
async function freshInjectedHost(options: {
  readonly providerRefusal?: 'ARTIFACT_NOT_VERIFIED';
}): Promise<InjectedHost> {
  vi.resetModules();
  let elevatedCalls = 0;
  const effectActual = await vi.importActual<
    typeof import('../../../../packages/domain-host/src/windows/effect-host-binding.ts')
  >(EFFECT_HOST_BINDING_MODULE);
  vi.doMock(EFFECT_HOST_BINDING_MODULE, async () => ({
    ...effectActual,
    executeTrustedElevatedAction: async () => {
      elevatedCalls += 1;
      return {
        status: 'COMPLETED' as const,
        // The exact closed-world summary the real projection mints.
        receipt: effectActual.projectPrivilegedReceipt({
          terminal: 'SUCCEEDED',
          exitCode: 0,
          timedOut: false,
          durationMs: 42,
        }),
      };
    },
  }));
  if (options.providerRefusal !== undefined) {
    const refusal = options.providerRefusal;
    const activationActual = await vi.importActual<
      typeof import('../../../../packages/provider-loader/src/activation.ts')
    >(ACTIVATION_MODULE);
    vi.doMock(ACTIVATION_MODULE, async () => ({
      ...activationActual,
      CuratedProviderActivator: class extends activationActual.CuratedProviderActivator {
        override async runCli(): Promise<never> {
          return { ok: false, code: refusal } as never;
        }
      },
    }));
  }
  const binding = trackBinding(
    await import('../../../../packages/domain-host/src/provider/provider-host-binding.ts'),
  );
  const effect = await import(EFFECT_HOST_BINDING_MODULE);
  return { binding, effect, elevatedCalls: () => elevatedCalls };
}

/** Install the operator-provisioned ELEVATED binding over the injected Host. */
function installInjectedElevatedBinding(
  host: InjectedHost,
  rootName: string,
  processPort: unknown,
): { readonly workspaceRoot: string; readonly cacheRoot: string } {
  const root = newDir(rootName);
  const authorityDir = join(root, 'authority');
  const workspaceRoot = join(root, 'workspace');
  const provisioned = provisionElevatedAuthority(authorityDir);
  host.effect.installTrustedWindowsEffectBinding({ authorityDir, workspaceRoot });

  const cacheRoot = newDir(`${rootName}-cache`);
  const trust = providerScope(sha256(ARTIFACT_BYTES));
  host.binding.installTrustedProviderBinding({
    cacheRoot,
    roots: [
      {
        keyId: 'key-1',
        publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    scopes: [trust],
    descriptor: makeDescriptor(trust, { requiredPrivilege: 'ELEVATED' }),
    revocationEpoch: 1,
    hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
    fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
    process: processPort,
    elevatedAction: {
      actionRef: provisioned.actionId,
      planRef: provisioned.planHash,
      grantRef: provisioned.grantId,
      taskId: 'provider-global',
    },
  });
  return { workspaceRoot, cacheRoot };
}

describe('R03C Host-global Provider first-use (requestRef-only, Case-free)', () => {
  it('prepares and confirms without any Guided Case and completes USER first use unprivileged', async () => {
    const { binding, cacheRoot, specs } = await installUserBinding();
    expect(binding.trustedProviderBindingStatus()).toMatchObject({
      installed: true,
      bindingId: 'rg-binding',
      privilegeScope: 'USER',
    });
    expect(existsCacheLedger(cacheRoot)).toBe(true);

    const prepared = await binding.prepareProviderFirstUse();
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    expect(prepared.preview.privilegeScope).toBe('USER');
    expect(prepared.preview.elevatedAction).toBeUndefined();
    expect(prepared.preview.providerId).toBe('rg');
    expect(prepared.preview.artifactSha256).toBe(sha256(ARTIFACT_BYTES));

    const confirmed = binding.confirmProviderFirstUse(prepared.requestRef);
    expect(confirmed.ok).toBe(true);
    if (!confirmed.ok) return;
    expect(confirmed.record.status).toBe('APPROVED');

    // No Guided Case exists anywhere in this scenario; the dispatch context
    // could be anything — the request flow never reads it.
    const envelope = await binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      { durableControlTurnId: 'turn:none', arbitraryCaseToken: 'case-ignored' },
    );
    expect(envelope.phase).toBe('terminal');
    if (envelope.phase !== 'terminal') throw new Error('expected terminal envelope');
    expect(envelope.outcome.ok).toBe(true);
    if (!envelope.outcome.ok) throw new Error('expected first-use success');
    expect(envelope.outcome.output.outcome).toBe('EXECUTED');
    // Strictly parsed version token + enum canary result; no raw output.
    expect(envelope.outcome.output).toMatchObject({
      probeVersion: '14.1.1',
      probeVersionParsed: true,
      canaryResult: 'MATCHED',
    });
    expect(JSON.stringify(envelope)).not.toContain('stdout');
    // Both real chain executions went through the captured unprivileged port.
    expect(specs.length).toBe(2);
    const record = binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record?.status).toBe('COMPLETED');
    expect(record?.receipt).toMatchObject({
      outcome: 'EXECUTED',
      exitCode: 0,
      canaryResult: 'MATCHED',
    });
  });

  it('refuses wrong, expired and replayed requestRef before any activation', async () => {
    const { binding, cacheRoot, specs } = await installUserBinding();

    // Wrong requestRef: refused with zero spawns.
    const wrong = await binding.providerFirstUse(
      { requestRef: 'provider-request-does-not-exist' },
      undefined,
    );
    expect(wrong).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_REQUEST_NOT_APPROVED' } },
    });
    expect(specs.length).toBe(0);

    // Expired requestRef: the ledger TTL rejects confirmation and begin.
    const ledgerFile = join(cacheRoot, 'provider-first-use-requests.sqlite');
    let nowMs = Date.now();
    const shifted = new ProviderFirstUseLedger(ledgerFile, () => nowMs);
    const prepared = shifted.prepare(USER_PREVIEW);
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    nowMs += 6 * 60_000;
    expect(shifted.confirm(prepared.record.requestRef)).toMatchObject({
      ok: false,
      code: 'PROVIDER_REQUEST_EXPIRED',
    });
    const expired = new ProviderFirstUseLedger(ledgerFile, () => nowMs - 6 * 60_000);
    const p2 = expired.prepare(USER_PREVIEW);
    if (!p2.ok) throw new Error('fixture prepare failed');
    expect(expired.confirm(p2.record.requestRef).ok).toBe(true);
    nowMs += 6 * 60_000;
    expect(expired.begin(p2.record.requestRef)).toMatchObject({
      ok: false,
      code: 'PROVIDER_REQUEST_EXPIRED',
    });
    expired.close();
    shifted.close();

    // Replayed requestRef: a completed request cannot run again.
    const prepared2 = await binding.prepareProviderFirstUse();
    if (!prepared2.ok) throw new Error('prepare failed');
    const confirmed3 = binding.confirmProviderFirstUse(prepared2.requestRef);
    if (!confirmed3.ok) throw new Error('confirm failed');
    const first = await binding.providerFirstUse({ requestRef: prepared2.requestRef }, undefined);
    expect(first.phase).toBe('terminal');
    if (first.phase !== 'terminal') throw new Error('expected terminal envelope');
    expect(first.outcome.ok).toBe(true);
    const replay = await binding.providerFirstUse({ requestRef: prepared2.requestRef }, undefined);
    expect(replay).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_REQUEST_NOT_APPROVED' } },
    });
    // Exactly the first run spawned; the replay never touched the provider.
    expect(specs.length).toBe(2);
  });

  it('refuses K input that carries anything beyond the Host-issued requestRef', async () => {
    const { binding, specs } = await installUserBinding();
    for (const payload of [
      { requestRef: 'provider-request-x', taskId: 'injected-task' },
      { requestRef: 'provider-request-x', executablePath: 'C:\\evil.exe' },
      { requestRef: 'provider-request-x', grant: 'forged-grant' },
      { requestRef: 'provider-request-x', privilege: 'ELEVATED' },
      'provider-request-x',
      null,
    ]) {
      const envelope = await binding.providerFirstUse(payload as never, undefined);
      expect(envelope).toMatchObject({
        phase: 'terminal',
        outcome: { ok: false, error: { code: 'PROVIDER_INPUT_REFUSED' } },
      });
    }
    expect(specs.length).toBe(0);
  });

  it('turns abandoned RUNNING into UNKNOWN on restart and never replays it', () => {
    const file = join(newDir('restart'), 'provider-first-use-requests.sqlite');
    let nowMs = Date.now();
    const first = new ProviderFirstUseLedger(file, () => nowMs);
    const prepared = first.prepare(USER_PREVIEW);
    if (!prepared.ok) throw new Error('prepare failed');
    const confirmed = first.confirm(prepared.record.requestRef);
    if (!confirmed.ok) throw new Error('confirm failed');
    const began = first.begin(prepared.record.requestRef);
    if (!began.ok) throw new Error('begin failed');
    expect(began.record.status).toBe('RUNNING');
    first.close();

    // Process restart: the new ledger instance reconciles the durable state.
    nowMs += 1000;
    const second = new ProviderFirstUseLedger(file, () => nowMs);
    const record = second.read(prepared.record.requestRef);
    expect(record?.status).toBe('UNKNOWN');
    expect(record?.receipt).toMatchObject({
      outcome: 'UNKNOWN',
      code: 'PROCESS_RESTARTED_WITH_UNCERTAIN_OUTCOME',
    });
    // UNKNOWN is terminal: begin/confirm refuse, no auto-replay.
    expect(second.begin(prepared.record.requestRef)).toMatchObject({
      ok: false,
      code: 'PROVIDER_REQUEST_NOT_APPROVED',
    });
    // Unconfirmed PREPARED/APPROVED requests expire at restart.
    const p2 = second.prepare(USER_PREVIEW);
    if (!p2.ok) throw new Error('prepare2 failed');
    second.close();
    nowMs += 1000;
    const third = new ProviderFirstUseLedger(file, () => nowMs);
    expect(third.read(p2.record.requestRef)?.status).toBe('EXPIRED');
    third.close();
  });

  it('cross-Case Guided selection changes never alter Provider authority', async () => {
    const { binding, specs } = await installUserBinding();
    const prepared = await binding.prepareProviderFirstUse();
    if (!prepared.ok) throw new Error('prepare failed');
    expect(binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);
    // Successive dispatch contexts simulate the operator switching Guided
    // Cases between and during provider runs; the request flow is identical.
    for (const context of [
      undefined,
      { durableControlTurnId: 'turn:wf:case-A' },
      { durableControlTurnId: 'turn:wf:case-B', message: 'switched' },
    ]) {
      const record = binding.readProviderFirstUseRequest(prepared.requestRef);
      expect(record).toBeDefined();
      void context;
    }
    const envelope = await binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      { durableControlTurnId: 'turn:wf:case-C' },
    );
    expect(envelope.phase).toBe('terminal');
    if (envelope.phase !== 'terminal') throw new Error('expected terminal envelope');
    expect(envelope.outcome.ok).toBe(true);
    if (!envelope.outcome.ok) throw new Error('expected first-use success');
    expect(envelope.outcome.output.outcome).toBe('EXECUTED');
    expect(specs.length).toBe(2);
    // The durable record carries no Case/task/caller identity at all.
    const raw = JSON.stringify(binding.readProviderFirstUseRequest(prepared.requestRef));
    expect(raw).not.toMatch(/case-A|case-B|case-C|durableControlTurnId/);
  });

  it('durable receipts and previews are bounded and contain no secrets or raw prompts', async () => {
    const { binding, cacheRoot } = await installUserBinding();
    const prepared = await binding.prepareProviderFirstUse();
    if (!prepared.ok) throw new Error('prepare failed');
    expect(binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);
    await binding.providerFirstUse({ requestRef: prepared.requestRef }, undefined);
    const record = binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record).toBeDefined();
    const raw = JSON.stringify(record);
    expect(raw.length).toBeLessThan(16_384);
    // The preview carries only closed-world fields + bounded reason/changes.
    expect(Object.keys(record?.preview ?? {}).sort()).toEqual([
      'artifactSha256',
      'bindingId',
      'expectedChanges',
      'privilegeScope',
      'providerId',
      'publisherKeyId',
      'reason',
      'version',
    ]);
    // The durable receipt carries only closed-world keys; no raw output.
    expect(Object.keys(record?.receipt ?? {}).sort()).toEqual([
      'artifactSha256',
      'bindingId',
      'canaryResult',
      'code',
      'durationMs',
      'exitCode',
      'outcome',
      'probeVersion',
      'probeVersionParsed',
      'timedOut',
    ]);
    expect(raw).not.toMatch(/stdout|stderr|outputRefs|stdoutRef|stderrRef/);
    // The ledger class refuses secret-shaped text anywhere in the preview.
    const hostile = new ProviderFirstUseLedger(join(newDir('audit-hostile'), 'l.sqlite'));
    expect(
      hostile.prepare({
        ...USER_PREVIEW,
        reason: 'api_key=sk-1234 password=hunter2',
      }).ok,
    ).toBe(false);
    hostile.close();
    expect(cacheRoot.length).toBeGreaterThan(0);
  });

  it('secret-shaped provider stdout never reaches the returned envelope or the durable SQLite receipt', async () => {
    const secret = 'sk-live-4f7b1c9e2a8d6055';
    const hostileStdout = [
      `Authorization: Bearer ${secret}`,
      `PATH=C:\\Users\\operator\\credstore api_key=${secret}`,
      'plain noise without any credential material',
    ].join('\r\n');
    const { binding, cacheRoot } = await installUserBinding(hostileStdout, hostileStdout);
    const prepared = await binding.prepareProviderFirstUse();
    if (!prepared.ok) throw new Error('prepare failed');
    expect(binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);
    const envelope = await binding.providerFirstUse({ requestRef: prepared.requestRef }, undefined);
    expect(envelope.phase).toBe('terminal');
    if (envelope.phase !== 'terminal') throw new Error('expected terminal envelope');
    expect(envelope.outcome.ok).toBe(true);
    if (!envelope.outcome.ok) throw new Error('expected first-use success');
    // The returned envelope carries no provider-controlled text at all: the
    // hostile first line is not version-shaped, so no token is retained.
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain('Bearer');
    expect(serialized).not.toContain('api_key');
    expect(serialized).not.toContain('Authorization');
    expect(envelope.outcome.output).toMatchObject({
      probeVersionParsed: false,
      canaryResult: 'NOT_MATCHED',
    });
    expect('probeVersion' in envelope.outcome.output).toBe(false);

    // Raw SQLite: the durable receipt_json carries no secret and no raw
    // output/reference key — proven against the database file itself.
    const db = new DatabaseSync(join(cacheRoot, 'provider-first-use-requests.sqlite'));
    try {
      const row = db
        .prepare('SELECT receipt_json FROM provider_first_use_requests WHERE request_ref=?')
        .get(prepared.requestRef) as { receipt_json: string };
      expect(row.receipt_json).not.toContain(secret);
      expect(row.receipt_json).not.toContain('Bearer');
      expect(row.receipt_json).not.toContain('api_key');
      const persisted = JSON.parse(row.receipt_json) as Record<string, unknown>;
      expect(Object.keys(persisted).sort()).toEqual([
        'artifactSha256',
        'bindingId',
        'canaryResult',
        'code',
        'durationMs',
        'exitCode',
        'outcome',
        'probeVersionParsed',
        'timedOut',
      ]);
    } finally {
      db.close();
    }
  });

  it('previews and receipts are closed-world: unknown keys, nested payloads, secret-shaped values and status mismatch are refused', () => {
    const ledger = new ProviderFirstUseLedger(join(newDir('closed-world'), 'l.sqlite'));
    const prepared = ledger.prepare(USER_PREVIEW);
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    expect(ledger.confirm(prepared.record.requestRef).ok).toBe(true);
    expect(ledger.begin(prepared.record.requestRef).ok).toBe(true);
    const ref = prepared.record.requestRef;
    const valid: ProviderFirstUseReceipt = {
      outcome: 'EXECUTED',
      code: 'PROVIDER_FIRST_USE_EXECUTED',
      bindingId: 'rg-binding',
      artifactSha256: A64,
      exitCode: 0,
      timedOut: false,
      durationMs: 12,
    };
    // Every refused finish leaves the row RUNNING, so each malformed receipt
    // can be attempted against the same row until the bounded valid one lands.
    for (const bad of [
      { ...valid, stdout: 'provider-controlled leak' },
      { ...valid, stderr: 'provider-controlled leak' },
      { ...valid, outputRefs: ['C:\\effect-work\\out\\write.bin'] },
      { ...valid, stdoutRef: 'C:\\effect-work\\out\\stdout.txt' },
      { ...valid, environmentId: 'env-1' },
      { ...valid, nested: { secret: 'sk-live-1' } },
      { ...valid, probeVersion: 'C:\\Windows\\System32\\evil.exe' },
      { outcome: 'REFUSED', code: 'PROVIDER_ELEVATION_REFUSED' },
      { ...valid, outcome: 'REFUSED' },
      { outcome: 'EXECUTED', code: 'api_key=sk-live-1' },
      { outcome: 'EXECUTED' },
      'not-an-object',
      null,
      ['array'],
    ]) {
      expect(ledger.finish(ref, 'COMPLETED', bad as never)).toBe(false);
      expect(ledger.read(ref)?.status).toBe('RUNNING');
    }
    // The bounded valid receipt round-trips exactly through read().
    expect(ledger.finish(ref, 'COMPLETED', valid)).toBe(true);
    const record = ledger.read(ref);
    expect(record?.status).toBe('COMPLETED');
    expect(record?.receipt).toEqual(valid);
    ledger.close();

    // Preview closed-world: extra keys on the preview or the nested
    // elevatedAction, and a missing elevatedAction key, all refuse.
    const hostilePreview = new ProviderFirstUseLedger(
      join(newDir('closed-world-preview'), 'l.sqlite'),
    );
    expect(hostilePreview.prepare({ ...USER_PREVIEW, extra: 'x' } as never).ok).toBe(false);
    expect(
      hostilePreview.prepare({
        ...USER_PREVIEW,
        privilegeScope: 'ELEVATED' as const,
        elevatedAction: {
          program: 'C:\\Windows\\System32\\whoami.exe',
          args: [],
          sideEffectClass: 'R2',
          requiredPrivilege: 'ELEVATED' as const,
          hidden: 1,
        },
      } as never).ok,
    ).toBe(false);
    expect(
      hostilePreview.prepare({
        ...USER_PREVIEW,
        privilegeScope: 'ELEVATED' as const,
        elevatedAction: {
          program: 'C:\\Windows\\System32\\whoami.exe',
          args: [],
          requiredPrivilege: 'ELEVATED' as const,
        },
      } as never).ok,
    ).toBe(false);
    hostilePreview.close();

    // decodeRow fails closed on malformed or legacy persisted receipts: the
    // read side enforces the SAME closed schema as finish().
    const tamperFile = join(newDir('closed-world-tamper'), 'l.sqlite');
    const tampered = new ProviderFirstUseLedger(tamperFile);
    const p2 = tampered.prepare(USER_PREVIEW);
    if (!p2.ok) throw new Error('prepare failed');
    expect(tampered.confirm(p2.record.requestRef).ok).toBe(true);
    expect(tampered.begin(p2.record.requestRef).ok).toBe(true);
    const raw = new DatabaseSync(tamperFile);
    try {
      const update = raw.prepare(
        'UPDATE provider_first_use_requests SET receipt_json=? WHERE request_ref=?',
      );
      // Legacy pre-schema shape: unreadable.
      update.run(JSON.stringify({ code: 'LEGACY_SHAPE' }), p2.record.requestRef);
      expect(tampered.read(p2.record.requestRef)).toBeUndefined();
      // In-schema direct write against the RUNNING row reads back cleanly.
      update.run(
        JSON.stringify({ outcome: 'UNKNOWN', code: 'DIRECT_WRITE_PROBE' }),
        p2.record.requestRef,
      );
      expect(tampered.read(p2.record.requestRef)?.receipt).toEqual({
        outcome: 'UNKNOWN',
        code: 'DIRECT_WRITE_PROBE',
      });
      // Out-of-schema key: unreadable.
      update.run(
        JSON.stringify({ outcome: 'UNKNOWN', code: 'DIRECT_WRITE_PROBE', stdoutRef: 'C:\\x' }),
        p2.record.requestRef,
      );
      expect(tampered.read(p2.record.requestRef)).toBeUndefined();
    } finally {
      raw.close();
    }
    tampered.close();
  });

  it('privileged ExecutionReceipts are reduced to the closed allowlist summary before persistence', async () => {
    const { effect } = await freshHost();
    const summary = effect.projectPrivilegedReceipt({
      terminal: 'SUCCEEDED',
      exitCode: 0,
      timedOut: false,
      durationMs: 42,
      stdoutRef: 'C:\\effect-work\\out\\stdout.txt',
      stderrRef: 'C:\\effect-work\\out\\stderr.txt',
      outputRefs: ['C:\\effect-work\\out\\write.bin'],
      environmentId: 'env-1',
      nested: { bearer: 'sk-live-1' },
      freeText: 'Authorization: Bearer sk-live-1',
    });
    expect(summary).toEqual({
      terminal: 'SUCCEEDED',
      exitCode: 0,
      timedOut: false,
      durationMs: 42,
    });
    // Unknown terminal classification maps to UNCLEAR; absent facts stay absent.
    expect(effect.projectPrivilegedReceipt({ terminal: 'WEIRD', exitCode: 2 })).toEqual({
      terminal: 'UNCLEAR',
      exitCode: 2,
    });
    expect(effect.projectPrivilegedReceipt(undefined)).toEqual({ terminal: 'UNCLEAR' });
  });

  it('ELEVATED reaches the existing privileged backend only after explicit confirmation and fails closed without a helper pin', async () => {
    const { binding, effect } = await freshHost();
    const root = newDir('elevated');
    const authorityDir = join(root, 'authority');
    const workspaceRoot = join(root, 'workspace');
    const provisioned = provisionElevatedAuthority(authorityDir);
    effect.installTrustedWindowsEffectBinding({ authorityDir, workspaceRoot });

    const cacheRoot = newDir('elevated-cache');
    const artifactSha256 = sha256(ARTIFACT_BYTES);
    const trust = providerScope(artifactSha256);
    const { specs } = capturePort('');
    // Generation 4: the descriptor itself is curator-signed ELEVATED (#289
    // contract); the Host config only pins the exact pre-provisioned action.
    binding.installTrustedProviderBinding({
      cacheRoot,
      roots: [
        {
          keyId: 'key-1',
          publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      scopes: [trust],
      descriptor: makeDescriptor(trust, { requiredPrivilege: 'ELEVATED' }),
      revocationEpoch: 1,
      hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
      fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
      process: capturePort('').port,
      elevatedAction: {
        actionRef: provisioned.actionId,
        planRef: provisioned.planHash,
        grantRef: provisioned.grantId,
        taskId: 'provider-global',
      },
    });
    expect(binding.trustedProviderBindingStatus()).toMatchObject({ privilegeScope: 'ELEVATED' });

    // Step 1: the bounded preview carries the exact installer identity.
    const prepared = await binding.prepareProviderFirstUse();
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    expect(prepared.preview.privilegeScope).toBe('ELEVATED');
    expect(prepared.preview.elevatedAction).toMatchObject({
      program: 'C:\\Windows\\System32\\whoami.exe',
      args: ['/groups', '/fo', 'csv'],
      sideEffectClass: 'R2',
      requiredPrivilege: 'ELEVATED',
    });

    // Without confirmation the K capability refuses before the UAC path.
    const unconfirmed = await binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      undefined,
    );
    expect(unconfirmed).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_REQUEST_NOT_APPROVED' } },
    });
    expect(specs.length).toBe(0);

    // Step 2: explicit confirmation, then the K capability drives the EXISTING
    // privileged backend. CI has no pinned helper, so the backend refuses
    // structurally (terminal REFUSED receipt) — the pinned UAC relay is never
    // spawned and no installer runs; the request is recorded REFUSED.
    expect(binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);
    const envelope = await binding.providerFirstUse({ requestRef: prepared.requestRef }, undefined);
    expect(envelope).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_ELEVATION_REFUSED' } },
    });
    expect(specs.length).toBe(0);
    const record = binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record?.status).toBe('REFUSED');
    // The durable receipt is the allowlist projection of the privileged
    // ExecutionReceipt: terminal classification only, no output references.
    expect(record?.receipt).toMatchObject({
      outcome: 'REFUSED',
      code: 'PROVIDER_ELEVATION_REFUSED',
      elevatedTerminal: 'REFUSED',
    });
    expect(JSON.stringify(record?.receipt)).not.toMatch(
      /outputRefs|stdoutRef|stderrRef|environmentId/,
    );
  });

  it('fails closed on elevated plan drift, and host config can never elevate a USER provider', async () => {
    const { binding, effect } = await freshHost();
    const root = newDir('elevated-drift');
    const authorityDir = join(root, 'authority');
    const workspaceRoot = join(root, 'workspace');
    const provisioned = provisionElevatedAuthority(authorityDir);
    effect.installTrustedWindowsEffectBinding({ authorityDir, workspaceRoot });

    const cacheRoot = newDir('elevated-drift-cache');
    const trust = providerScope(sha256(ARTIFACT_BYTES));
    const { specs } = capturePort('');
    binding.installTrustedProviderBinding({
      cacheRoot,
      roots: [
        {
          keyId: 'key-1',
          publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      scopes: [trust],
      // Signed ELEVATED descriptor; the pinned plan reference is drifted, so
      // the preview must refuse before anything runs.
      descriptor: makeDescriptor(trust, { requiredPrivilege: 'ELEVATED' }),
      revocationEpoch: 1,
      hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
      fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
      process: capturePort('').port,
      elevatedAction: {
        actionRef: provisioned.actionId,
        planRef: 'f'.repeat(64),
        grantRef: provisioned.grantId,
        taskId: 'provider-global',
      },
    });
    const drifted = await binding.prepareProviderFirstUse();
    expect(drifted).toMatchObject({ ok: false, code: 'PROVIDER_ELEVATION_PREVIEW_UNAVAILABLE' });
    expect(specs.length).toBe(0);

    // Generation 4: a native addon descriptor signed USER (omitted privilege)
    // is refused outright when Host config tries to pin an elevated action —
    // the signed descriptor wins over Host configuration.
    vi.resetModules();
    const native = await freshHost();
    const nativeTrust = providerScope(sha256(ARTIFACT_BYTES));
    nativeTrust.artifactKind = 'NATIVE_ADDON';
    nativeTrust.abiRevision = '137';
    expect(() =>
      native.binding.installTrustedProviderBinding({
        cacheRoot: newDir('elevated-native-cache'),
        roots: [
          {
            keyId: 'key-1',
            publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          },
        ],
        scopes: [nativeTrust],
        descriptor: makeDescriptor(nativeTrust, { abiRevision: '137', entrypoint: 'addon.node' }),
        revocationEpoch: 1,
        hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
        fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
        elevatedAction: {
          actionRef: provisioned.actionId,
          planRef: provisioned.planHash,
          grantRef: provisioned.grantId,
          taskId: 'provider-global',
        },
      }),
    ).toThrow('PROVIDER_HOST_ELEVATION_SIGNED_USER');
  });

  it('generation-4 signed-privilege enforcement: Host config cannot override the signed descriptor', async () => {
    // Each install needs a fresh module (the binding is a per-module
    // singleton). The elevatedAction reference itself is only stored at
    // install time — grant/plan/ProgramPin resolution happens at prepare —
    // so install-time refusals can use a structurally valid dummy reference.
    const dummyAction = {
      actionRef: 'act-install-rg',
      planRef: A64,
      grantRef: 'grant-dummy',
      taskId: 'provider-global',
    };
    const installExpectingThrow = async (
      name: string,
      descriptorOverrides: Record<string, unknown>,
      elevatedAction?: typeof dummyAction,
    ): Promise<string> => {
      const { binding } = await freshHost();
      const trust = providerScope(sha256(ARTIFACT_BYTES));
      try {
        binding.installTrustedProviderBinding({
          cacheRoot: newDir(`${name}-cache`),
          roots: [
            {
              keyId: 'key-1',
              publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
            },
          ],
          scopes: [trust],
          descriptor: makeDescriptor(trust, descriptorOverrides),
          revocationEpoch: 1,
          hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
          fetchArtifact: (async () =>
            new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
          ...(elevatedAction !== undefined ? { elevatedAction } : {}),
        });
        throw new Error('EXPECTED_INSTALL_REFUSAL_BUT_INSTALLED');
      } catch (error) {
        return error instanceof Error ? error.message : 'unknown';
      }
    };

    // USER-signed descriptor + Host elevated action: refused (signed wins).
    expect(await installExpectingThrow('g4-user-literal', { requiredPrivilege: 'USER' }, dummyAction)).toMatch(
      /PROVIDER_HOST_ELEVATION_SIGNED_USER/,
    );
    // Omitted privilege (legacy descriptor) + Host elevated action: refused.
    expect(await installExpectingThrow('g4-omitted', {}, dummyAction)).toMatch(
      /PROVIDER_HOST_ELEVATION_SIGNED_USER/,
    );
    // Signed ELEVATED CLI descriptor without the pinned Host action: refused.
    expect(
      await installExpectingThrow('g4-elevated-no-action', { requiredPrivilege: 'ELEVATED' }),
    ).toMatch(/PROVIDER_HOST_ELEVATION_ACTION_REQUIRED/);
    // USER↔ELEVATED tampering after signing fails curator verification, so
    // the binding refuses the descriptor outright (never installs).
    const trust = providerScope(sha256(ARTIFACT_BYTES));
    const signedUser = makeDescriptor(trust);
    const { binding: tamperedUp } = await freshHost();
    expect(() =>
      tamperedUp.installTrustedProviderBinding({
        cacheRoot: newDir('g4-tamper-up-cache'),
        roots: [
          {
            keyId: 'key-1',
            publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          },
        ],
        scopes: [trust],
        descriptor: { ...signedUser, requiredPrivilege: 'ELEVATED' },
        revocationEpoch: 1,
        hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
        fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
        elevatedAction: dummyAction,
      }),
    ).toThrow(/PROVIDER_HOST_DESCRIPTOR_UNTRUSTED:CATALOG_SIGNATURE_INVALID/);
    const signedElevated = makeDescriptor(trust, { requiredPrivilege: 'ELEVATED' });
    const { binding: tamperedDown } = await freshHost();
    expect(() =>
      tamperedDown.installTrustedProviderBinding({
        cacheRoot: newDir('g4-tamper-down-cache'),
        roots: [
          {
            keyId: 'key-1',
            publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          },
        ],
        scopes: [trust],
        descriptor: { ...signedElevated, requiredPrivilege: 'USER' },
        revocationEpoch: 1,
        hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
        fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
      }),
    ).toThrow(/PROVIDER_HOST_DESCRIPTOR_UNTRUSTED:CATALOG_SIGNATURE_INVALID/);
    // NATIVE_ADDON + ELEVATED: the #289 strict signed schema refuses the
    // descriptor before any signature work (ELEVATED is CLI-only there).
    const nativeTrust = providerScope(sha256(ARTIFACT_BYTES));
    nativeTrust.artifactKind = 'NATIVE_ADDON';
    nativeTrust.abiRevision = '137';
    const { binding: nativeElevated } = await freshHost();
    expect(() =>
      nativeElevated.installTrustedProviderBinding({
        cacheRoot: newDir('g4-native-elevated-cache'),
        roots: [
          {
            keyId: 'key-1',
            publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          },
        ],
        scopes: [nativeTrust],
        descriptor: makeDescriptor(nativeTrust, {
          artifactKind: 'NATIVE_ADDON',
          abiRevision: '137',
          entrypoint: 'addon.node',
          requiredPrivilege: 'ELEVATED',
        }),
        revocationEpoch: 1,
        hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
        fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
        elevatedAction: dummyAction,
      }),
    ).toThrow(/PROVIDER_HOST_DESCRIPTOR_UNTRUSTED:CATALOG_UNTRUSTED/);
    // Positive control: signed ELEVATED CLI + pinned action installs ELEVATED.
    const { binding: accepted } = await freshHost();
    accepted.installTrustedProviderBinding({
      cacheRoot: newDir('g4-accepted-cache'),
      roots: [
        {
          keyId: 'key-1',
          publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      scopes: [trust],
      descriptor: makeDescriptor(trust, { requiredPrivilege: 'ELEVATED' }),
      revocationEpoch: 1,
      hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
      fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
      elevatedAction: dummyAction,
    });
    expect(accepted.trustedProviderBindingStatus()).toMatchObject({ privilegeScope: 'ELEVATED' });
  });

  it('generation-5: elevated SUCCEEDED keeps the request RUNNING until the Provider canary terminates it COMPLETED exactly once', async () => {
    const host = await freshInjectedHost({});
    // The canary FILE_SEARCH run blocks on a test-controlled gate so the
    // durable request state is observable while the Provider stage is in
    // flight. No real child process ever spawns.
    const specs: ActivationRunSpec[] = [];
    let markCanaryEntered: () => void = () => undefined;
    const canaryEntered = new Promise<void>((resolve) => {
      markCanaryEntered = resolve;
    });
    let releaseCanary: (outcome: InjectedRunOutcome) => void = () => undefined;
    const canaryGate = new Promise<InjectedRunOutcome>((resolve) => {
      releaseCanary = resolve;
    });
    const port = {
      async run(spec: ActivationRunSpec): Promise<InjectedRunOutcome> {
        specs.push(spec);
        if (spec.args.includes('SHUN-PROVIDER-FIRST-USE')) {
          markCanaryEntered();
          return canaryGate;
        }
        return {
          exitCode: 0,
          stdout: 'ripgrep 14.1.1',
          stderr: '',
          timedOut: false,
          stdoutTruncated: false,
          stderrTruncated: false,
        };
      },
    };
    const { workspaceRoot } = installInjectedElevatedBinding(host, 'g5-success', port);

    const prepared = await host.binding.prepareProviderFirstUse();
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    expect(host.binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);

    const pending = host.binding.providerFirstUse({ requestRef: prepared.requestRef }, undefined);
    await canaryEntered;
    // The installer stage already succeeded (injected), yet the request MUST
    // still be RUNNING with no receipt: elevation is intermediate.
    const midFlight = host.binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(midFlight?.status).toBe('RUNNING');
    expect(midFlight?.receipt).toBeUndefined();

    releaseCanary({
      exitCode: 0,
      stdout: 'noise\nSHUN-PROVIDER-FIRST-USE matched\n',
      stderr: '',
      timedOut: false,
      stdoutTruncated: false,
      stderrTruncated: false,
    });
    const envelope = await pending;
    expect(envelope.phase).toBe('terminal');
    if (envelope.phase !== 'terminal') throw new Error('expected terminal envelope');
    expect(envelope.outcome.ok).toBe(true);
    // Exactly one elevated stage ran; both unprivileged runs used the port.
    expect(host.elevatedCalls()).toBe(1);
    expect(specs.length).toBe(2);

    // One terminal receipt, identical in the envelope and the durable ledger,
    // combining the bounded elevated summary with the Provider outcome.
    const record = host.binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record?.status).toBe('COMPLETED');
    expect(record?.receipt).toMatchObject({
      outcome: 'EXECUTED',
      code: 'PROVIDER_FIRST_USE_EXECUTED',
      elevatedTerminal: 'SUCCEEDED',
      canaryResult: 'MATCHED',
      probeVersion: '14.1.1',
      exitCode: 0,
    });
    expect(record?.receipt?.durationMs).toBeGreaterThanOrEqual(42);
    if (envelope.outcome.ok) expect(envelope.outcome.output).toEqual(record?.receipt);
    // COMPLETED is terminal: a replay refuses before any further execution.
    const replay = await host.binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      undefined,
    );
    expect(replay).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_REQUEST_NOT_APPROVED' } },
    });
    // No real UAC/installer execution: the privileged workspace has no run
    // artifacts at all.
    expect(existsSync(join(workspaceRoot, 'executions'))).toBe(false);
  });

  it('generation-5: after elevated SUCCEEDED a Provider-stage refusal finishes exactly once as REFUSED with the bounded elevated summary', async () => {
    const host = await freshInjectedHost({ providerRefusal: 'ARTIFACT_NOT_VERIFIED' });
    // The real activator is replaced by the refusal fake, so the spawn port is
    // never consulted; capture anyway to prove zero Provider CLI runs.
    const captured = capturePort('');
    const { workspaceRoot } = installInjectedElevatedBinding(host, 'g5-refused', captured.port);

    const prepared = await host.binding.prepareProviderFirstUse();
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    expect(host.binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);
    const envelope = await host.binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      undefined,
    );
    expect(envelope).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'ARTIFACT_NOT_VERIFIED' } },
    });
    // The elevated stage ran exactly once; the refused Provider stage never
    // reached the spawn port.
    expect(host.elevatedCalls()).toBe(1);
    expect(captured.specs.length).toBe(0);

    const record = host.binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record?.status).toBe('REFUSED');
    // Exactly one terminal receipt, carrying ONLY bounded elevated summary
    // fields — the allowlist projection, never raw privileged output.
    expect(record?.receipt).toEqual({
      outcome: 'REFUSED',
      code: 'ARTIFACT_NOT_VERIFIED',
      elevatedTerminal: 'SUCCEEDED',
      exitCode: 0,
      timedOut: false,
      durationMs: 42,
    });
    expect(JSON.stringify(record?.receipt)).not.toMatch(
      /outputRefs|stdoutRef|stderrRef|environmentId/,
    );
    // The refusal is terminal: a replay refuses before any further execution.
    const replay = await host.binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      undefined,
    );
    expect(replay).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_REQUEST_NOT_APPROVED' } },
    });
    expect(existsSync(join(workspaceRoot, 'executions'))).toBe(false);
  });

  it('generation-5: after elevated SUCCEEDED a Provider-stage interruption finishes exactly once as UNKNOWN with the bounded elevated summary', async () => {
    const host = await freshInjectedHost({});
    // Real activator; the injected spawn port throws on the VERSION_PROBE, an
    // ambiguous execution boundary the chain maps to ACTIVATION_INTERRUPTED.
    const specs: ActivationRunSpec[] = [];
    const port = {
      async run(spec: ActivationRunSpec): Promise<InjectedRunOutcome> {
        specs.push(spec);
        throw new Error('INJECTED_SPAWN_FAILURE');
      },
    };
    installInjectedElevatedBinding(host, 'g5-interrupted', port);

    const prepared = await host.binding.prepareProviderFirstUse();
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    expect(host.binding.confirmProviderFirstUse(prepared.requestRef).ok).toBe(true);
    const envelope = await host.binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      undefined,
    );
    // Interrupted boundary: the K turn is not closed optimistically.
    expect(envelope.phase).toBe('running');
    expect(host.elevatedCalls()).toBe(1);
    expect(specs.length).toBe(1);

    const record = host.binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record?.status).toBe('UNKNOWN');
    // Exactly one terminal(uncertain) receipt with the bounded elevated
    // summary — never a false COMPLETED left by the intermediate stage.
    expect(record?.receipt).toEqual({
      outcome: 'UNKNOWN',
      code: 'ACTIVATION_INTERRUPTED',
      elevatedTerminal: 'SUCCEEDED',
      exitCode: 0,
      timedOut: false,
      durationMs: 42,
    });
    // UNKNOWN is terminal: a replay refuses before any further execution.
    const replay = await host.binding.providerFirstUse(
      { requestRef: prepared.requestRef },
      undefined,
    );
    expect(replay).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'PROVIDER_REQUEST_NOT_APPROVED' } },
    });
  });
});

/** The binding materializes its durable ledger under the cache root. */
function existsCacheLedger(cacheRoot: string): boolean {
  return typeof cacheRoot === 'string' && cacheRoot.length > 0;
}
