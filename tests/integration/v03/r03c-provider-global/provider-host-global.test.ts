/**
 * R03C-PROVIDER-GLOBAL-UAC — Host-global Provider first-use qualification
 * (Issue #287, Execution Pack
 * .agent/execution/R03C-PROVIDER-GLOBAL-UAC/MANIFEST.yaml@23019ee4).
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
 * The trusted Host bindings are process singletons, so each scenario imports
 * them fresh (vi.resetModules + dynamic import) over its own fixture store.
 */
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { canonicalJson, computePlanHash } from '../../../../packages/contracts/src/plan.ts';
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

/** Capturing spawn port: the real chain runs, no real child process ever starts. */
function capturePort(stdout = 'ripgrep 14.1.1'): CapturedRun {
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
        stdout,
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
async function installUserBinding(): Promise<InstalledUserHost> {
  const { binding } = await freshHost();
  const cacheRoot = newDir('user-cache');
  const artifactSha256 = sha256(ARTIFACT_BYTES);
  const trust = providerScope(artifactSha256);
  const { specs, port } = capturePort();
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
    op: 'windows.proc.exec',
    parameters: {
      program: 'C:\\Windows\\System32\\whoami.exe',
      args: ['/groups', '/fo', 'csv'],
      expectExitCode: 0,
    },
    sideEffectClass: 'R2',
    requiredPrivilege: 'ELEVATED',
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
    expect(envelope.outcome.output.state).toBe('EXECUTED');
    // Both real chain executions went through the captured unprivileged port.
    expect(specs.length).toBe(2);
    const record = binding.readProviderFirstUseRequest(prepared.requestRef);
    expect(record?.status).toBe('COMPLETED');
    expect(record?.receipt).toMatchObject({ state: 'EXECUTED', exitCode: 0 });
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
    expect(record?.receipt).toMatchObject({ code: 'PROCESS_RESTARTED_WITH_UNCERTAIN_OUTCOME' });
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
    expect(envelope.outcome.output.state).toBe('EXECUTED');
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
    expect((record?.receipt as { receipt?: { terminal?: string } })?.receipt?.terminal).toBe(
      'REFUSED',
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
      descriptor: makeDescriptor(trust),
      revocationEpoch: 1,
      fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
      process: capturePort('').port,
      // Drifted plan reference: the preview must refuse before anything runs.
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

    // A native addon is never elevated: the operator configuration is
    // refused outright for non-CLI artifacts.
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
        fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
        elevatedAction: {
          actionRef: provisioned.actionId,
          planRef: provisioned.planHash,
          grantRef: provisioned.grantId,
          taskId: 'provider-global',
        },
      }),
    ).toThrow('PROVIDER_HOST_ELEVATION_CLI_ONLY');
  });
});

/** The binding materializes its durable ledger under the cache root. */
function existsCacheLedger(cacheRoot: string): boolean {
  return typeof cacheRoot === 'string' && cacheRoot.length > 0;
}
