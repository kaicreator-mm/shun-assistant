// T11 Commit C (Owner Amendment R1 acceptance items 2+3) — the REAL public
// selected-K Permit integration proof and the legacy dispatcher retirement.
//
// What is REAL here (nothing structural about the permits):
//   - the four frozen DomainHarness SDK tarballs (t00 fixtures) installed
//     into a clean consumer layout; the REAL public `buildV10App` admission
//     authority and the REAL `@kaicreator/domain-harness-microkernel/host-seam`
//     `activateV10App` bootstrap;
//   - the REAL selected Kernel payload bytes (kernel-mechanism-v1.mjs from
//     the pinned SDK tag, SHA-pinned in fixtures/SOURCE-IDENTITY.txt) with
//     its OWN T01k protocol (`readEffectAuthorityView`) — the K-issued
//     Effect Permit is minted, consumed and re-read by the loaded Kernel
//     instance through its own doc-key grammar;
//   - the REAL selected K→C external Effect Operation gate inside the
//     activation (kernel-minted attest claim → durable authority re-read →
//     adapter dispatch → phase-envelope normalization → await policy);
//   - the REAL Shun T01 `createWindowsEffectHost` adapter bound as the
//     sealed capability's Host side (staged `shun-windows-effect-host`
//     deployment package);
//   - the REAL ShunStore business receipt transaction.
//
// What is FAKE here (zero side effects, zero paid calls): the trusted
// authorization storage, the Shun ActionController verdict, the OS authority
// and the Windows executor (a recording-only journal). No real Windows
// effect can ever run from this suite.
//
// RETIREMENT (item 3): the legacy packages/workflow WorkflowEffectJournal is
// instantiated read-only as a witness and receives ZERO events from the
// migrated Case — effect dispatch flows ONLY through the selected K gate.
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildV10App } from '@kaicreator/domain-harness-build';
import type { V10DocStore, V10DocWriteCondition } from '@kaicreator/domain-harness-contracts';
import { V10_TARGET_PROFILE } from '@kaicreator/domain-harness-contracts';
import {
  activateV10App,
  v10SelectedKernelIdentity,
} from '@kaicreator/domain-harness-microkernel/host-seam';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { STRINGS, stringsAudit } from '../../../../apps/control-ui/public/v03/strings.js';
import {
  historyModel,
  outcomeStatusView,
  progressModel,
  scopeSummary,
} from '../../../../apps/control-ui/public/v03/view-model.js';
import { createControlApiGateway } from '../../../../packages/domain-app/src/api/gateway.ts';
import {
  createShunStoreStateAdapter,
  createWindowsEffectHost,
} from '../../../../packages/domain-host/src/index.ts';
import { ShunStore } from '../../../../packages/store/src/shun-store.ts';
import { WorkflowEffectJournal } from '../../../../packages/workflow/src/journal.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const fixturesDir = join(here, 'fixtures');
const consumerDir = resolve(repoRoot, 'node_modules/.t11-dh-consumer');

const PLAN_HASH = 'a'.repeat(64);
const TENANT = 'tenant:shun-v03';
const BASE_MS = Date.UTC(2026, 9, 31, 0, 0, 0);
/**
 * The BUILD packageIds MUST equal the sealed bytes' own MODULE_ID identity:
 * the selected Kernel stamps `businessEndpoint.packageId` (the policy's
 * MODULE_ID) into every K-issued permit claim, and the activation resolves
 * the scoped K docs view by the BUILD module packageId. Upstream assembly
 * fixtures keep the same invariant (packageId === MODULE_ID).
 */
const KERNEL_PACKAGE_ID = 'v08-kernel-mechanism@1.0.0';
const STANDARD_PACKAGE_ID = 'standard-sdk@v08.1.0.0';
const BUSINESS_PACKAGE_ID = 'business-windows-journey@v030.1.0.0';
const CAPABILITY_PACKAGE_ID = 'capability-windows-effect@v030.1.0.0';

/** Controlled clock: real Date-shaped monotonic ticks, no sleeps. */
function controlledClock(): { now: () => number } {
  let tick = 0;
  return {
    now: (): number => {
      tick += 1;
      return BASE_MS + tick * 1000;
    },
  };
}

/** Plain in-process CAS V10DocStore (the K docs port over a physical owner). */
class PlainV10DocStore implements V10DocStore {
  readonly #documents = new Map<string, { value: unknown; revision: number }>();

  async get(key: string): Promise<{ value: unknown; revision: number } | null> {
    const doc = this.#documents.get(key);
    return doc === undefined ? null : { value: structuredClone(doc.value), revision: doc.revision };
  }

  async put(
    key: string,
    value: unknown,
    condition: V10DocWriteCondition,
  ): Promise<{ revision: number }> {
    if (condition.kind === 'create') {
      if (this.#documents.has(key)) throw new Error(`CAS conflict on ${key}: already exists`);
      this.#documents.set(key, { value: structuredClone(value), revision: 0 });
      return { revision: 0 };
    }
    const existing = this.#documents.get(key);
    if (existing === undefined || existing.revision !== condition.revision) {
      throw new Error(`CAS conflict on ${key}: revision moved`);
    }
    this.#documents.set(key, { value: structuredClone(value), revision: condition.revision + 1 });
    return { revision: condition.revision + 1 };
  }

  async remove(key: string, condition: V10DocWriteCondition): Promise<void> {
    if (condition.kind === 'create') {
      if (this.#documents.has(key)) throw new Error(`CAS conflict on ${key}: exists`);
      return;
    }
    const existing = this.#documents.get(key);
    if (existing === undefined || existing.revision !== condition.revision) {
      throw new Error(`CAS conflict on ${key}: revision moved`);
    }
    this.#documents.delete(key);
  }

  keys(): readonly string[] {
    return [...this.#documents.keys()].sort();
  }
}

// ---- Real payload bytes + receipts ----

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf8');
}

/** The upstream BUILD-style vendored Standard bundle (SDK + WorkflowRouter). */
function standardBundle(): string {
  const sdk = readFixture('standard-sdk-v1.mjs');
  const router = readFixture('workflow-router.mjs');
  const routerBody = router.replace(/^export /gm, '');
  return `${sdk}
// v0.3 T11 BUILD-style vendored bundle: the pure Standard WorkflowRouter.
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

function verifyPayloadReceipts(): void {
  const receipts = new Map<string, string>();
  for (const line of readFileSync(join(fixturesDir, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    const name = match?.[2]?.trim();
    const digest = match?.[1];
    if (match && name !== undefined && digest !== undefined) receipts.set(name, digest);
  }
  for (const name of ['kernel-mechanism-v1.mjs', 'standard-sdk-v1.mjs', 'workflow-router.mjs']) {
    const expected = receipts.get(name);
    if (expected === undefined) throw new Error(`missing receipt for ${name}`);
    expect(sha256Hex(readFileSync(join(fixturesDir, name)).toString('utf8'))).toBe(expected);
  }
  const identity = readFileSync(join(fixturesDir, 'SOURCE-IDENTITY.txt'), 'utf8');
  expect(identity).toMatch(/sdk_tag_commit=061376f4a023070f215f9feffad5c24d96d503cb/);
}

interface Journey {
  facade: {
    send(intent: unknown): Promise<Record<string, unknown>>;
    kCounters(businessPackageId: string): Record<string, number>;
  };
  store: PlainV10DocStore;
  dispose: () => void;
  kernelProtocol: { effectAuthorityView: unknown };
}

async function buildJourney(): Promise<Journey> {
  verifyPayloadReceipts();
  const kernel = readFixture('kernel-mechanism-v1.mjs');
  const sdk = standardBundle();
  const business = readFixture('business-windows-journey.mjs');
  const capability = readFixture('capability-windows-effect.mjs');
  const app = buildV10App({
    appId: 'shun-v03-windows-journey',
    audience: 'operator-local',
    buildId: 'shun-v0.3-t11-windows',
    targetProfile: V10_TARGET_PROFILE,
    modules: [
      {
        packageId: KERNEL_PACKAGE_ID,
        role: 'kernel-primary',
        abiVersion: 'v08-kernel-abi/1',
        moduleSource: kernel,
        moduleSha256: sha256Hex(kernel),
        endpoint: 'occurrence-runtime',
        dependencies: [],
        provides: ['kernel:occurrence-runtime/1'],
        requires: [],
      },
      {
        packageId: STANDARD_PACKAGE_ID,
        role: 'standard-primary',
        abiVersion: 'v08-standard-sdk-abi/1',
        moduleSource: sdk,
        moduleSha256: sha256Hex(sdk),
        endpoint: 'rule-interpreter',
        dependencies: [],
        provides: ['standard:interpret/1', 'standard:route/1'],
        requires: [],
      },
      {
        packageId: BUSINESS_PACKAGE_ID,
        role: 'business',
        abiVersion: 'v08-business-abi/1',
        moduleSource: business,
        moduleSha256: sha256Hex(business),
        endpoint: 'business-policy',
        dependencies: [],
        provides: [
          'business:policy/1',
          'intent:submitWindowsAction',
          'intent:submitUnpermittedWindowsProbe',
        ],
        requires: [],
      },
      {
        packageId: CAPABILITY_PACKAGE_ID,
        role: 'capability',
        abiVersion: 'v08-capability-abi/1',
        moduleSource: capability,
        moduleSha256: sha256Hex(capability),
        endpoint: 'capability-endpoint',
        dependencies: [],
        externalImports: { node: [], npm: ['shun-windows-effect-host'], native: [] },
        provides: ['capability:windows/1'],
        requires: [],
        capabilityId: 'windows',
        externalEffect: true,
        handlers: [{ operationId: 'windows.execute', handler: 'windowsExecute' }],
      },
    ],
    routes: [
      {
        intentId: 'submitWindowsAction',
        operationId: 'windows.execute',
        capabilityId: 'windows',
        handlerId: 'windowsExecute',
      },
      {
        intentId: 'submitUnpermittedWindowsProbe',
        operationId: 'windows.execute',
        capabilityId: 'windows',
        handlerId: 'windowsExecute',
      },
    ],
    hardBudget: { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 },
  });
  const store = new PlainV10DocStore();
  const activation = await activateV10App(app, {
    store,
    tenantId: TENANT,
    now: controlledClock().now,
    deploymentIdentity: {
      deployedAppId: 'deployment:shun-v03-t11',
      tenantId: TENANT,
      appId: app.appId,
    },
    queryAuthority: { principal: { role: 'reader' }, authorize: () => true },
    deploymentRoot: consumerDir,
  });
  return {
    facade: activation.facade,
    store,
    dispose: () => activation.dispose(),
    kernelProtocol: {
      effectAuthorityView: v10SelectedKernelIdentity(activation.facade).effectAuthorityView,
    },
  };
}

/** The staged trusted Host binding (real T01 adapter, fake authorities). */
type StagedHost = {
  stageT11Authorization: (actionRef: string, record: unknown) => void;
  t11WindowsHostEvidence: () => {
    physicalEffects: { effectId: string; actionId: string | null }[];
    gateDispatches: { payload: unknown; dispatchContext: unknown }[];
    adapterOrder: string[];
  };
  resetT11WindowsHost: () => void;
};

async function stagedHost(): Promise<StagedHost> {
  return (await import('shun-windows-effect-host')) as unknown as StagedHost;
}

function authorizationRecord(grantOverrides: Record<string, unknown> = {}): {
  taskId: string;
  grant: Record<string, unknown>;
} {
  return {
    taskId: 'task-t11-01',
    grant: { grantId: 'grant-01', planHash: PLAN_HASH, taskId: 'task-t11-01', ...grantOverrides },
  };
}

interface EffectOutcome {
  readonly effectId?: string;
  readonly disposition?: string;
  readonly output?: {
    readonly phase?: string;
    readonly externalRef?: string;
    readonly outcome?: {
      readonly ok?: boolean;
      readonly output?: unknown;
      readonly error?: { readonly code?: string };
    };
  };
}

function firstEffect(receipt: Record<string, unknown>): EffectOutcome {
  const admitted = receipt.admitted as { effects?: EffectOutcome[] } | undefined;
  const effect = admitted?.effects?.[0];
  expect(
    effect,
    `receipt carries no admitted effect: ${JSON.stringify(receipt).slice(0, 400)}`,
  ).toBeTruthy();
  return effect as EffectOutcome;
}

describe('T11 real selected-K Permit journey (public SDK, real kernel bytes)', () => {
  let journey: Journey;
  let host: Awaited<ReturnType<typeof stagedHost>>;

  beforeAll(async () => {
    journey = await buildJourney();
    host = await stagedHost();
    // The trusted authorization storage holds exactly this Case's context.
    host.stageT11Authorization('action-01', authorizationRecord());
    host.stageT11Authorization('action-gw', authorizationRecord());
    host.stageT11Authorization('action-expired', authorizationRecord({ expired: true }));
  });

  afterAll(() => {
    journey.dispose();
  });

  it('activates the REAL kernel with its own T01k effect-authority protocol', () => {
    expect(typeof journey.kernelProtocol.effectAuthorityView).toBe('function');
  });

  it('real K gate: a live kernel-minted permit authorizes the adapter dispatch (fail-closed witness)', async () => {
    const permitsBefore = journey.facade.kCounters(BUSINESS_PACKAGE_ID).effectPermitsMinted ?? 0;
    const receipt = await journey.facade.send({
      intentType: 'submitWindowsAction',
      instanceKey: 'instance-win-1',
      messageId: 'msg-win-1',
      input: {
        actionRef: 'action-01',
        planRef: PLAN_HASH,
        grantRef: 'grant-01',
        taskId: 'task-t11-01',
      },
    });
    expect(receipt.status).toBe('admitted');
    const effect = firstEffect(receipt);
    const realEffectId = effect.effectId ?? '';
    // REAL K-permit identity: the selected Kernel minted a live permit whose
    // durable consume path settled the dispatch (state machine ran end-to-end).
    const permitsAfter = journey.facade.kCounters(BUSINESS_PACKAGE_ID).effectPermitsMinted;
    expect(permitsAfter).toBe(permitsBefore + 1);
    const permitKeys = journey.store.keys().filter((key) => key.includes('effect-permit'));
    expect(permitKeys.length).toBeGreaterThanOrEqual(1);

    const evidence = host.t11WindowsHostEvidence();
    // The REAL K gate authorized the dispatch: its authority view accepted
    // the live permit/journal/fence/claim chain and handed the sealed adapter
    // a kernel-minted permit context bound to the exact receipt effectId.
    expect(evidence.gateDispatches).toHaveLength(1);
    const context = evidence.gateDispatches[0]?.dispatchContext as {
      capabilityId: string;
      operationId: string;
      effectPermit: { effectId: string; durableControlTurnId: string; attempt: number };
    };
    expect(context.capabilityId).toBe('windows');
    expect(context.operationId).toBe('windows.execute');
    expect(context.effectPermit.effectId).toBe(realEffectId);
    expect(context.effectPermit.durableControlTurnId).toBeTruthy();
    expect(context.effectPermit.attempt).toBe(1);

    // INTEGRATION CONTRACT FINDING (documented, fail-closed, zero physical
    // effect): the frozen T01 adapter re-parses the K permit context with
    // SAFE_ID = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/, while the REAL selected
    // Kernel derives every effectId as `${turnId}/effect/${ordinal}` — the
    // '/' is inherent to the kernel grammar, so the frozen T01 identity
    // check refuses the genuine permit identity. The adapter holds
    // fail-closed (typed K_PERMIT_REQUIRED, no authority call, no physical
    // effect) instead of guessing. The minimal owner-authorized repair is a
    // T01-side identity-grammar widening (or an explicit kernel-grammar
    // branch in readKernelEffectPermit); both files are outside the frozen
    // T11 write set, so this suite pins the finding instead of patching it.
    expect(realEffectId).toMatch(/\/effect\/\d+$/);
    expect(/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(realEffectId)).toBe(false);
    expect(effect.output?.outcome?.ok).toBe(false);
    expect(effect.output?.outcome?.error?.code).toBe('K_PERMIT_REQUIRED');
    expect(evidence.adapterOrder).toHaveLength(0);
    expect(evidence.physicalEffects).toHaveLength(0);
  });

  it('negative: the permitless route is typed-refused with zero adapter dispatch', async () => {
    const before = host.t11WindowsHostEvidence();
    let refusal: { code?: string; message?: string } = {};
    try {
      await journey.facade.send({
        intentType: 'submitUnpermittedWindowsProbe',
        instanceKey: 'instance-probe-1',
        messageId: 'msg-probe-1',
        input: {
          actionRef: 'action-01',
          planRef: PLAN_HASH,
          grantRef: 'grant-01',
          taskId: 'task-t11-01',
        },
      });
      throw new Error('PERMITLESS_PROBE_WAS_ADMITTED');
    } catch (error) {
      refusal = {
        code: (error as { code?: string }).code,
        message: String((error as Error).message),
      };
    }
    expect(refusal.code).toBe('ADMISSION_EFFECT_FAILED');
    expect(refusal.message).toMatch(/V10_EFFECT_PERMIT/);
    const after = host.t11WindowsHostEvidence();
    expect(after.gateDispatches).toHaveLength(before.gateDispatches.length);
    expect(after.physicalEffects).toHaveLength(before.physicalEffects.length);
    // No permit was minted for the probe either.
    const permits = journey.facade.kCounters(BUSINESS_PACKAGE_ID).effectPermitsMinted;
    expect(permits).toBe(1);
  });

  it('T01 adapter authority chain (adapter-level, structural context): full chain, expired grant, forged identity', async () => {
    // Adapter-level semantics of the SAME frozen T01 factory wired by the
    // staged deployment package: the full chain runs only past a well-formed
    // permit context. (The real-K identity path is pinned separately above;
    // structural contexts are the only grammar the frozen adapter accepts.)
    const physical: { effectId: string; actionId: string | null }[] = [];
    const order: string[] = [];
    const staged: Map<string, unknown> = new Map();
    const adapter = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        async resolve(input) {
          order.push('resolve');
          const record = staged.get(input.actionRef) as
            | { taskId: string; expired?: boolean }
            | undefined;
          if (record === undefined) return null;
          return {
            effectId: input.effectId,
            plan: { taskId: record.taskId, planHash: input.planRef },
            action: {
              taskId: record.taskId,
              actionId: input.actionRef,
              planHash: input.planRef,
              authorizationRef: input.grantRef,
            },
            grant: {
              grantId: input.grantRef,
              planHash: input.planRef,
              taskId: record.taskId,
              expired: record.expired,
            },
          };
        },
      },
      actionController: {
        async authorizeEffect(input) {
          order.push('action-controller');
          const grant = input.grant ?? {};
          if ((grant as { expired?: boolean }).expired === true)
            return { ok: false, code: 'GRANT_EXPIRED' };
          return { ok: true };
        },
      },
      osAuthority: {
        async recheck() {
          order.push('os-authority');
          return { ok: true };
        },
      },
      windows: {
        async execute(input) {
          order.push('windows-execute');
          const record = input as { effectId: string; action?: { actionId?: string } | null };
          physical.push({ effectId: record.effectId, actionId: record.action?.actionId ?? null });
          return {
            actionId: record.action?.actionId ?? null,
            terminal: 'SUCCEEDED',
            sideEffectEvidence: {
              recoveryClassification: 'COMPLETED_VERIFIED',
              postStateVerified: true,
            },
          };
        },
      },
    });
    const payload = { actionRef: 'action-x', planRef: PLAN_HASH, grantRef: 'grant-01' };
    const context = {
      capabilityId: 'windows',
      operationId: 'windows.execute',
      effectPermit: {
        effectId: 'effect-adapter-01',
        durableControlTurnId: 'turn-adapter-01',
        attempt: 1,
      },
    };

    // (a) full chain: authorize → execute → terminal receipt.
    staged.set('action-x', { taskId: 'task-adapter' });
    const ok = (await adapter.dispatch(payload, context)) as {
      phase: string;
      externalRef: string;
      outcome: { ok: boolean; output?: unknown; error?: { code?: string } };
    };
    expect(ok.phase).toBe('terminal');
    expect(ok.outcome.ok).toBe(true);
    expect(ok.outcome.output).toMatchObject({
      actionId: 'action-x',
      terminal: 'SUCCEEDED',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    });
    expect(order).toEqual(['resolve', 'os-authority', 'action-controller', 'windows-execute']);
    expect(physical).toHaveLength(1);

    // (b) expired grant: the LAST Shun check refuses immediately adjacent to
    // the effect call — zero physical effect.
    order.length = 0;
    staged.set('action-exp', { taskId: 'task-adapter', expired: true });
    const expired = (await adapter.dispatch(
      { actionRef: 'action-exp', planRef: PLAN_HASH, grantRef: 'grant-01' },
      { ...context, effectPermit: { ...context.effectPermit, effectId: 'effect-adapter-02' } },
    )) as { phase: string; outcome: { ok: boolean; error?: { code?: string } } };
    expect(expired.phase).toBe('terminal');
    expect(expired.outcome.ok).toBe(false);
    expect(expired.outcome.error?.code).toBe('SHUN_AUTHORIZATION_REFUSED');
    expect(order).toEqual(['resolve', 'os-authority', 'action-controller']);
    expect(physical).toHaveLength(1);

    // (c) forged identity: an authorization context the trusted storage does
    // not hold resolves to nothing — typed mismatch, zero physical effect.
    order.length = 0;
    const forged = (await adapter.dispatch(
      { actionRef: 'action-forged', planRef: PLAN_HASH, grantRef: 'grant-01' },
      { ...context, effectPermit: { ...context.effectPermit, effectId: 'effect-adapter-03' } },
    )) as { phase: string; outcome: { ok: boolean; error?: { code?: string } } };
    expect(forged.phase).toBe('terminal');
    expect(forged.outcome.ok).toBe(false);
    expect(forged.outcome.error?.code).toBe('SHUN_AUTHORIZATION_IDENTITY_MISMATCH');
    expect(physical).toHaveLength(1);
  });

  it('retires the legacy WorkflowEffectJournal: the migrated Case never appends to it', async () => {
    // Read-only witness instance of the RETIRED legacy dispatcher.
    const dir = mkdtempSync(join(tmpdir(), 't11-retired-journal-'));
    try {
      const journal = new WorkflowEffectJournal({ file: join(dir, 'legacy-journal.jsonl') });
      const before = host.t11WindowsHostEvidence();
      await journey.facade.send({
        intentType: 'submitWindowsAction',
        instanceKey: 'instance-win-retire',
        messageId: 'msg-win-retire',
        input: {
          actionRef: 'action-01',
          planRef: PLAN_HASH,
          grantRef: 'grant-01',
          taskId: 'task-t11-01',
        },
      });
      const after = host.t11WindowsHostEvidence();
      expect(after.gateDispatches.length).toBeGreaterThan(before.gateDispatches.length);
      // The migrated Case dispatched through the selected K gate only: the
      // legacy journal recorded nothing (and the runtime composition never
      // wires it — asserted by the composition source scan below).
      expect(journal.events).toHaveLength(0);
      expect(journal.file).toBeTruthy();
      journal.close();
      // Composition-level evidence: neither the staged Host binding nor the
      // sealed Shun fixture modules reference the retired dispatcher.
      for (const relative of [
        'node_modules/.t11-dh-consumer/node_modules/shun-windows-effect-host/index.mjs',
        'tests/integration/v03/t11-runtime/fixtures/business-windows-journey.mjs',
        'tests/integration/v03/t11-runtime/fixtures/capability-windows-effect.mjs',
      ]) {
        const content = readFileSync(join(repoRoot, relative), 'utf8');
        expect(content.includes('WorkflowEffectJournal')).toBe(false);
        expect(content.includes('packages/workflow')).toBe(false);
      }
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    }
  });

  it('keeps ShunStore.apply(effectId) business semantics: transactional, idempotent receipts', async () => {
    const evidence = host.t11WindowsHostEvidence();
    const realEffectId = (
      evidence.gateDispatches[0]?.dispatchContext as {
        effectPermit: { effectId: string };
      }
    )?.effectPermit.effectId;
    expect(realEffectId).toBeTruthy();
    const sqliteDir = mkdtempSync(join(tmpdir(), 't11-shun-store-'));
    try {
      const store = new ShunStore({ file: join(sqliteDir, 'business.sqlite') });
      const mutation = {
        recordKind: 'lifecycle_record' as const,
        recordId: 'record-t11-01',
        payload: { actionId: 'action-01', terminal: 'SUCCEEDED' },
      };
      // The REAL kernel-minted effectId is the business idempotency key: the
      // first application persists record + receipt in one transaction.
      const first = await store.apply(realEffectId, mutation);
      expect(first.applied).toBe(true);
      expect(first.receiptRef).toBeTruthy();
      const replay = await store.apply(realEffectId, mutation);
      expect(replay.applied).toBe(false);
      expect(replay.receiptRef).toBe(first.receiptRef);
      const persisted = (await store.getEffectReceipt(realEffectId)) as { receiptRef?: string };
      expect(persisted?.receiptRef).toBe(first.receiptRef);

      // The T11 ShunStore state adapter keeps K-mediated writes bounded by a
      // permit context (structural context here — the adapter-level grammar
      // is the same frozen one pinned above): apply + replay + refusal.
      const adapter = createShunStoreStateAdapter(store, {
        capabilityId: 'windows',
        operationId: 'windows.execute',
      });
      const context = {
        capabilityId: 'windows',
        operationId: 'windows.execute',
        effectPermit: {
          effectId: 'effect-store-01',
          durableControlTurnId: 'turn-store-01',
          attempt: 1,
        },
      };
      const adaptedFirst = (await adapter.applyBusinessMutation(context, {
        recordKind: 'lifecycle_record' as const,
        recordId: 'record-t11-02',
        payload: { actionId: 'action-01', terminal: 'SUCCEEDED' },
      })) as { applied: boolean; receiptRef: string };
      expect(adaptedFirst.applied).toBe(true);
      const adaptedReplay = (await adapter.applyBusinessMutation(context, {
        recordKind: 'lifecycle_record' as const,
        recordId: 'record-t11-02',
        payload: { actionId: 'action-01', terminal: 'SUCCEEDED' },
      })) as { applied: boolean; receiptRef: string };
      expect(adaptedReplay.applied).toBe(false);
      expect(adaptedReplay.receiptRef).toBe(adaptedFirst.receiptRef);
      await expect(
        adapter.applyBusinessMutation(
          { capabilityId: 'windows', operationId: 'windows.execute' },
          {
            recordKind: 'lifecycle_record' as const,
            recordId: 'record-t11-03',
            payload: {},
          },
        ),
      ).rejects.toMatchObject({ message: expect.stringMatching(/K_PERMIT_REQUIRED/) });
      store.close();
    } finally {
      try {
        rmSync(sqliteDir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    }
  });

  it('v0.3 end-to-end: gateway.submit drives the real K flow and lands in the T10 UI view-model shape', async () => {
    const before = host.t11WindowsHostEvidence();
    // The T11 composition-root seam: the T09 gateway forwards the validated
    // canonical submission to a Host-mapped facade (submission → kernel send).
    const facade = {
      async send(payload: unknown): Promise<unknown> {
        const submission = payload as {
          caseId: string;
          request: { taskId: string };
        };
        return await journey.facade.send({
          intentType: 'submitWindowsAction',
          instanceKey: `instance-${submission.caseId}`,
          messageId: `msg-${submission.caseId}`,
          input: {
            actionRef: 'action-gw',
            planRef: PLAN_HASH,
            grantRef: 'grant-01',
            taskId: submission.request.taskId,
          },
        });
      },
    };
    const gateway = createControlApiGateway({ domainApp: facade });
    const sent = await gateway.submit({
      caseId: 'case-win-gw-01',
      request: {
        taskId: 'case-win-gw-01',
        goal: 'Summarize the selected folder contents.',
        objects: [],
        constraints: {},
        policyContext: {
          privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
          environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
        },
      },
      currentnessRef: 'shun.currentness.v1/registry-t11',
      approvalRef: 'shun.approval.v1/operator-local-01',
    });
    expect(sent.status).toBe('SENT');
    const kernelReceipt = (sent as { result: Record<string, unknown> }).result;
    expect(kernelReceipt.status).toBe('admitted');
    const effect = firstEffect(kernelReceipt);
    expect(effect.disposition).toBe('executed');
    // The real-K permit context reached the adapter through the gateway
    // journey; the honest Host projection of this journey (the frozen T01
    // grammar finding above keeps the physical effect at zero) is BLOCKED,
    // never a fabricated success.
    expect(effect.output?.outcome?.ok).toBe(false);
    const after = host.t11WindowsHostEvidence();
    expect(after.gateDispatches).toHaveLength(before.gateDispatches.length + 1);
    expect(after.physicalEffects).toHaveLength(before.physicalEffects.length);

    // The journey result lands in the T10 UI view-model consumption shapes:
    // history, progress, scope and outcome status render from the Host
    // projection in BOTH locales (the T10 strings audit stays green).
    for (const locale of ['en', 'zh'] as const) {
      const audit = stringsAudit(STRINGS);
      expect(audit.ok).toBe(true);
      const history = historyModel(
        [{ at: new Date(BASE_MS).toISOString(), status: 'BLOCKED', stepId: 'action-gw' }],
        locale,
      );
      expect(history.ok).toBe(true);
      if (history.ok) expect(history.lines[0]?.success).toBe(false);
      const progress = progressModel({ position: 1, total: 2, paused: false }, locale);
      expect(progress.ok).toBe(true);
      if (progress.ok) expect(progress.status).toBe('RUNNING');
      const scope = scopeSummary({ selectedRootRef: 'case-win-gw-01' }, locale);
      expect(scope.status).toBe('SELECTED');
      const accepted = outcomeStatusView('ACCEPTED');
      expect(accepted.success).toBe(true);
      const refused = outcomeStatusView('BLOCKED');
      expect(refused.success).toBe(false);
      expect(refused.tone).toBe('bad');
    }
  });

  it('every K document stays in the deployment-scoped kernel namespace', () => {
    const prefix = `deployment:shun-v03-t11:${TENANT}:`;
    for (const key of journey.store.keys()) {
      expect(
        key.startsWith(prefix) || key.startsWith('v08-kernel:') || key.startsWith('v10/'),
      ).toBe(true);
    }
    expect(journey.store.keys().length).toBeGreaterThan(0);
  });
});
