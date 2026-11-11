// U06 (#401) — the positive no-effect end-user journey E2E: the REAL shipped
// desktop.js executes against a REAL loopback control server carrying the
// REAL guided journey (select-root → INSPECT → read-only preview →
// REVIEW_EFFECT) and the REAL selected-root R2 admission stack. The user
// completes the two separate clicks — explicit APPROVE, then explicit RUN —
// WITHOUT any manual console interaction: no reference is ever displayed,
// typed, pasted or transported by the browser; the effect POST body is
// exactly {caseId} and the trusted Host resolves the issued pair internally.
//
// REAL here: server routing, HostGuidedService, FolderSelectionHost, the
// durable SqliteHostSubmitReferenceLedger (issue + resolveCurrent + verify),
// the ActionController R2 route over the ShunStore AuthorizationAuthority
// (HMAC-signed grant), the executor authority-store writers and the Guided
// approval adapter.
//
// INJECTED (zero real effects, zero paid calls): the Windows folder picker
// native port (fake identity), the storage metadata walker and the selected-K
// facade (replays the exact admitted envelope without minting a Permit).
// The controlled DOM is the established t10-ui harness shape; the browser
// scripts and every projection module they import are the REAL shipped
// files, unmodified, loaded from apps/control-ui/public/v03.
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { ActionPlanSchema, type CurrentAuthorityState } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import { HostGuidedService } from '../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  FileGrantSource,
  resolveGrantHmacKeyFile,
  verifyGrantWithHmac,
  writeCurrentAuthority,
  writeGrantHmacKey,
  writeGrantRecord,
  writePlanRecord,
} from '../../../packages/executor-windows/src/trusted-store.ts';
import { DemoShunBackend } from '../src/demo/backend.ts';
import { createControlServer } from '../src/server.ts';
import { SqliteHostSubmitReferenceLedger } from '../src/v03/composition-approval.ts';
import { classifyJourneyKernelResult } from '../src/v03/composition-journeys.ts';
import { issueLiveStepSubmitReferences } from '../src/v03/composition-production.ts';
import { FolderSelectionHost } from '../src/v03/folder-selection-host.ts';
import {
  createGuidedReviewApprovalPort,
  createSelectedRootEffectSubmit,
  deriveSelectedRootEffect,
  type SelectedRootEffectAuthority,
  type SelectedRootEffectDescriptor,
} from '../src/v03/selected-root-effect-flow.ts';

const identity = { volumeSerial: '1a2b3c4d', fileId: '0123456789abcdef' };
const POLICY = 'shun.selected-root-effect.policy-v1';
const TASK = 'task-u06-e2e';
const JOURNEY = 'journey-u06-e2e';
const ISSUANCE_SECRET = 'issuance-secret-u06';
const INTEGRITY_SECRET = 'integrity-secret-u06';
const UI_BASE = new URL('../../../apps/control-ui/public/v03/', import.meta.url);

function evidence(root: string, now: number) {
  return {
    observedAt: new Date(now).toISOString(),
    roots: [root],
    directories: [
      {
        path: join(root, 'Documents'),
        bytes: 10,
        files: 1,
        lastModifiedMs: 1_700_000_000_000,
        inaccessibleEntries: [],
      },
    ],
    rootFiles: [{ path: join(root, 'root.txt'), bytes: 5 }],
    totalBytes: 15,
  };
}

class StubElement {
  children: StubElement[] = [];
  events: Record<string, (event?: unknown) => void> = {};
  attrs: Record<string, string> = {};
  dataset: Record<string, string> = {};
  tagName: string;
  id = '';
  className = '';
  value = '';
  textContent = '';
  hidden = false;
  disabled = false;
  checked = false;
  focused = false;
  type = '';
  name = '';
  htmlFor = '';
  required = false;
  maxLength = 256;
  autocomplete = '';
  dateTime = '';
  previousElementSibling: StubElement | null = null;
  classList = {
    add() {},
    remove() {},
    toggle() {},
    contains: () => false,
  };
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
  }
  append(...nodes: (StubElement | string)[]) {
    for (const node of nodes) this.children.push(node as StubElement);
  }
  replaceChildren(...nodes: StubElement[]) {
    this.children = nodes;
    this.textContent = '';
  }
  setAttribute(key: string, value: string) {
    this.attrs[key] = value;
  }
  removeAttribute(key: string) {
    delete this.attrs[key];
  }
  addEventListener(type: string, fn: (event?: unknown) => void) {
    this.events[type] = fn;
  }
  querySelector() {
    return null;
  }
  querySelectorAll() {
    return [];
  }
  focus() {
    this.focused = true;
  }
  blur() {}
  reportValidity() {
    return true;
  }
  click() {
    this.events.click?.();
  }
}

function findNode(node: StubElement, id: string): StubElement | undefined {
  if (node.id === id) return node;
  for (const child of node.children) {
    const hit = findNode(child, id);
    if (hit) return hit;
  }
  return undefined;
}

function allText(node: StubElement, into: string[]) {
  if (node.textContent) into.push(node.textContent);
  for (const child of node.children) allText(child, into);
}

async function waitFor(probe: () => boolean, deadlineMs = 10_000): Promise<void> {
  const start = Date.now();
  while (!probe()) {
    if (Date.now() - start > deadlineMs) throw new Error('E2E waitFor deadline exceeded');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe('U06 (#401) real desktop.js × real server selected-root journey (no-effect E2E)', () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup();
  });

  it('completes APPROVE click then RUN click with zero manual console interaction; the browser carries caseId only', async () => {
    // ---- REAL backend stack (same assembly as the production composition) --
    const directory = mkdtempSync(join(tmpdir(), 'shun-u06-e2e-'));
    const root = join(directory, 'selected-root');
    mkdirSync(root);
    mkdirSync(join(root, 'Documents'));
    writeFileSync(join(root, 'root.txt'), 'x');
    const clock = (): number => Date.now();
    const guided = new HostGuidedService(join(directory, 'guided.sqlite'), clock);
    const host = new FolderSelectionHost({
      guided,
      databaseFile: join(directory, 'folder-selection.sqlite'),
      clock,
      native: {
        pickFolder: async () => ({
          status: 'SELECTED' as const,
          path: root,
          displayName: 'Documents',
          identity,
        }),
        inspectFolder: () => ({
          ...identity,
          isDirectory: true,
          isReparsePoint: false,
          isNetworkPath: false,
          isVolumeRoot: false,
        }),
        acquireDirectoryLease: () => ({
          leaseId: 'a'.repeat(32),
          directory: {
            ...identity,
            isDirectory: true,
            isReparsePoint: false,
            isNetworkPath: false,
            isVolumeRoot: false,
          },
        }),
        verifyDirectoryLease: () => ({
          ...identity,
          isDirectory: true,
          isReparsePoint: false,
          isNetworkPath: false,
          isVolumeRoot: false,
        }),
        releaseDirectoryLease: () => {},
        directoryLeasePath: () => root,
      },
      storage: {
        resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
        observeStorage: async (scope) => evidence(scope.roots[0] as string, clock()),
      },
    });
    const references = new SqliteHostSubmitReferenceLedger(
      join(directory, 'submit-references.sqlite'),
      clock,
    );
    // The REAL guided journey up to the live REVIEW_EFFECT review step.
    const staged = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: TASK,
        journeyId: JOURNEY,
        sourceRef: 'host:obs:u06-e2e',
        revision: 'u06-e2e-r1',
        caseRef: { snapshotId: 'snap-u06-e2e', digest: 'd'.repeat(64) },
        observedAtUnixMs: clock() - 1_000,
        validUntilUnixMs: clock() + 3_600_000,
        evidenceRefs: ['host:scope:u06-e2e'],
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: TASK,
          goalContract: { taskId: TASK, objective: 'journal the selected folder metadata' },
          capabilityId: 'system.storage.diagnose_bounded_action',
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN' },
    });
    if (staged.status !== 'CURRENT') throw new Error(`staging failed: ${staged.code}`);
    const selected = await host.selectRoot();
    if (selected.status !== 'SELECTED') throw new Error('selection failed');
    const selectStep = guided.state().currentStep;
    if (!selectStep) throw new Error('select step missing');
    const answerOutcome = {
      schema: 'shun.guided.step-outcome.v1',
      journeyId: selectStep.journeyId,
      taskId: selectStep.taskId,
      stepId: selectStep.stepId,
      caseRef: selectStep.caseRef,
      event: 'USER_SUBMIT',
      source: 'USER',
      sourceRef: 'ui:u06-e2e',
      answers: [{ fieldId: 'selectedRoot', value: selected.selectionRef }],
      evidenceRefs: [],
      occurredAtUnixMs: clock(),
    };
    const answerRelay = {
      kind: 'USER_DECISION_RELAY',
      authorityClaimed: false,
      relayedVia: '/api',
      decision: 'ANSWER',
      humanApproval: false,
      stepId: selectStep.stepId,
      stepDigest: selectStep.templateRef.digest,
      caseRef: selectStep.caseRef,
      outcome: answerOutcome,
    };
    if (host.validateSelectionAnswer(answerRelay, selectStep) !== null) {
      throw new Error('selection answer refused');
    }
    const recorded = guided.decide(answerRelay);
    if (recorded.status !== 'RECORDED') throw new Error(`answer refused: ${recorded.code}`);
    const after = host.afterSelectionRecorded(answerRelay, selectStep, recorded);
    if (after.status !== 'RECORDED') throw new Error(`post-answer refused: ${after.code}`);
    const observed = await host.observeCurrentSelectedFolder();
    if (!observed.ok) throw new Error(`observation failed: ${observed.code}`);
    const previewStaged = host.stageReadOnlyPlanPreview();
    if (previewStaged.status !== 'STAGED') {
      throw new Error(`preview staging failed: ${previewStaged.code}`);
    }
    // Trusted process-side issuance for the LIVE review step (production
    // order: staging → issuance → human APPROVE). Values never leave the
    // process from here on.
    const issued = issueLiveStepSubmitReferences({
      state: () => guided.state(),
      references,
      now: clock,
    });
    if (issued.status !== 'ISSUED') throw new Error(`issuance refused: ${issued.code}`);

    // The REAL R2 authority stack.
    const authorityDir = join(directory, 'authority');
    const policyStore = new ShunStore({ file: join(directory, 'policy.sqlite') });
    const adapter = new ShunStoreAuthorizationAdapter(policyStore);
    const clockIso = (): string => new Date(clock()).toISOString();
    const authority = new AuthorizationAuthority({
      state: adapter,
      grants: adapter,
      integritySecret: INTEGRITY_SECRET,
      issuanceSecret: ISSUANCE_SECRET,
      clock: clockIso,
      newGrantId: () => `grant-${randomUUID()}`,
    });
    await adapter.compareAndSaveAuthorityRecord(
      {
        authorityId: 'shun.local.selected-root-effect',
        authorityRevision: 'r1',
        updatedAt: clockIso(),
        policyInitialized: true,
        priorAuthorityRevisions: [],
      },
      null,
    );
    await adapter.compareAndSavePolicySnapshot(
      {
        policySnapshotRevision: POLICY,
        status: 'ACTIVE',
        authorityId: 'shun.local.selected-root-effect',
        authorityRevision: 'r1',
        revokedGrantIds: [],
        priorRevisions: [],
        rules: [],
        riskGuards: [],
        updatedAt: clockIso(),
      },
      null,
    );
    writeGrantHmacKey(authorityDir, Buffer.from(INTEGRITY_SECRET, 'utf8').toString('base64'));
    const plansDir = join(authorityDir, 'plans');
    const grantsDir = join(authorityDir, 'grants');
    const sends: unknown[] = [];
    const facade = {
      send: async (payload: unknown) => {
        sends.push(payload);
        return {
          status: 'admitted',
          admitted: {
            effects: [
              {
                effectId: `turn:${TASK}:instance-1/effect/1`,
                disposition: 'executed',
                output: {
                  phase: 'terminal',
                  externalRef: 'effect-1',
                  outcome: {
                    ok: true,
                    output: {
                      actionId: 'windows-fs-write-selected-root-journal',
                      terminal: 'SUCCEEDED',
                      recoveryClassification: 'COMPLETED_VERIFIED',
                      postStateVerified: true,
                    },
                  },
                },
              },
            ],
          },
        };
      },
    };
    const effectAuthority: SelectedRootEffectAuthority = {
      async authorizePlan({ plan, expect }) {
        const controller = new ActionController({
          authority,
          policyState: adapter,
          approvals: createGuidedReviewApprovalPort({ guided, expect }),
          issuanceSecret: ISSUANCE_SECRET,
          clock: clockIso,
        });
        const authorized = await controller.authorizePlan({ plan });
        if (!authorized.ok) return authorized;
        return {
          ok: true,
          plan: authorized.authorization.plan,
          grants: authorized.authorization.grants,
        };
      },
      async readCurrentAuthority() {
        const state = await authority.currentAuthority();
        if (state.kind !== 'CURRENT') throw new Error('authority unresolved');
        return state;
      },
      policySnapshotRevision: () => POLICY,
      writePlanRecord: (plan) => writePlanRecord(plansDir, plan),
      writeGrantRecord: (grant) => writeGrantRecord(grantsDir, grant),
      writeCurrentAuthority: (state: CurrentAuthorityState) =>
        writeCurrentAuthority(authorityDir, state),
      hasPlanRecord: (planHash) => existsSync(join(plansDir, `${planHash}.json`)),
      hmacKeyCoherent: () =>
        readFileSync(resolveGrantHmacKeyFile(authorityDir), 'utf8').trim() ===
        Buffer.from(INTEGRITY_SECRET, 'utf8').toString('base64'),
    };
    const submit = createSelectedRootEffectSubmit({
      host,
      references,
      facade,
      classifyJourneyKernelResult,
      now: clock,
      authority: effectAuthority,
    });
    const proposal = ():
      | { ok: true; descriptor: SelectedRootEffectDescriptor }
      | { ok: false; code: string } => {
      const facts = host.readSelectedRootEffectFacts();
      if (facts.status !== 'CURRENT') return { ok: false, code: facts.code };
      const derived = deriveSelectedRootEffect({ facts: facts.facts });
      if (!derived.ok) return { ok: false, code: derived.code };
      return { ok: true, descriptor: derived.descriptor };
    };

    const server = createControlServer({
      backend: new DemoShunBackend(),
      v03Guided: guided,
      v03SelectedRootEffect: submit,
      v03SelectedRootEffectProposal: proposal,
    });
    const port = await server.start();
    cleanups.push(() => {
      void server.close();
      host.close();
      references.close();
      policyStore.close();
      guided.close();
      rmSync(directory, { recursive: true, force: true });
    });
    const origin = `http://127.0.0.1:${port}`;

    const post = async (path: string, body: unknown) => {
      const response = await fetch(origin + path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: await response.json().catch(() => undefined) };
    };

    // ---- Negative gate BEFORE the human approval --------------------------
    // The ordinary journey cannot execute anything before the durable human
    // APPROVE — the Host readback refuses with zero sends.
    const preApprove = await post('/api/v03/effect/selected-root', { caseId: TASK });
    expect(preApprove).toMatchObject({
      status: 422,
      body: { status: 'REFUSED', code: 'SELECTED_ROOT_EFFECT_APPROVAL_REQUIRED', sendCalls: 0 },
    });
    expect(sends).toHaveLength(0);

    // ---- Boot the REAL shipped desktop.js in the controlled DOM -----------
    const registry = new Map<string, StubElement>();
    const documentElement = new StubElement('html');
    const shell = new StubElement('div');
    shell.className = 'shell';
    const document = {
      documentElement,
      body: new StubElement('body'),
      // Like a real document: a lookup first resolves nodes the shipped UI
      // rendered (with their live state) into the container trees, and only
      // then falls back to creating the static shell elements.
      getElementById(id: string) {
        const known = registry.get(id);
        if (known) return known;
        for (const element of registry.values()) {
          const rendered = findNode(element, id);
          if (rendered) {
            registry.set(id, rendered);
            return rendered;
          }
        }
        const created = new StubElement('div');
        registry.set(id, created);
        return created;
      },
      createElement: (tag: string) => new StubElement(tag),
      createTextNode: (text: string) => {
        const node = new StubElement('#text');
        node.textContent = text;
        return node;
      },
      querySelector: (selector: string) => (selector === '.shell' ? shell : new StubElement()),
      querySelectorAll: () => [],
      addEventListener() {},
    };
    documentElement.dataset.theme = 'system';
    const captured: { url: string; method: string; body?: unknown }[] = [];
    const contextFetch = async (url: string, options?: { method?: string; body?: string }) => {
      captured.push({
        url,
        method: options?.method ?? 'GET',
        ...(options?.body !== undefined ? { body: safeJson(options.body) } : {}),
      });
      return fetch(new URL(url, origin), options);
    };
    const sessionStorage = {
      getItem: () => null,
      setItem() {},
    };
    const context: Record<string, unknown> = {
      document,
      fetch: contextFetch,
      navigator: { language: 'en-US' },
      sessionStorage,
      setTimeout,
      clearTimeout,
      Date,
      JSON,
      Promise,
      console: { log() {}, warn() {}, error() {} },
    };
    // Each shipped module runs in its own closure (real module semantics:
    // no cross-module top-level name collisions) and publishes exactly its
    // real export surface onto the context globals, which the stripped
    // import statements of the next modules bind to.
    const strip = (source: string): string =>
      source
        .replace(/^import .* from '\.\/[^']+';\s*$/gm, '')
        .replace(/^export (?=(const|let|var|function|class)\b)/gm, '');
    const load = (name: string, exports: readonly string[]): void => {
      const source = readFileSync(new URL(name, UI_BASE), 'utf8');
      const script = strip(source);
      if (/^import /m.test(script)) throw new Error(`Unexpected import in ${name}`);
      const wrapped = `(function(){\n${script}\nObject.assign(globalThis,{${exports.join(',')}});\n})();`;
      runInNewContext(wrapped, context, { timeout: 5_000 });
    };
    // Dependency order: the projection modules first (their real export
    // surfaces become context globals), then the REAL entrypoint.
    load('strings.js', ['t', 'tf']);
    context.approvedText = context.t;
    load('view-model.js', [
      'currentStepModel',
      'buildStepOutcome',
      'userDecisionRelay',
      'replayGuard',
      'progressModel',
    ]);
    load('desktop-approvals.js', [
      'realApprovalPosture',
      'projectPendingApprovals',
      'projectExactApproval',
      'projectApprovalDecision',
      'projectTaskSnapshots',
      'filterTaskSnapshots',
      'projectHostTaskDetail',
      'projectClarificationReceipt',
    ]);
    load('desktop-folder.js', ['projectFolderSelection', 'guidedReceiptStatus']);
    load('desktop-history.js', ['projectGuidedHistory']);
    load('desktop-observations.js', [
      'projectLocalObservation',
      'projectRoutineState',
      'projectRoutineExecution',
      'projectDisclosurePreview',
      'projectFolderObservation',
    ]);
    load('desktop.js', []);

    // Boot: refresh() pulls the real guided state and renders the live
    // REVIEW_EFFECT review step with the real Host proposal.
    const node = (id: string): StubElement => document.getElementById(id);
    const container = node('step-container');
    await waitFor(() => findNode(container, 'root-confirm') !== undefined);
    // The real descriptor (operation/relativeTarget) is rendered as text on
    // the detail node the shipped UI itself renders for the review step.
    const detailText = (): string => findNode(container, 'root-detail')?.textContent ?? '';
    await waitFor(() => detailText().includes('windows.fs.write'));
    expect(detailText()).toContain('shun-folder-journal.json');

    // No reference, grant or permit material ever reached the DOM.
    const rendered = (): string[] => {
      const texts: string[] = [];
      for (const element of registry.values()) allText(element, texts);
      allText(shell, texts);
      return texts;
    };
    const flat = rendered().join('\n');
    expect(flat).not.toContain('shun.currentness.v1');
    expect(flat).not.toContain('shun.approval.v1');

    // ---- CLICK 1: explicit human APPROVE ----------------------------------
    const checkbox = findNode(container, 'root-confirm');
    if (!checkbox) throw new Error('confirm checkbox missing');
    checkbox.checked = true;
    checkbox.events.change?.();
    // The CHOICE control is rendered into #form-fields (the real form
    // surface), not the review-detail container.
    const choice = node('field-continue');
    if (!choice) throw new Error('continue choice missing');
    choice.value = 'continue-to-independent-approval';
    choice.events.change?.();
    // The submit button only enables with proposal + choice + checkbox.
    await waitFor(() => node('step-submit').disabled === false);
    const approveClick = node('dynamic-form').events.submit;
    if (!approveClick) throw new Error('form submit listener missing');
    approveClick({ preventDefault: () => {} });
    await waitFor(() => node('root-effect-panel').hidden === false);
    await waitFor(() => node('root-effect-run').disabled === false);
    // The APPROVE decision travelled through the real guided ledger.
    expect(captured.some((entry) => entry.url === '/api/v03/guided/decision')).toBe(true);
    expect(guided.state().history.at(-1)?.status).toBe('ACCEPTED');

    // ---- CLICK 2: explicit RUN — no manual console interaction ------------
    const effectCalls = captured.filter((entry) => entry.url === '/api/v03/effect/selected-root');
    expect(effectCalls).toHaveLength(0);
    node('root-effect-run').click();
    await waitFor(() => node('root-effect-status').textContent.length > 0);
    // Truthful terminal outcome wording (Verified completed).
    expect(node('root-effect-status').textContent).toContain('Verified completed');
    // The browser's ONLY effect payload is the Case identity.
    const effect = captured.find((entry) => entry.url === '/api/v03/effect/selected-root');
    expect(effect).toBeDefined();
    expect(effect?.body).toEqual({ caseId: TASK });
    expect(JSON.stringify(effect?.body)).not.toContain('Ref');
    // The real R2 stack admitted exactly one K send and persisted the plan
    // and grant records the Windows effect Host would read at effect time.
    expect(sends).toHaveLength(1);
    const send = sends[0] as { input: { planRef: string; grantRef: string } };
    const planFile = join(authorityDir, 'plans', `${send.input.planRef}.json`);
    const grantFile = join(authorityDir, 'grants', `${send.input.grantRef}.json`);
    expect(existsSync(planFile)).toBe(true);
    expect(existsSync(grantFile)).toBe(true);
    expect(ActionPlanSchema.parse(JSON.parse(readFileSync(planFile, 'utf8'))).planHash).toBe(
      send.input.planRef,
    );
    expect(new FileGrantSource(grantsDir).byGrantId(send.input.grantRef)).toBeDefined();
    expect(
      verifyGrantWithHmac(
        readFileSync(resolveGrantHmacKeyFile(authorityDir), 'utf8').trim(),
        JSON.parse(readFileSync(grantFile, 'utf8')),
      ),
    ).toBe(true);

    // No physical effect: nothing was ever written outside the temp fixture.
    expect(existsSync(join(root, 'shun-folder-journal.json'))).toBe(false);

    // ---- Post-success negatives: no blind retry, no forged replay ---------
    // A second browser run click is refused client-side (one attempt only).
    expect(node('root-effect-run').disabled).toBe(true);
    // A replayed HTTP admission hits the durable plan-identity fence.
    const replay = await post('/api/v03/effect/selected-root', { caseId: TASK });
    expect(replay).toMatchObject({
      status: 422,
      body: { status: 'REFUSED', code: 'SELECTED_ROOT_EFFECT_REPLAY_REFUSED', sendCalls: 0 },
    });
    // Cross-Case identity refuses typed.
    const crossCase = await post('/api/v03/effect/selected-root', { caseId: 'task-other' });
    expect(crossCase).toMatchObject({
      status: 422,
      body: { status: 'REFUSED', code: 'HOST_CASE_NOT_CURRENT', sendCalls: 0 },
    });
    // Any caller-supplied reference strings (or other extra input) are
    // refused as malformed bodies — references are not part of the contract.
    for (const malformed of [
      {
        caseId: TASK,
        currentnessRef: 'shun.currentness.v1/forged',
        approvalRef: 'shun.approval.v1/forged',
      },
      { caseId: TASK, path: 'C:\\evil\\path.txt' },
      { currentnessRef: 'shun.currentness.v1/only' },
      {},
    ]) {
      const refused = await post('/api/v03/effect/selected-root', malformed);
      expect(refused).toMatchObject({
        status: 422,
        body: { status: 'REFUSED', code: 'GATEWAY_INPUT_INVALID', sendCalls: 0 },
      });
    }
    // Exactly one K send for the whole journey.
    expect(sends).toHaveLength(1);
  }, 30_000);
});

function safeJson(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}
