// T11 Commit B — the three Shun package public entries exist as controlled,
// side-effect-free exits, and the v0.3 gateway route (T09 seam) is wired into
// the Control API server behind the trusted composition-only option.
//
// The facade here is a fake: this file proves the SERVER ADMISSION wiring
// (one gateway.submit per request, zero send on refusal, lazy factory),
// not the real DomainHarness journey — that real K proof lives in the
// real-kernel-permit suite of this same directory.
import { describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import {
  createControlApiGateway,
  type DomainAppSendFacade,
} from '../../../../packages/domain-app/src/api/gateway.ts';

function goalRequest(taskId = 'case-v03-01') {
  return {
    taskId,
    goal: 'Summarize the selected folder contents.',
    objects: [],
    constraints: {},
    policyContext: {
      privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    },
  };
}

function validSubmission() {
  return {
    caseId: 'case-v03-01',
    request: goalRequest(),
    currentnessRef: 'shun.currentness.v1/registry-t11',
    approvalRef: 'shun.approval.v1/operator-local-01',
  };
}

function fakeFacade(): DomainAppSendFacade & { calls: () => number; payloads: unknown[] } {
  const payloads: unknown[] = [];
  let calls = 0;
  return {
    async send(payload: unknown) {
      calls += 1;
      payloads.push(payload);
      return { status: 'admitted', admitted: { effects: [] } };
    },
    calls: () => calls,
    payloads,
  };
}

async function post(
  port: number,
  path: string,
  body: unknown,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => undefined) };
}

describe('T11 v0.3 gateway route is wired into the Control API server', () => {
  it('admits a valid submission through exactly one gateway.send', async () => {
    const facade = fakeFacade();
    const server = createControlServer({
      backend: new DemoShunBackend(),
      v03Gateway: createControlApiGateway({ domainApp: facade }),
    });
    const port = await server.start();
    try {
      const sent = await post(port, '/api/v03/gateway/submit', validSubmission());
      expect(sent.status).toBe(202);
      expect(sent.body).toMatchObject({ status: 'ADMITTED', sendCalls: 1 });
      expect(facade.calls()).toBe(1);
      // The facade receives EXACTLY the validated canonical submission.
      expect(facade.payloads[0]).toMatchObject({
        caseId: 'case-v03-01',
        currentnessRef: 'shun.currentness.v1/registry-t11',
        approvalRef: 'shun.approval.v1/operator-local-01',
      });
    } finally {
      await server.close();
    }
  });

  it('refuses malformed submissions with zero send calls (pre-send admission)', async () => {
    const facade = fakeFacade();
    const server = createControlServer({
      backend: new DemoShunBackend(),
      v03Gateway: createControlApiGateway({ domainApp: facade }),
    });
    const port = await server.start();
    try {
      for (const body of [
        { ...validSubmission(), extra: 1 },
        { ...validSubmission(), caseId: 'mismatched-case' },
        { caseId: 'case-v03-01', request: goalRequest() },
        { ...validSubmission(), approvalRef: { forged: 'object-not-a-reference' } },
        { ...validSubmission(), currentnessRef: 'not-a-trusted-reference' },
      ]) {
        const refused = await post(port, '/api/v03/gateway/submit', body);
        expect(refused.status).toBe(422);
        expect((refused.body as { status: string }).status).toBe('REFUSED');
        expect((refused.body as { sendCalls: number }).sendCalls).toBe(0);
        expect((refused.body as { journalEntries: number }).journalEntries).toBe(0);
      }
      expect(facade.calls()).toBe(0);
    } finally {
      await server.close();
    }
  });

  it('resolves the lazy gateway factory at most once, only on first submission', async () => {
    const facade = fakeFacade();
    let factoryCalls = 0;
    const server = createControlServer({
      backend: new DemoShunBackend(),
      v03Gateway: () => {
        factoryCalls += 1;
        return createControlApiGateway({ domainApp: facade });
      },
    });
    const port = await server.start();
    try {
      // Starting the server (and hitting other routes) never pays for the
      // DomainHarness composition.
      const health = await fetch(`http://127.0.0.1:${port}/api/health`);
      expect(health.status).toBe(200);
      expect(factoryCalls).toBe(0);
      const first = await post(port, '/api/v03/gateway/submit', validSubmission());
      expect(first.status).toBe(202);
      expect(factoryCalls).toBe(1);
      const second = await post(port, '/api/v03/gateway/submit', validSubmission());
      expect(second.status).toBe(202);
      expect(factoryCalls).toBe(1);
    } finally {
      await server.close();
    }
  });

  it('answers typed V03_GATEWAY_UNAVAILABLE when no gateway was composed', async () => {
    const server = createControlServer({ backend: new DemoShunBackend() });
    const port = await server.start();
    try {
      const unavailable = await post(port, '/api/v03/gateway/submit', validSubmission());
      expect(unavailable.status).toBe(503);
      expect(unavailable.body).toEqual({ ok: false, code: 'V03_GATEWAY_UNAVAILABLE' });
    } finally {
      await server.close();
    }
  });
});

describe('T11 package public entries are side-effect-free controlled exits', () => {
  it('domain-app exports the T09 composition and gateway adapters', async () => {
    const app = await import('../../../../packages/domain-app/src/index.ts');
    expect(typeof app.composeDomainBuild).toBe('function');
    expect(typeof app.createControlApiGateway).toBe('function');
    expect(app.V03_TRUSTED_CLOUD_INTERPRETER_PORT).toBe('shun.trusted-cloud-interpreter.v03');
    expect(app.V03_EXTERNAL_IMPORT_BINDINGS).toEqual({
      'domain-harness-openai-host': 'shun.trusted-cloud-interpreter.v03',
    });
  });

  it('domain-computer exports every merged task adapter factory', async () => {
    const computer = await import('../../../../packages/domain-computer/src/index.ts');
    for (const name of [
      'selectGoalSemantic',
      'issueHostObjectObservation',
      'createNextGuidedStep',
      'validateGuidedStepOutcome',
      'validateGuidedAdvisory',
      'APPROVED_STEP_TEMPLATES',
      'createMetaFeedbackAdapter',
      'createProviderJitBusinessAdapter',
      'DomainComputerRecipeReplayAdapter',
      'createComputerFolderObservationAdapter',
      'collectLocalComputerSupportContext',
      'buildNeutralGoalRequest',
      'selectedCAdapterSeam',
    ]) {
      expect(typeof (computer as Record<string, unknown>)[name]).toBe(
        name === 'APPROVED_STEP_TEMPLATES' ? 'object' : 'function',
      );
    }
  });

  it('domain-host exports the T01/T04/T08 Host seams without side effects', async () => {
    const host = await import('../../../../packages/domain-host/src/index.ts');
    for (const name of [
      'createTrustedCloudHostBinding',
      'installTrustedCloudHostBinding',
      'MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS',
      'createWindowsEffectHost',
      'readKernelEffectPermit',
      'createShunStoreStateAdapter',
      'createTrustedProviderHost',
    ]) {
      expect(typeof (host as Record<string, unknown>)[name]).toBe(
        name === 'MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS' ? 'number' : 'function',
      );
    }
    expect(host.MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS).toBe(20_000);
  });
});
