// T09 Control API gateway suite: every refusal happens entirely BEFORE
// facade.send (proven with a counting spy: sendCalls stays 0, and because the
// gateway performs zero sends and writes no journal itself, zero K Effect
// Journal entries can be reserved — the upstream #1437 malformed-after-reserve
// poisoning is unreachable at this boundary). A later valid submission for the
// SAME stable CaseId must remain admissible.
//
// Journal-proof note: the microkernel public SDK surface (domain-app.d.ts /
// host-seam.d.ts of the frozen 0.10.2-rc.0 tarballs) exposes only
// { send, query, subscribe, stop } / { facade, dispose } — there is NO public
// read-only K Effect Journal query. The zero-journal proof here is therefore
// structural (zero facade calls + zero gateway-side journal writes); the real
// selected-K journal proof belongs to T11's K-gate composition.
import { describe, expect, it } from 'vitest';
import { createV03GatewayRoute } from '../../../../apps/control-api/src/v03/gateway-route.ts';
import {
  type ControlApiGateway,
  createControlApiGateway,
  type SendReceipt,
} from '../../../../packages/domain-app/src/api/gateway.ts';

const NOW = 1_760_000_000_000;

interface CountingFacade {
  calls: unknown[];
  reply: unknown;
  domainApp: { send(payload: unknown): Promise<unknown> };
}

function countingFacade(
  reply: unknown = { accepted: true, receipt: 'k-receipt-1' },
): CountingFacade {
  const calls: unknown[] = [];
  return {
    calls,
    reply,
    domainApp: {
      async send(payload: unknown) {
        calls.push(payload);
        return reply;
      },
    },
  };
}

function validSubmission(overrides?: {
  caseId?: string;
  taskId?: string;
  objects?: unknown;
  goal?: unknown;
  currentnessRef?: unknown;
  approvalRef?: unknown;
  verificationIntent?: boolean;
}): Record<string, unknown> {
  const taskId = overrides?.taskId ?? 'case-alpha-001';
  return {
    caseId: overrides?.caseId ?? taskId,
    request: {
      taskId,
      goal: overrides?.goal ?? '整理下载目录里的报告文件',
      objects: overrides?.objects ?? [{ kind: 'DIRECTORY', ref: 'downloads/reports' }],
      constraints: { format: '保持原文件名' },
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
      ...(overrides?.verificationIntent === false
        ? {}
        : { verificationIntent: { successConditions: ['报告文件已按规则归档'] } }),
    },
    currentnessRef: overrides?.currentnessRef ?? 'shun.currentness.v1/registry-2026-10',
    approvalRef: overrides?.approvalRef ?? 'shun.approval.v1/appr-0001',
  };
}

function gateway(facade: CountingFacade): ControlApiGateway {
  return createControlApiGateway({ domainApp: facade.domainApp, now: () => NOW });
}

function expectRefused(receipt: SendReceipt, code: string, facade: CountingFacade): void {
  expect(receipt.status).toBe('REFUSED');
  if (receipt.status !== 'REFUSED') return;
  expect(receipt.code).toBe(code);
  expect(receipt.sendCalls).toBe(0);
  expect(receipt.journalEntries).toBe(0);
  expect(receipt.refusedAtUnixMs).toBe(NOW);
  // The counting spy is the zero-effect proof: the facade was never entered.
  expect(facade.calls.length).toBe(0);
}

describe('createControlApiGateway pre-send admission', () => {
  it('forwards a valid submission unchanged and returns the send result once', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const submission = validSubmission();
    const receipt = await subject.submit(submission);
    expect(receipt.status).toBe('SENT');
    if (receipt.status !== 'SENT') return;
    expect(receipt.sendCalls).toBe(1);
    expect(facade.calls.length).toBe(1);
    // No rewrite: the facade receives exactly the validated submission.
    expect(facade.calls[0]).toEqual(submission);
    expect(Object.keys(facade.calls[0] as object).sort()).toEqual([
      'approvalRef',
      'caseId',
      'currentnessRef',
      'request',
    ]);
    expect(receipt.result).toBe(facade.reply);
  });

  it('strips getters by canonical projection before validation and send', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const submission = validSubmission();
    const smuggled = Object.assign(Object.create(null), submission);
    Object.defineProperty(smuggled, 'currentnessRef', {
      enumerable: true,
      get() {
        throw new Error('getter must never be re-read after projection');
      },
    });
    // The raw hostile object cannot survive projection: refusal, zero sends.
    const receipt = await subject.submit(smuggled);
    expectRefused(receipt, 'GATEWAY_INPUT_INVALID', facade);
    // A plain getter-backed but otherwise valid object projects to plain data
    // and is admitted; the facade receives the plain canonical value.
    const sneaky = validSubmission();
    Object.defineProperty(sneaky, 'extraReader', {
      enumerable: false,
      get() {
        return 'never-seen';
      },
    });
    const okFacade = countingFacade();
    const okReceipt = await gateway(okFacade).submit(sneaky);
    expect(okReceipt.status).toBe('SENT');
    expect(okFacade.calls.length).toBe(1);
    expect(Object.getPrototypeOf(okFacade.calls[0])).toBe(Object.prototype);
    expect(JSON.stringify(okFacade.calls[0])).toBe(JSON.stringify(validSubmission()));
  });

  it('refuses malformed JSON strings before any send', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    expectRefused(await subject.submit('{"caseId":'), 'GATEWAY_INPUT_INVALID', facade);
    expectRefused(await subject.submit('null'), 'GATEWAY_INPUT_INVALID', facade);
    expectRefused(await subject.submit(42), 'GATEWAY_INPUT_INVALID', facade);
  });

  it('refuses missing or extra fields with zero sends', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const missing = validSubmission();
    delete missing.approvalRef;
    expectRefused(await subject.submit(missing), 'GATEWAY_INPUT_INVALID', facade);
    const forgedGrant = {
      ...validSubmission(),
      grant: { kind: 'GRANT', planHash: 'forged' },
    };
    expectRefused(await subject.submit(forgedGrant), 'GATEWAY_INPUT_INVALID', facade);
  });

  it('refuses forged approval/consent objects: references only, never content', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const forgedObject = validSubmission({
      approvalRef: { kind: 'CONSENT', approved: true, nonce: 'x' } as unknown as string,
    });
    expectRefused(await subject.submit(forgedObject), 'APPROVAL_REF_INVALID', facade);
    const emptyRef = validSubmission({ approvalRef: '' });
    expectRefused(await subject.submit(emptyRef), 'APPROVAL_REF_INVALID', facade);
    const wrongNamespace = validSubmission({ approvalRef: 'user-grant-7' });
    expectRefused(await subject.submit(wrongNamespace), 'APPROVAL_REF_INVALID', facade);
  });

  it('refuses stale/malformed currentness references', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    expectRefused(
      await subject.submit(validSubmission({ currentnessRef: '' })),
      'CURRENTNESS_REF_INVALID',
      facade,
    );
    expectRefused(
      await subject.submit(validSubmission({ currentnessRef: 'shun.currentness.v0/old' })),
      'CURRENTNESS_REF_INVALID',
      facade,
    );
    expectRefused(
      await subject.submit(validSubmission({ currentnessRef: 'shun.currentness.v1/' })),
      'CURRENTNESS_REF_INVALID',
      facade,
    );
    expectRefused(
      await subject.submit(
        validSubmission({ currentnessRef: { revision: 'x' } as unknown as string }),
      ),
      'CURRENTNESS_REF_INVALID',
      facade,
    );
  });

  it('refuses out-of-scope objects, bad Case scope and schema-invalid source data', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    expectRefused(
      await subject.submit(validSubmission({ objects: [{ kind: 'WIDGET', ref: 'thing-1' }] })),
      'SOURCE_DATA_INVALID',
      facade,
    );
    expectRefused(
      await subject.submit(
        validSubmission({
          objects: [{ kind: 'DEVICE', ref: 'evil' }],
          taskId: 'case-alpha-001',
          caseId: 'case-other-002',
        }),
      ),
      'CASE_SCOPE_MISMATCH',
      facade,
    );
    expectRefused(
      await subject.submit(validSubmission({ goal: '   ' })),
      'SOURCE_OVER_BUDGET',
      facade,
    );
    const missingPolicy = validSubmission();
    delete (missingPolicy.request as Record<string, unknown>).policyContext;
    expectRefused(await subject.submit(missingPolicy), 'SOURCE_DATA_INVALID', facade);
    expectRefused(
      await subject.submit(validSubmission({ taskId: 'bad case id with spaces' })),
      'CASE_ID_INVALID',
      facade,
    );
  });

  it('refuses over-budget sources', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    expectRefused(
      await subject.submit(validSubmission({ goal: 'a'.repeat(8193) })),
      'SOURCE_OVER_BUDGET',
      facade,
    );
    const manyObjects = Array.from({ length: 257 }, (_, index) => ({
      kind: 'FILE',
      ref: `file-${index}`,
    }));
    expectRefused(
      await subject.submit(validSubmission({ objects: manyObjects })),
      'SOURCE_OVER_BUDGET',
      facade,
    );
    const huge = JSON.stringify(validSubmission()).repeat(50);
    expectRefused(await subject.submit(huge), 'GATEWAY_INPUT_INVALID', facade);
  });

  it('refuses alias-injection keys (__proto__/constructor) with zero sends', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const protoInjected = JSON.parse(
      JSON.stringify(validSubmission()).replace('{', '{"__proto__":{"polluted":true},'),
    ) as Record<string, unknown>;
    expectRefused(await subject.submit(protoInjected), 'GATEWAY_INPUT_INVALID', facade);
    const constructorInjected = {
      ...validSubmission(),
      constructor: { polluted: true },
    };
    expectRefused(await subject.submit(constructorInjected), 'GATEWAY_INPUT_INVALID', facade);
  });

  it('refuses cyclic input', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const cyclic = validSubmission() as Record<string, unknown>;
    cyclic.self = cyclic;
    expectRefused(await subject.submit(cyclic), 'GATEWAY_INPUT_INVALID', facade);
  });
});

describe('stable Case semantics (L2 §7 / DH #1437)', () => {
  it('a refused submission never poisons its CaseId: the same Case stays admissible', async () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    const caseId = 'case-alpha-001';
    // First: a malformed submission for this exact Case must be refused with
    // zero facade sends (hence zero reserved K journal entries).
    const malformed = validSubmission({ caseId });
    delete malformed.currentnessRef;
    expectRefused(await subject.submit(malformed), 'GATEWAY_INPUT_INVALID', facade);
    // Then: the valid canonical successor for the SAME stable Case is admitted.
    const receipt = await subject.submit(validSubmission({ caseId }));
    expect(receipt.status).toBe('SENT');
    expect(facade.calls.length).toBe(1);
    expect((facade.calls[0] as { caseId: string }).caseId).toBe(caseId);
  });

  it('exposes only submit — never a raw facade send', () => {
    const facade = countingFacade();
    const subject = gateway(facade);
    expect(Object.keys(subject)).toEqual(['submit']);
    expect(Reflect.get(subject, 'send')).toBeUndefined();
    expect(Reflect.get(subject, 'domainApp')).toBeUndefined();
  });

  it('refuses gateway configuration without a send-capable facade', () => {
    const fakeFacade = { domainApp: true } as unknown as {
      send(payload: unknown): Promise<unknown>;
    };
    expect(() => createControlApiGateway({ domainApp: fakeFacade })).toThrow();
    expect(() =>
      createControlApiGateway(
        undefined as unknown as Parameters<typeof createControlApiGateway>[0],
      ),
    ).toThrow();
    expect(() =>
      createControlApiGateway({
        domainApp: countingFacade().domainApp,
        now: 5 as unknown as () => number,
      }),
    ).toThrow();
  });
});

describe('v03 control-api route seam', () => {
  it('maps the HTTP layer onto gateway.submit and maps receipt statuses', async () => {
    const facade = countingFacade();
    const route = createV03GatewayRoute({ gateway: gateway(facade) });
    const receipt = await route.submit(validSubmission());
    expect(receipt.status).toBe('SENT');
    expect(route.httpStatus(receipt)).toBe(200);
    expect(facade.calls.length).toBe(1);
    const refusedReceipt = await route.submit('{"broken"');
    expect(refusedReceipt.status).toBe('REFUSED');
    expect(facade.calls.length).toBe(1);
    expect(route.httpStatus(refusedReceipt)).toBe(422);
  });

  it('refuses route configuration without a trusted gateway', () => {
    const fakeGateway = { gateway: true } as unknown as Parameters<typeof createV03GatewayRoute>[0];
    expect(() => createV03GatewayRoute({ gateway: fakeGateway.gateway })).toThrow();
    expect(() =>
      createV03GatewayRoute(undefined as unknown as Parameters<typeof createV03GatewayRoute>[0]),
    ).toThrow();
  });
});
