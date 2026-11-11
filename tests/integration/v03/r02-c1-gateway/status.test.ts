import { describe, expect, it } from 'vitest';
import { createControlApiGateway } from '../../../../packages/domain-app/src/api/gateway.ts';
import { createV03GatewayRoute } from '../../../../apps/control-api/src/v03/gateway-route.ts';

function submission() {
  return {
    caseId: 'case-r02-c1',
    request: {
      taskId: 'case-r02-c1',
      goal: 'Read selected scope',
      objects: [],
      constraints: {},
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    },
    currentnessRef: 'shun.currentness.v1/frozen-r02',
    approvalRef: 'shun.approval.v1/current-r02',
  };
}

const effect = (outcome: unknown) => ({
  status: 'admitted',
  admitted: { effects: [outcome] },
});

describe('R02-C1 K receipt truth — no SENT=success shortcut', () => {
  async function receipt(result: unknown) {
    const gateway = createControlApiGateway({ domainApp: { send: async () => result } });
    return gateway.submit(submission());
  }

  it('only recognizes explicit real K terminal success', async () => {
    const ok = await receipt(effect({
      disposition: 'executed',
      output: { phase: 'terminal', outcome: { ok: true, output: { verified: true } } },
    }));
    expect(ok).toMatchObject({ status: 'COMPLETED', sendCalls: 1 });
    expect(createV03GatewayRoute({ gateway: { submit: async () => ok } }).httpStatus(ok)).toBe(200);
  });

  it('refuses the false-positive resolved unknown, refused and ambiguous K envelopes', async () => {
    for (const [result, expectedStatus] of [
      [{ status: 'unknown' }, 'UNKNOWN'],
      [{ status: 'refused' }, 'KERNEL_REFUSED'],
      [{ status: 'admitted' }, 'UNKNOWN'],
      [{ status: 'admitted', admitted: {} }, 'UNKNOWN'],
      [effect({ disposition: 'executed', output: { phase: 'pending' } }), 'UNKNOWN'],
      [effect({ disposition: 'executed', output: { phase: 'terminal', outcome: { ok: null } } }), 'UNKNOWN'],
      [effect({ disposition: 'executed', output: { phase: 'terminal', outcome: { ok: false } } }), 'KERNEL_REFUSED'],
    ] as const) {
      const found = await receipt(result);
      expect(found.status).toBe(expectedStatus);
      expect(createV03GatewayRoute({ gateway: { submit: async () => found } }).httpStatus(found))
        .not.toBe(200);
    }
  });

  it('does not misrepresent a K admission with zero external effects as completion', async () => {
    const found = await receipt({ status: 'admitted', admitted: { effects: [] } });
    expect(found.status).toBe('ADMITTED');
    expect(createV03GatewayRoute({ gateway: { submit: async () => found } }).httpStatus(found)).toBe(202);
  });

  it('records may-have-sent on promise rejection, never claims zero journal', async () => {
    let sends = 0;
    const gateway = createControlApiGateway({
      domainApp: { send: async () => { sends++; throw new Error('sensitive backend detail'); } },
    });
    const found = await gateway.submit(submission());
    expect(found).toEqual({ status: 'UNKNOWN', code: 'SEND_OUTCOME_UNKNOWN', sendCalls: 1 });
    expect(sends).toBe(1);
  });

  it('rejects hostile shape before ANY K call', async () => {
    let sends = 0;
    const gateway = createControlApiGateway({
      domainApp: { send: async () => { sends++; return { status: 'admitted' }; } },
    });
    const found = await gateway.submit({ ...submission(), extra: 'untrusted' });
    expect(found).toMatchObject({ status: 'REFUSED', sendCalls: 0, journalEntries: 0 });
    expect(sends).toBe(0);
  });
});
