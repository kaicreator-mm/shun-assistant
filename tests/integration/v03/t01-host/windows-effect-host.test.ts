import { describe, expect, it, vi } from 'vitest';
import { createShunStoreStateAdapter } from '../../../../packages/domain-host/src/state/shun-store-state.ts';
import {
  createWindowsEffectHost,
  type KernelEffectDispatchContext,
  readKernelEffectPermit,
} from '../../../../packages/domain-host/src/windows/effect-host.ts';

const PLAN_HASH = 'a'.repeat(64);
const PAYLOAD = { actionRef: 'action-01', planRef: PLAN_HASH, grantRef: 'grant-01' };

function context(
  overrides: Partial<KernelEffectDispatchContext> = {},
): KernelEffectDispatchContext {
  return {
    capabilityId: 'cap.windows',
    operationId: 'windows.execute',
    effectPermit: {
      effectId: 'effect-01',
      durableControlTurnId: 'turn-01',
      attempt: 1,
    },
    ...overrides,
  };
}

function authorizationContext(effectId = 'effect-01') {
  return {
    effectId,
    plan: { taskId: 'task-01', planHash: PLAN_HASH },
    action: {
      taskId: 'task-01',
      actionId: 'action-01',
      planHash: PLAN_HASH,
      authorizationRef: 'grant-01',
    },
    grant: { grantId: 'grant-01', planHash: PLAN_HASH, taskId: 'task-01' },
  };
}

function harness(
  options: {
    osCurrent?: boolean;
    shunCurrent?: boolean;
    resolved?: unknown;
    receipt?: unknown;
    throwExecute?: boolean;
  } = {},
) {
  const order: string[] = [];
  const authorization = {
    resolve: vi.fn(async () => {
      order.push('resolve');
      // The trusted authorization storage holds exactly this effect-01
      // context; a permit claiming any other effectId must mismatch here.
      return options.resolved ?? authorizationContext();
    }),
  };
  const osAuthority = {
    recheck: vi.fn(async () => {
      order.push('os-currentness');
      return { ok: options.osCurrent ?? true };
    }),
  };
  const actionController = {
    authorizeEffect: vi.fn(async () => {
      order.push('shun-authorize');
      return { ok: options.shunCurrent ?? true };
    }),
  };
  const windows = {
    execute: vi.fn(async () => {
      order.push('windows-effect');
      if (options.throwExecute) throw new Error('private executor detail');
      return (
        options.receipt ?? {
          actionId: 'action-01',
          terminal: 'SUCCEEDED',
          sideEffectEvidence: {
            recoveryClassification: 'COMPLETED_VERIFIED',
            postStateVerified: true,
          },
        }
      );
    }),
  };
  const host = createWindowsEffectHost({
    binding: { capabilityId: 'cap.windows', operationId: 'windows.execute' },
    authorization,
    osAuthority,
    actionController,
    windows,
  });
  return { host, order, authorization, osAuthority, actionController, windows };
}

describe('T01 K-gated Windows Host authorization boundary', () => {
  it('requires a K dispatch context and refuses absent, malformed or mismatched permit claims with zero effect', async () => {
    const h = harness();
    expect(await h.host.dispatch(PAYLOAD, {})).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'K_PERMIT_REQUIRED' } },
    });
    expect(
      await h.host.dispatch(PAYLOAD, {
        capabilityId: 'cap.windows',
        operationId: 'windows.execute',
        effectPermit: { effectId: 'effect-01', durableControlTurnId: '', attempt: 1 },
      }),
    ).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'K_PERMIT_REQUIRED' } },
    });
    expect(
      await h.host.dispatch(
        PAYLOAD,
        context({
          effectPermit: { effectId: 'effect-other', durableControlTurnId: 'turn-01', attempt: 1 },
        }),
      ),
    ).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'SHUN_AUTHORIZATION_IDENTITY_MISMATCH' } },
    });
    expect(h.windows.execute).not.toHaveBeenCalled();
  });

  it('accepts the real selected-Kernel identifier grammar and still refuses hostile identities', async () => {
    // The real Kernel derives effectId as `${turnId}/effect/${ordinal}` with
    // turnId `turn:{workflowId}:{instanceKey}[:message:{id}|:child:...]`.
    const kernelTurnId = 'turn:wf-journey:instance-01:message:msg-9';
    const kernelEffectId = `${kernelTurnId}/effect/2`;
    const h = harness({ resolved: authorizationContext(kernelEffectId) });
    await expect(
      h.host.dispatch(
        PAYLOAD,
        context({
          effectPermit: {
            effectId: kernelEffectId,
            durableControlTurnId: kernelTurnId,
            attempt: 2,
          },
        }),
      ),
    ).resolves.toMatchObject({
      phase: 'terminal',
      outcome: { ok: true, output: { terminal: 'SUCCEEDED' } },
    });
    expect(h.windows.execute).toHaveBeenCalledTimes(1);

    for (const bad of [
      '../escape',
      'turn:..:x/effect/1',
      'turn:wf:inst/effect/1\\..\\escape',
      'turn:wf:inst/effect/1 with space',
      'turn:wf:inst/effect/1\n',
      `${'y'.repeat(129)}/effect/1`,
      '',
    ]) {
      expect(
        readKernelEffectPermit({
          capabilityId: 'cap.windows',
          operationId: 'windows.execute',
          effectPermit: { effectId: bad, durableControlTurnId: 'turn:wf:inst', attempt: 1 },
        }),
      ).toBeNull();
    }
    expect(
      readKernelEffectPermit({
        capabilityId: 'cap.windows',
        operationId: 'windows.execute',
        effectPermit: { effectId: kernelEffectId, durableControlTurnId: kernelTurnId, attempt: 2 },
      }),
    ).toMatchObject({ effectId: kernelEffectId, durableControlTurnId: kernelTurnId, attempt: 2 });

    const apply = vi.fn(async (effectId: string) => ({ effectId }));
    const adapter = createShunStoreStateAdapter(
      { apply, getEffectReceipt: async (effectId: string) => ({ effectId }) },
      { capabilityId: 'cap.windows', operationId: 'windows.execute' },
    );
    await expect(adapter.readBusinessReceipt(kernelEffectId)).resolves.toEqual({
      effectId: kernelEffectId,
    });
    await expect(adapter.readBusinessReceipt('../escape')).rejects.toThrow(
      'SHUN_STORE_EFFECT_ID_INVALID',
    );
  });

  it('binds capability, operation, effectId, plan, action and grant identity', async () => {
    const h = harness();
    expect(await h.host.dispatch(PAYLOAD, context({ operationId: 'windows.other' }))).toMatchObject(
      {
        phase: 'terminal',
        outcome: { ok: false, error: { code: 'K_BINDING_MISMATCH' } },
      },
    );
    const mismatch = harness({ resolved: authorizationContext('effect-other') });
    expect(await mismatch.host.dispatch(PAYLOAD, context())).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'SHUN_AUTHORIZATION_IDENTITY_MISMATCH' } },
    });
    expect(h.windows.execute).not.toHaveBeenCalled();
    expect(mismatch.windows.execute).not.toHaveBeenCalled();
  });

  it('rechecks OS authority then calls real ActionController immediately before the effect port', async () => {
    const h = harness();
    expect(await h.host.dispatch(PAYLOAD, context())).toMatchObject({
      phase: 'terminal',
      externalRef: 'effect-01',
      outcome: { ok: true, output: { actionId: 'action-01', postStateVerified: true } },
    });
    expect(h.order).toEqual(['resolve', 'os-currentness', 'shun-authorize', 'windows-effect']);
    expect(h.actionController.authorizeEffect).toHaveBeenCalledWith({
      plan: authorizationContext().plan,
      action: authorizationContext().action,
      grant: authorizationContext().grant,
    });
    expect(h.windows.execute).toHaveBeenCalledTimes(1);
    expect(h.windows.execute).toHaveBeenCalledWith({
      effectId: 'effect-01',
      action: authorizationContext().action,
    });
  });

  it('refuses when OS currentness or Shun grant currentness is unavailable/stale', async () => {
    const os = harness({ osCurrent: false });
    expect(await os.host.dispatch(PAYLOAD, context())).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'OS_AUTHORITY_REFUSED' } },
    });
    expect(os.actionController.authorizeEffect).not.toHaveBeenCalled();
    expect(os.windows.execute).not.toHaveBeenCalled();

    const shun = harness({ shunCurrent: false });
    expect(await shun.host.dispatch(PAYLOAD, context())).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'SHUN_AUTHORIZATION_REFUSED' } },
    });
    expect(shun.windows.execute).not.toHaveBeenCalled();
  });

  it('keeps ambiguous execution outcomes non-terminal for K UNKNOWN/fence reconciliation', async () => {
    const thrown = harness({ throwExecute: true });
    expect(await thrown.host.dispatch(PAYLOAD, context())).toEqual({
      phase: 'running',
      externalRef: 'effect-01',
    });
    const unverified = harness({
      receipt: {
        actionId: 'action-01',
        terminal: 'SUCCEEDED',
        sideEffectEvidence: {
          recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
          postStateVerified: false,
        },
      },
    });
    expect(await unverified.host.dispatch(PAYLOAD, context())).toEqual({
      phase: 'running',
      externalRef: 'effect-01',
    });
    expect(thrown.windows.execute).toHaveBeenCalledTimes(1);
    expect(unverified.windows.execute).toHaveBeenCalledTimes(1);
  });

  it('exposes no legacy workflow dispatcher or journal dependency on the Host adapter', () => {
    const h = harness();
    expect(Object.keys(h.host)).toEqual(['dispatch']);
    expect('dispatchAction' in h.host).toBe(false);
    expect('journal' in h.host).toBe(false);
  });

  it('snapshots privileged callbacks at construction against getter-backed replacement', async () => {
    let hostile = false;
    const resolveCalls = vi.fn(async () => authorizationContext());
    const osRecheck = vi.fn(async () => ({ ok: true }));
    const shunAuthorize = vi.fn(async () => ({ ok: true }));
    const execute = vi.fn(async () => ({
      actionId: 'action-01',
      terminal: 'SUCCEEDED',
      sideEffectEvidence: { recoveryClassification: 'COMPLETED_VERIFIED', postStateVerified: true },
    }));
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'cap.windows', operationId: 'windows.execute' },
      authorization: {
        get resolve() {
          if (hostile) return async () => authorizationContext('effect-evil');
          return resolveCalls;
        },
      },
      osAuthority: { recheck: osRecheck },
      actionController: { authorizeEffect: shunAuthorize },
      windows: { execute },
    });
    hostile = true;
    await expect(host.dispatch(PAYLOAD, context())).resolves.toMatchObject({
      phase: 'terminal',
      outcome: { ok: true, output: { terminal: 'SUCCEEDED' } },
    });
    expect(resolveCalls).toHaveBeenCalledTimes(1);
    expect(osRecheck).toHaveBeenCalledTimes(1);
    expect(shunAuthorize).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it('refuses post-construction replacement of the binding or the final effect port', async () => {
    const h = harness();
    const executeSpy = h.windows.execute;
    const binding = { capabilityId: 'cap.windows', operationId: 'windows.execute' };
    const mutatingHost = createWindowsEffectHost({
      binding,
      authorization: h.authorization,
      osAuthority: h.osAuthority,
      actionController: h.actionController,
      windows: h.windows,
    });
    binding.capabilityId = 'cap.evil';
    (h.windows as { execute: unknown }).execute = async () => ({
      actionId: 'action-01',
      terminal: 'SUCCEEDED',
      sideEffectEvidence: { recoveryClassification: 'COMPLETED_VERIFIED', postStateVerified: true },
    });
    await expect(mutatingHost.dispatch(PAYLOAD, context())).resolves.toMatchObject({
      phase: 'terminal',
      outcome: { ok: true, output: { terminal: 'SUCCEEDED' } },
    });
    await expect(
      mutatingHost.dispatch(PAYLOAD, context({ capabilityId: 'cap.evil' })),
    ).resolves.toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'K_BINDING_MISMATCH' } },
    });
    expect(executeSpy).toHaveBeenCalledTimes(1);
  });
});

describe('T01 ShunStore business state adapter', () => {
  it('uses the same K effectId for transactional ShunStore apply and receipt readback', async () => {
    const calls: unknown[][] = [];
    const store = {
      apply: vi.fn(async (effectId: string, mutation: unknown) => {
        calls.push([effectId, mutation]);
        return {
          effectId,
          applied: calls.length === 1,
          receiptRef: 'shunstore://effect/effect-01',
        };
      }),
      getEffectReceipt: vi.fn(async (effectId: string) => ({ effectId })),
    };
    const adapter = createShunStoreStateAdapter(store, {
      capabilityId: 'cap.windows',
      operationId: 'windows.execute',
    });
    const mutation = { recordKind: 'case', recordId: 'case-01', payload: { state: 'ready' } };
    await adapter.applyBusinessMutation(context(), mutation);
    await adapter.applyBusinessMutation(context(), mutation);
    expect(calls).toEqual([
      ['effect-01', mutation],
      ['effect-01', mutation],
    ]);
    await expect(adapter.readBusinessReceipt('effect-01')).resolves.toEqual({
      effectId: 'effect-01',
    });
    await expect(adapter.applyBusinessMutation({}, mutation)).rejects.toThrow('K_PERMIT_REQUIRED');
    await expect(
      adapter.applyBusinessMutation(context({ operationId: 'windows.other' }), mutation),
    ).rejects.toThrow('K_PERMIT_REQUIRED');
  });

  it('snapshots store methods and binding at construction against later mutation', async () => {
    const apply = vi.fn(async (effectId: string) => ({ effectId }));
    const getEffectReceipt = vi.fn(async (effectId: string) => ({ effectId }));
    const store = { apply, getEffectReceipt };
    const binding = { capabilityId: 'cap.windows', operationId: 'windows.execute' };
    const adapter = createShunStoreStateAdapter(store, binding);
    (store as { apply: unknown }).apply = async () => {
      throw new Error('swapped store');
    };
    binding.operationId = 'windows.evil';
    const mutation = { recordKind: 'case', recordId: 'case-01', payload: { state: 'ready' } };
    await expect(adapter.applyBusinessMutation(context(), mutation)).resolves.toEqual({
      effectId: 'effect-01',
    });
    expect(apply).toHaveBeenCalledTimes(1);
    await expect(
      adapter.applyBusinessMutation(context({ operationId: 'windows.evil' }), mutation),
    ).rejects.toThrow('K_PERMIT_REQUIRED');
    await expect(adapter.applyBusinessMutation(context(), mutation)).resolves.toEqual({
      effectId: 'effect-01',
    });
  });
});
