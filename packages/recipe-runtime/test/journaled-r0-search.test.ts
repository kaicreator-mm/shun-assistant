import { type AuthorizedAction, AuthorizedActionSchema } from '@shun/contracts';
import { describe, expect, it, vi } from 'vitest';
import {
  JournaledR0SearchCapability,
  type R0SearchJournalPort,
} from '../src/journaled-r0-search.ts';

function action(): AuthorizedAction {
  return AuthorizedActionSchema.parse({
    taskId: 'task-1',
    actionId: 'search-1',
    planHash: 'b'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'issued-grant-1',
    action: {
      actionId: 'search-1',
      bindingRef: 'binding-1',
      op: 'file.search',
      parameters: { root: 'C:/safe', query: '*.txt' },
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      filesystemScope: { read: ['C:/safe'], write: [] },
    },
  });
}

function receipt() {
  return {
    actionId: 'search-1',
    environmentId: 'test-windows',
    providerId: 'host-native-port',
    providerVersion: 'test-only',
    startedAt: '2026-10-23T00:00:00.000Z',
    finishedAt: '2026-10-23T00:00:00.001Z',
    terminal: 'SUCCEEDED',
    outputRefs: [],
    sideEffectEvidence: {
      sideEffectClass: 'R0',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    },
  };
}

function journal(): {
  port: R0SearchJournalPort;
  reserve: ReturnType<typeof vi.fn>;
  record: ReturnType<typeof vi.fn>;
} {
  const reserve = vi.fn(() => ({ ok: true }));
  const record = vi.fn(() => true);
  return {
    port: { reserve, recordObservation: record },
    reserve,
    record,
  };
}

describe('T04 private R0 journal-before-native-effect (synthetic effect)', () => {
  it('reserves before one post-state verified host effect without minting semantic Task PASS', async () => {
    const j = journal();
    const calls: string[] = [];
    j.reserve.mockImplementation(() => {
      calls.push('RESERVED');
      return { ok: true };
    });
    const effect = vi.fn(async () => {
      calls.push('EFFECT');
      return receipt();
    });
    const capability = new JournaledR0SearchCapability({ journal: j.port, effect });
    const result = await capability.execute(action());
    expect(calls).toEqual(['RESERVED', 'EFFECT']);
    expect(effect).toHaveBeenCalledTimes(1);
    expect(j.record).toHaveBeenCalledWith(
      expect.anything(),
      'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
      expect.stringMatching(/^[0-9a-f]{64}$/),
    );
    expect(result).toMatchObject({
      terminal: 'SUCCEEDED',
      sideEffectEvidence: { postStateVerified: true, recoveryClassification: 'COMPLETED_VERIFIED' },
    });
  });

  it('duplicate reservation and unauthorized privilege never invoke a host effect', async () => {
    const j = journal();
    j.reserve.mockReturnValue({ ok: false });
    const effect = vi.fn(async () => receipt());
    const capability = new JournaledR0SearchCapability({ journal: j.port, effect });
    await expect(capability.execute(action())).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
    await expect(
      capability.execute({
        ...action(),
        action: { ...action().action, requiredPrivilege: 'ELEVATED' },
      }),
    ).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
    expect(j.reserve).toHaveBeenCalledTimes(1);
    expect(effect).not.toHaveBeenCalled();
  });

  it('records uncertainty and rejects an effect throw, invalid receipt and fake semantic proof', async () => {
    const j = journal();
    let result: unknown = new Error('private C:/secret');
    const effect = vi.fn(async () => {
      if (result instanceof Error) throw result;
      return result;
    });
    const capability = new JournaledR0SearchCapability({ journal: j.port, effect });
    await expect(capability.execute(action())).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
    expect(j.record).toHaveBeenCalledWith(action(), 'UNCERTAIN', expect.any(String));
    j.record.mockClear();
    result = { terminal: 'SUCCEEDED' };
    await expect(capability.execute(action())).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
    expect(j.record).toHaveBeenCalledTimes(1);
    result = {
      ...receipt(),
      sideEffectEvidence: {
        ...receipt().sideEffectEvidence,
        postStateVerified: false,
        recoveryClassification: 'COMPLETED_VERIFIED',
      },
    };
    await expect(capability.execute(action())).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
    expect(effect).toHaveBeenCalledTimes(3);
  });


  it.each([
    'NOT_STARTED',
    'FAILED_BEFORE_EFFECT',
    'MAY_HAVE_EXECUTED_UNCERTAIN',
  ] as const)(
    'rejects contradictory or uncertain SUCCEEDED + %s with zero positive observations',
    async (classification) => {
      const j = journal();
      const effect = vi.fn(async () => ({
        ...receipt(),
        sideEffectEvidence: {
          sideEffectClass: 'R0',
          postStateVerified: false,
          recoveryClassification: classification,
        },
      }));
      const capability = new JournaledR0SearchCapability({ journal: j.port, effect });
      await expect(capability.execute(action())).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
      expect(effect).toHaveBeenCalledTimes(1);
      expect(j.record).toHaveBeenCalledTimes(1);
      expect(j.record).toHaveBeenCalledWith(action(), 'UNCERTAIN', expect.stringMatching(/^[a-f0-9]{64}$/));
      expect(j.record).not.toHaveBeenCalledWith(
        expect.anything(),
        'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
        expect.anything(),
      );
    },
  );

  it('fails closed if journaling after OS effect cannot persist', async () => {
    const j = journal();
    j.record.mockReturnValue(false);
    const effect = vi.fn(async () => receipt());
    const capability = new JournaledR0SearchCapability({ journal: j.port, effect });
    await expect(capability.execute(action())).rejects.toThrow('R0_JOURNALED_SEARCH_UNCERTAIN');
    expect(effect).toHaveBeenCalledTimes(1);
  });
});
