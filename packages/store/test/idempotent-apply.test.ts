// T03 required evidence — idempotent application-effect protocol (L2 §5.4).
// Retrying the same effectId returns the recorded result; a conflicting
// identity under the same effectId fails closed; effects survive restarts.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ShunStore, ShunStoreEffectConflictError } from '../src/index.ts';
import { tempStoreFile } from './helpers.ts';

const mutation = {
  recordKind: 'approval',
  recordId: 'approval-1',
  payload: { approved: true, planHash: 'a'.repeat(64), approvedBy: 'USER_APPROVAL' },
} as const;

let file: string;
let store: ShunStore;

beforeEach(() => {
  file = tempStoreFile();
  store = new ShunStore({ file });
});

afterEach(async () => {
  await store.close();
});

describe('ShunStore.apply — first application', () => {
  it('applies a fresh effectId and persists the authoritative record', async () => {
    const receipt = await store.apply('effect-1', mutation);

    expect(receipt.effectId).toBe('effect-1');
    expect(receipt.applied).toBe(true);
    expect(receipt.receiptRef).toBe('shunstore://effect/effect-1');

    const record = await store.getRecord('approval', 'approval-1');
    expect(record).not.toBeNull();
    expect(record?.payload).toEqual(mutation.payload);
    expect(record?.revision).toBe(1);
  });

  it('treats a different effectId with the same payload as a new effect', async () => {
    const first = await store.apply('effect-1', mutation);
    const second = await store.apply('effect-2', mutation);

    expect(first.applied).toBe(true);
    expect(second.applied).toBe(true);
    expect(second.receiptRef).toBe('shunstore://effect/effect-2');

    // The record was mutated twice through two distinct effects.
    const record = await store.getRecord('approval', 'approval-1');
    expect(record?.revision).toBe(2);
  });
});

describe('ShunStore.apply — idempotent replay', () => {
  it('returns the recorded result for the same effectId without re-applying', async () => {
    const first = await store.apply('effect-1', mutation);
    const replay = await store.apply('effect-1', mutation);

    expect(replay.applied).toBe(false);
    expect(replay.effectId).toBe('effect-1');
    expect(replay.receiptRef).toBe(first.receiptRef);

    // No second write happened.
    const record = await store.getRecord('approval', 'approval-1');
    expect(record?.revision).toBe(1);
  });

  it('replays the recorded disposition even when the payload differs in key order/whitespace', async () => {
    await store.apply('effect-1', mutation);
    const reordered = {
      recordKind: 'approval',
      recordId: 'approval-1',
      payload: { approvedBy: 'USER_APPROVAL', planHash: 'a'.repeat(64), approved: true },
    } as const;
    const replay = await store.apply('effect-1', reordered);
    expect(replay.applied).toBe(false);
  });
});

describe('ShunStore.apply — identity conflicts fail closed', () => {
  it('rejects the same effectId with a different payload', async () => {
    await store.apply('effect-1', mutation);
    const before = await store.getRecord('approval', 'approval-1');

    const tampered = { ...mutation, payload: { ...mutation.payload, approved: false } };
    await expect(store.apply('effect-1', tampered)).rejects.toBeInstanceOf(
      ShunStoreEffectConflictError,
    );

    // Store state is untouched by the refused call.
    const after = await store.getRecord('approval', 'approval-1');
    expect(after).toEqual(before);
  });

  it('rejects the same effectId pointed at a different record', async () => {
    await store.apply('effect-1', mutation);
    const retargeted = { ...mutation, recordId: 'approval-2' };
    await expect(store.apply('effect-1', retargeted)).rejects.toBeInstanceOf(
      ShunStoreEffectConflictError,
    );
    await expect(store.getRecord('approval', 'approval-2')).resolves.toBeNull();
  });

  it('rejects malformed mutations and empty effectIds', async () => {
    await expect(
      store.apply('effect-x', {
        recordKind: 'not-a-kind',
        recordId: 'r',
        payload: {},
      } as unknown as typeof mutation),
    ).rejects.toHaveProperty('code', 'STORE_INVALID_MUTATION');

    await expect(store.apply('', mutation)).rejects.toHaveProperty(
      'code',
      'STORE_INVALID_MUTATION',
    );
  });
});

describe('ShunStore — restart durability', () => {
  it('survives a full close/reopen cycle and replays recorded effects', async () => {
    const first = await store.apply('effect-1', mutation);
    await store.close();

    const reopened = new ShunStore({ file });
    try {
      const replay = await reopened.apply('effect-1', mutation);
      expect(replay.applied).toBe(false);
      expect(replay.receiptRef).toBe(first.receiptRef);

      const record = await reopened.getRecord('approval', 'approval-1');
      expect(record?.payload).toEqual(mutation.payload);

      const probe = await reopened.getEffectReceipt('effect-1');
      expect(probe?.applied).toBe(true);
      expect(probe?.receiptRef).toBe(first.receiptRef);
      await expect(reopened.getEffectReceipt('missing')).resolves.toBeNull();
    } finally {
      await reopened.close();
    }
  });
});
