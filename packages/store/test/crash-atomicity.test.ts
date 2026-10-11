// T03 required evidence — crash/torn-write behavior. The store's answer to a
// torn application is transactional atomicity: a failure between the record
// write and the effect/receipt bookkeeping leaves NEITHER behind, and a retry
// of the same effectId then applies cleanly. Failure is injected at the
// database layer (RAISE(ABORT) trigger) — no production test hooks.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ShunStore } from '../src/index.ts';
import { tempStoreFile } from './helpers.ts';

const mutation = {
  recordKind: 'execution_receipt',
  recordId: 'receipt-1',
  payload: { actionId: 'action-1', terminal: 'SUCCEEDED' },
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

describe('ShunStore — torn application atomicity', () => {
  it('leaves no partial state when the transaction aborts mid-application', async () => {
    store.database.exec(`
      CREATE TRIGGER abort_effect_insert
      BEFORE INSERT ON effects
      WHEN NEW.effect_id = 'effect-1'
      BEGIN
        SELECT RAISE(ABORT, 'injected crash between record and effect write');
      END;
    `);

    await expect(store.apply('effect-1', mutation)).rejects.toHaveProperty(
      'code',
      'STORE_WRITE_FAILED',
    );

    // Neither the business record nor the effect bookkeeping may exist.
    await expect(store.getRecord('execution_receipt', 'receipt-1')).resolves.toBeNull();
    await expect(store.getEffectReceipt('effect-1')).resolves.toBeNull();
  });

  it('allows the same effectId to apply cleanly once the fault is gone', async () => {
    store.database.exec(`
      CREATE TRIGGER abort_effect_insert
      BEFORE INSERT ON effects WHEN NEW.effect_id = 'effect-1'
      BEGIN
        SELECT RAISE(ABORT, 'injected crash');
      END;
    `);
    await expect(store.apply('effect-1', mutation)).rejects.toHaveProperty(
      'code',
      'STORE_WRITE_FAILED',
    );

    store.database.exec('DROP TRIGGER abort_effect_insert');
    const receipt = await store.apply('effect-1', mutation);
    expect(receipt.applied).toBe(true);

    const replay = await store.apply('effect-1', mutation);
    expect(replay.applied).toBe(false);
  });
});

describe('ShunStore — committed-state visibility across connections (in-process)', () => {
  // Narrowed claim (Issue #36, C05): abandon() simulates disappearance only
  // within ONE live process; a sibling connection sees committed state
  // regardless. This test deliberately proves only connection-level
  // visibility. Real hard-kill/process-death durability evidence lives in
  // crash-hard-kill.test.ts (spawn → taskkill|SIGKILL → reopen).
  it('keeps committed effects readable by a brand-new connection after abandon()', async () => {
    const receipt = await store.apply('effect-1', mutation);
    // Simulate the process disappearing: no checkpoint, no clean teardown.
    store.abandon();

    const postCrash = new ShunStore({ file });
    try {
      const replay = await postCrash.apply('effect-1', mutation);
      expect(replay.applied).toBe(false);
      expect(replay.receiptRef).toBe(receipt.receiptRef);
      await expect(postCrash.getRecord('execution_receipt', 'receipt-1')).resolves.toMatchObject({
        payload: mutation.payload,
      });
    } finally {
      await postCrash.close();
    }
  });
});
