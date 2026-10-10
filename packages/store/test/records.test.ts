// T03 — ShunStore record surface: every frozen record kind (L2 §11.1) is a
// first-class business-authority record; unknown kinds are rejected; the read
// model exposes what reconciliation probes and upper layers need.

import type { ShunStoreMutation } from '@shun/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SHUN_STORE_RECORD_KINDS, ShunStore } from '../src/index.ts';
import { tempStoreFile } from './helpers.ts';

let file: string;
let store: ShunStore;

beforeEach(() => {
  file = tempStoreFile();
  store = new ShunStore({ file });
});

afterEach(async () => {
  await store.close();
});

describe('ShunStore record kinds', () => {
  it('accepts every frozen L2 §11.1 record kind', async () => {
    expect([...SHUN_STORE_RECORD_KINDS].sort()).toEqual(
      [
        'task',
        'goal_contract',
        'capability_resolution',
        'provider_environment_binding',
        'policy_snapshot',
        'action_plan',
        'approval',
        'execution_receipt',
        'verification_receipt',
        'provider_installation',
        'provider_provenance',
        'lifecycle_record',
        'provider_outcome_evidence',
        'recipe_definition',
        'recipe_promotion_evidence',
        'recipe_replay_evidence',
      ].sort(),
    );

    for (const [index, kind] of SHUN_STORE_RECORD_KINDS.entries()) {
      const receipt = await store.apply(`effect-${kind}`, {
        recordKind: kind,
        recordId: `${kind}-1`,
        payload: { seq: index },
      });
      expect(receipt.applied).toBe(true);
    }
  });
});

describe('ShunStore read model', () => {
  it('returns null for unknown records and lists by kind', async () => {
    await expect(store.getRecord('task', 'missing')).resolves.toBeNull();

    for (const id of ['t2', 't1']) {
      await store.apply(`effect-${id}`, {
        recordKind: 'task',
        recordId: id,
        payload: { id },
      });
    }

    const tasks = await store.listRecords('task');
    expect(tasks.map((task) => task.recordId)).toEqual(['t1', 't2']);
    expect(tasks.every((task) => task.recordKind === 'task')).toBe(true);
  });

  it('increments revision per applied effect and keeps canonical payload identity', async () => {
    const base: ShunStoreMutation = {
      recordKind: 'action_plan',
      recordId: 'plan-1',
      payload: { planHash: 'b'.repeat(64), bindingRefs: ['x'] },
    };
    await store.apply('e1', base);
    await store.apply('e2', { ...base, payload: { bindingRefs: ['x'], planHash: 'b'.repeat(64) } });

    const record = await store.getRecord('action_plan', 'plan-1');
    expect(record?.revision).toBe(2);
    // Key order in payloads is normalized to canonical form on write.
    expect(record?.payload).toEqual(base.payload);
  });
});
