import { describe, expect, it } from 'vitest';
import { canonicalJson, computePlanHash } from '../src/plan.ts';
import { parseActionPlan } from '../src/registry.ts';
import { loadFixture, reverseKeysDeep } from './helpers.ts';

const plan = parseActionPlan(loadFixture('valid/action-plan/single-binding.json'));

describe('plan hash version identity (canonicalization)', () => {
  it('the fixture planHash matches canonical recomputation', () => {
    expect(computePlanHash(plan)).toBe(plan.planHash);
  });

  it('hashing is deterministic across repeated computation', () => {
    expect(computePlanHash(plan)).toBe(computePlanHash(plan));
  });

  it('object key order does not affect the hash', () => {
    const shuffled = reverseKeysDeep(plan);
    expect(computePlanHash(shuffled as typeof plan)).toBe(computePlanHash(plan));
  });

  it('JSON whitespace does not affect the hash', () => {
    const roundTripped = JSON.parse(JSON.stringify(plan)) as typeof plan;
    expect(canonicalJson(roundTripped)).toBe(canonicalJson(plan));
    expect(computePlanHash(roundTripped)).toBe(computePlanHash(plan));
  });

  it('the planHash field itself is excluded from the hash', () => {
    const zeroed = { ...plan, planHash: '0'.repeat(64) };
    expect(computePlanHash(zeroed)).toBe(computePlanHash(plan));
  });

  it('any semantic change produces a different hash', () => {
    const first = plan.actions.at(0);
    if (!first) throw new Error('fixture plan must contain an action');

    const changedParameter = {
      ...plan,
      actions: [{ ...first, parameters: { ...first.parameters, maxLongEdgePx: 1601 } }],
    };
    expect(computePlanHash(changedParameter)).not.toBe(computePlanHash(plan));

    const changedTask = { ...plan, taskId: 'task-2026-10-10-999' };
    expect(computePlanHash(changedTask)).not.toBe(computePlanHash(plan));

    const changedPolicy = { ...plan, policySnapshotRevision: 'pol-snap-2026-10-10-b' };
    expect(computePlanHash(changedPolicy)).not.toBe(computePlanHash(plan));
  });
});
