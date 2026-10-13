import { describe, expect, it } from 'vitest';
import { restoreStorageTask } from '../src/real-storage/recovery.ts';

const base = {
  recordId: 'task-persisted-001',
  createdAt: '2026-10-10T10:00:00.000Z',
  updatedAt: '2026-10-10T10:05:00.000Z',
  revision: 2,
};
const root = 'C:\\safe\\test-root';
const row = (payload: Record<string, unknown>) => ({
  ...base,
  payload: { workspace: root, ...payload },
});

describe('C-003 restart safety of persisted task read model', () => {
  it('classifies durable pre-effect rows as NOT_STARTED', () => {
    for (const status of ['RECEIVED', 'FAILED_BEFORE_EFFECT']) {
      const out = restoreStorageTask(row({ status }), root);
      expect(out.state).toBe('FAILED');
      expect(out.recovery).toMatchObject({
        classification: 'NOT_STARTED',
        reconciled: true,
      });
      expect(out.recovery?.detail).toContain('never crossed the effect-authorization boundary');
      expect(out.execution).toBeUndefined();
    }
  });

  it('keeps effect-authorized, executing, unknown and corrupt nonterminals uncertain', () => {
    for (const status of ['EFFECT_AUTHORIZED', 'EXECUTING', 'FAILED', 'corrupt']) {
      const out = restoreStorageTask(row({ status }), root);
      expect(out.state).toBe('NEEDS_INTERVENTION');
      expect(out.recovery).toMatchObject({
        classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        reconciled: false,
      });
      expect(out.execution).toBeUndefined();
    }
  });

  it('a durable verified terminal is historical evidence, never a new measurement', () => {
    const out = restoreStorageTask(
      row({
        status: 'SUCCEEDED',
        planHash: 'a'.repeat(64),
        receiptCount: 2,
        protectedVerified: true,
      }),
      root,
    );
    expect(out.state).toBe('SUCCEEDED');
    expect(out.recovery).toMatchObject({ classification: 'COMPLETED_VERIFIED', reconciled: true });
    expect(out.recovery?.detail).toContain('Historical');
  });

  it('rejects partial or fabricated terminal flags and unrelated database roots', () => {
    const missing = restoreStorageTask(row({ status: 'SUCCEEDED', protectedVerified: true }), root);
    expect(missing.state).toBe('NEEDS_INTERVENTION');
    expect(missing.recovery?.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(() =>
      restoreStorageTask(row({ status: 'RECEIVED', workspace: 'C:\\different' }), root),
    ).toThrow('REAL_STORAGE_DURABLE_SCOPE_MISMATCH');
  });

  it('only durably finalised, explicitly effect-free cancellations report NOT_STARTED', () => {
    const out = restoreStorageTask(
      row({ status: 'CANCELLED', effectBoundaryCrossed: false }),
      root,
    );
    expect(out.state).toBe('CANCELLED');
    expect(out.recovery).toMatchObject({ classification: 'NOT_STARTED', reconciled: true });
  });

  it('never beautifies an unproven cancellation after an effect boundary', () => {
    for (const payload of [
      { status: 'CANCELLED' },
      { status: 'CANCELLED', effectBoundaryCrossed: true },
    ]) {
      const out = restoreStorageTask(row(payload), root);
      expect(out.state).toBe('NEEDS_INTERVENTION');
      expect(out.recovery).toMatchObject({
        classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        reconciled: false,
      });
    }
  });
});
