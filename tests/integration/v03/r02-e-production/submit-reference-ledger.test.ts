/**
 * R02-E (reference binding repair): unit journeys of the durable
 * Host-issued submit-reference ledger — the trusted surface that mints and
 * authenticates approval/currentness references. Forged, pair-spliced,
 * cross-Case, superseded-step, revoked and expired references must all
 * refuse; genuine issued pairs must verify and survive restart.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SqliteHostSubmitReferenceLedger } from '../../../../apps/control-api/src/v03/composition-approval.ts';

describe('R02-E durable Host submit-reference ledger', () => {
  let dir: string;
  let file: string;
  let nowMs: number;
  let ledger: SqliteHostSubmitReferenceLedger;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r02e-refs-'));
    file = join(dir, 'submit-references.sqlite');
    nowMs = Date.now();
    ledger = new SqliteHostSubmitReferenceLedger(file, () => nowMs);
  });

  afterAll(() => {
    ledger?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('refuses non-durable or misconfigured construction', () => {
    expect(() => new SqliteHostSubmitReferenceLedger('relative.sqlite')).toThrow(
      'SUBMIT_REFERENCE_LEDGER_DURABLE_FILE_REQUIRED',
    );
    expect(() => new SqliteHostSubmitReferenceLedger(join(dir, ':memory:'))).toThrow(
      'SUBMIT_REFERENCE_LEDGER_DURABLE_FILE_REQUIRED',
    );
    expect(() => new SqliteHostSubmitReferenceLedger(file, 'not-a-clock' as unknown as () => number)).toThrow(
      'SUBMIT_REFERENCE_LEDGER_CLOCK_REQUIRED',
    );
  });

  it('issues a grammar-valid pair bound to the Case step and verifies it VALID', () => {
    const issued = ledger.issue({
      caseId: 'task-a',
      stepId: 'step-a1',
      validUntilUnixMs: nowMs + 60_000,
    });
    expect(issued.status).toBe('ISSUED');
    if (issued.status !== 'ISSUED') return;
    expect(issued.currentnessRef).toMatch(/^shun\.currentness\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
    expect(issued.approvalRef).toMatch(/^shun\.approval\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
    expect(
      ledger.verify({
        caseId: 'task-a',
        stepId: 'step-a1',
        currentnessRef: issued.currentnessRef,
        approvalRef: issued.approvalRef,
      }),
    ).toEqual({ status: 'VALID' });
  });

  it('re-issuing the same (caseId, stepId) restores the SAME durable pair', () => {
    const again = ledger.issue({
      caseId: 'task-a',
      stepId: 'step-a1',
      validUntilUnixMs: nowMs + 60_000,
    });
    const first = ledger.issue({
      caseId: 'task-a',
      stepId: 'step-a1',
      validUntilUnixMs: nowMs + 60_000,
    });
    expect(again.status).toBe('ISSUED');
    expect(first.status).toBe('ISSUED');
    if (again.status !== 'ISSUED' || first.status !== 'ISSUED') return;
    expect(again.currentnessRef).toBe(first.currentnessRef);
    expect(again.approvalRef).toBe(first.approvalRef);
  });

  it('refuses issue input that is not a live bounded Case step', () => {
    expect(
      ledger.issue({ caseId: 'bad id!', stepId: 'step-a1', validUntilUnixMs: nowMs + 60_000 }),
    ).toMatchObject({ status: 'REFUSED' });
    expect(
      ledger.issue({ caseId: 'task-a', stepId: 'step-a1', validUntilUnixMs: nowMs }),
    ).toMatchObject({ status: 'REFUSED' });
  });

  it('rejects valid-shaped FORGED references that were never issued', () => {
    expect(
      ledger.verify({
        caseId: 'task-a',
        stepId: 'step-a1',
        currentnessRef: `shun.currentness.v1/${'0'.repeat(48)}`,
        approvalRef: `shun.approval.v1/${'1'.repeat(48)}`,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' });
  });

  it('rejects malformed namespaces and identical reference pairs', () => {
    const issued = ledger.issue({
      caseId: 'task-c',
      stepId: 'step-c1',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (issued.status !== 'ISSUED') throw new Error('issue failed');
    // Swapped namespaces never match a single Host record.
    expect(
      ledger.verify({
        caseId: 'task-c',
        stepId: 'step-c1',
        currentnessRef: issued.approvalRef,
        approvalRef: issued.currentnessRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' });
    expect(
      ledger.verify({
        caseId: 'task-c',
        stepId: 'step-c1',
        currentnessRef: issued.currentnessRef,
        approvalRef: issued.currentnessRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' });
  });

  it('rejects a pair spliced from two different issued records', () => {
    const issuedD = ledger.issue({
      caseId: 'task-d',
      stepId: 'step-d1',
      validUntilUnixMs: nowMs + 60_000,
    });
    const issuedE = ledger.issue({
      caseId: 'task-e',
      stepId: 'step-e1',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (issuedD.status !== 'ISSUED' || issuedE.status !== 'ISSUED') throw new Error('issue failed');
    expect(
      ledger.verify({
        caseId: 'task-d',
        stepId: 'step-d1',
        currentnessRef: issuedD.currentnessRef,
        approvalRef: issuedE.approvalRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' });
  });

  it('rejects CROSS-CASE use: references of another Case under this caseId', () => {
    const issuedF = ledger.issue({
      caseId: 'task-f',
      stepId: 'step-f1',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (issuedF.status !== 'ISSUED') throw new Error('issue failed');
    expect(
      ledger.verify({
        caseId: 'task-g',
        stepId: 'step-f1',
        currentnessRef: issuedF.currentnessRef,
        approvalRef: issuedF.approvalRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_CASE_MISMATCH' });
  });

  it('superseding a Case step revokes the older pair and binds the new step identity', () => {
    const first = ledger.issue({
      caseId: 'task-h',
      stepId: 'step-h1',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (first.status !== 'ISSUED') throw new Error('issue failed');
    const next = ledger.issue({
      caseId: 'task-h',
      stepId: 'step-h2',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (next.status !== 'ISSUED') throw new Error('reissue failed');
    // The superseded pair is revoked, not silently valid for the new step.
    expect(
      ledger.verify({
        caseId: 'task-h',
        stepId: 'step-h1',
        currentnessRef: first.currentnessRef,
        approvalRef: first.approvalRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_REVOKED' });
    // The new pair is bound to the NEW step id, not the old one.
    expect(
      ledger.verify({
        caseId: 'task-h',
        stepId: 'step-h1',
        currentnessRef: next.currentnessRef,
        approvalRef: next.approvalRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_STEP_MISMATCH' });
    expect(
      ledger.verify({
        caseId: 'task-h',
        stepId: 'step-h2',
        currentnessRef: next.currentnessRef,
        approvalRef: next.approvalRef,
      }),
    ).toEqual({ status: 'VALID' });
  });

  it('rejects EXPIRED references while the clock is still injectable', () => {
    const issued = ledger.issue({
      caseId: 'task-i',
      stepId: 'step-i1',
      validUntilUnixMs: nowMs + 1_000,
    });
    if (issued.status !== 'ISSUED') throw new Error('issue failed');
    nowMs += 999;
    expect(
      ledger.verify({
        caseId: 'task-i',
        stepId: 'step-i1',
        currentnessRef: issued.currentnessRef,
        approvalRef: issued.approvalRef,
      }),
    ).toEqual({ status: 'VALID' });
    nowMs += 2;
    expect(
      ledger.verify({
        caseId: 'task-i',
        stepId: 'step-i1',
        currentnessRef: issued.currentnessRef,
        approvalRef: issued.approvalRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_EXPIRED' });
  });

  it('re-issue after expiry mints a FRESH pair and revokes the expired one', () => {
    const expired = ledger.issue({
      caseId: 'task-k',
      stepId: 'step-k1',
      validUntilUnixMs: nowMs + 500,
    });
    if (expired.status !== 'ISSUED') throw new Error('issue failed');
    nowMs += 501;
    const fresh = ledger.issue({
      caseId: 'task-k',
      stepId: 'step-k1',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (fresh.status !== 'ISSUED') throw new Error('reissue failed');
    expect(fresh.currentnessRef).not.toBe(expired.currentnessRef);
    expect(fresh.approvalRef).not.toBe(expired.approvalRef);
    expect(
      ledger.verify({
        caseId: 'task-k',
        stepId: 'step-k1',
        currentnessRef: expired.currentnessRef,
        approvalRef: expired.approvalRef,
      }),
    ).toEqual({ status: 'REFUSED', code: 'HOST_REFERENCES_REVOKED' });
    expect(
      ledger.verify({
        caseId: 'task-k',
        stepId: 'step-k1',
        currentnessRef: fresh.currentnessRef,
        approvalRef: fresh.approvalRef,
      }),
    ).toEqual({ status: 'VALID' });
  });

  it('issued pairs survive a ledger restart over the same durable file', () => {
    const issued = ledger.issue({
      caseId: 'task-j',
      stepId: 'step-j1',
      validUntilUnixMs: nowMs + 60_000,
    });
    if (issued.status !== 'ISSUED') throw new Error('issue failed');
    ledger.close();
    const reopened = new SqliteHostSubmitReferenceLedger(file, () => nowMs);
    try {
      expect(
        reopened.verify({
          caseId: 'task-j',
          stepId: 'step-j1',
          currentnessRef: issued.currentnessRef,
          approvalRef: issued.approvalRef,
        }),
      ).toEqual({ status: 'VALID' });
      const restored = reopened.issue({
        caseId: 'task-j',
        stepId: 'step-j1',
        validUntilUnixMs: nowMs + 60_000,
      });
      expect(restored).toMatchObject({
        status: 'ISSUED',
        currentnessRef: issued.currentnessRef,
        approvalRef: issued.approvalRef,
      });
    } finally {
      reopened.close();
      ledger = new SqliteHostSubmitReferenceLedger(file, () => nowMs);
    }
  });
});
