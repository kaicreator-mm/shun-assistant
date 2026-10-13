// Restart-safe UI read model for durable C-003 tasks. Durable sequencing
// distinguishes requests that never crossed the effect-authorization boundary
// from tasks that may have executed. Uncertain destructive work is never
// automatically retried.
import type { TaskSnapshot } from '../ports.ts';

export interface PersistedStorageRecord {
  recordId: string;
  createdAt: string;
  updatedAt: string;
  revision: number;
  payload: Record<string, unknown>;
}

export function restoreStorageTask(
  row: PersistedStorageRecord,
  trustedWorkspace: string,
): TaskSnapshot {
  if (row.payload.workspace !== trustedWorkspace) {
    throw new Error('REAL_STORAGE_DURABLE_SCOPE_MISMATCH');
  }
  const completed =
    row.payload.status === 'SUCCEEDED' &&
    row.payload.protectedVerified === true &&
    typeof row.payload.planHash === 'string' &&
    /^[a-f0-9]{64}$/.test(row.payload.planHash) &&
    typeof row.payload.receiptCount === 'number' &&
    Number.isInteger(row.payload.receiptCount) &&
    row.payload.receiptCount > 0;
  const cancelled =
    row.payload.status === 'CANCELLED' && row.payload.effectBoundaryCrossed === false;
  const definitelyNotStarted =
    row.payload.status === 'RECEIVED' || row.payload.status === 'FAILED_BEFORE_EFFECT';
  const state = completed
    ? 'SUCCEEDED'
    : cancelled
      ? 'CANCELLED'
      : definitelyNotStarted
        ? 'FAILED'
        : 'NEEDS_INTERVENTION';
  const classification = completed
    ? 'COMPLETED_VERIFIED'
    : cancelled || definitelyNotStarted
      ? 'NOT_STARTED'
      : 'MAY_HAVE_EXECUTED_UNCERTAIN';
  return {
    taskId: row.recordId,
    title: 'Previously submitted bounded storage cleanup',
    state,
    revision: row.revision,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    progress: [
      { at: row.createdAt, state: 'RECEIVED' },
      { at: row.updatedAt, state },
    ],
    ...(completed
      ? {
          verification: {
            status: 'PASS',
            checks: [{ checkId: 'persisted-prior-verification', status: 'PASS' }],
          },
        }
      : {}),
    recovery: {
      classification,
      detail: completed
        ? 'Historical verified result was durably committed before shutdown; not a new post-restart measurement.'
        : cancelled
          ? 'Explicit effect-free refusal was durably committed before shutdown; no effect was started.'
          : definitelyNotStarted
            ? 'The durable task never crossed the effect-authorization boundary; no destructive effect was handed to the executor.'
            : 'Persisted task crossed or may have crossed the effect boundary without a verified terminal. Reconcile journal and disk before any new action.',
      reconciled: completed || cancelled || definitelyNotStarted,
    },
    localOnly: { enforced: true, externalDisclosure: 'FORBIDDEN' },
  };
}
