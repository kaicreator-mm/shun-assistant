// T07 F04B1: trusted same-store SQLite journal readback after process
// interruption. This private Host helper reads durable evidence; it never
// grants execution, retries an effect or asserts current Windows post-state.
//
// F03 journal holds an intent digest but no pre-effect file identities or
// content commitment. STARTED/UNCERTAIN cannot be upgraded to success from
// existence of the destination path, and even COMMITTED requires fresh
// independent Host re-observation before any task-level semantic PASS.
import type { AuthorizedAction } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { SqliteFileMutationJournal } from './sqlite-file-mutation-journal.ts';

export type FileMutationRecoveryReadback = Readonly<{
  schema: 'shun.files.mutation-recovery-readback.v02';
  provenance: 'HOST_DURABLE_SAME_STORE_JOURNAL';
  state:
    | 'NO_MATCHING_RECORD_UNPROVEN'
    | 'STARTED_RECONCILE_REQUIRED'
    | 'UNCERTAIN_RECONCILE_REQUIRED'
    | 'COMMITTED_REVALIDATION_REQUIRED';
  recordPresent: boolean;
  trustedJournalRead: true;
  postStateIndependentlyVerified: false;
  semanticVerified: false;
  effectCompletionReproven: false;
  automaticRetryAllowed: false;
  fileMutationAllowed: false;
  evidenceDigestRecorded: boolean;
}>;

export type FileMutationRecoveryReadbackResult =
  | Readonly<{ ok: true; snapshot: FileMutationRecoveryReadback }>
  | Readonly<{ ok: false; code: 'FILE_RECOVERY_JOURNAL_REFUSED' }>;

function snapshot(
  state: FileMutationRecoveryReadback['state'],
  recordPresent: boolean,
  evidenceDigestRecorded: boolean,
): FileMutationRecoveryReadbackResult {
  return Object.freeze({
    ok: true as const,
    snapshot: Object.freeze({
      schema: 'shun.files.mutation-recovery-readback.v02' as const,
      provenance: 'HOST_DURABLE_SAME_STORE_JOURNAL' as const,
      state,
      recordPresent,
      trustedJournalRead: true as const,
      postStateIndependentlyVerified: false as const,
      semanticVerified: false as const,
      effectCompletionReproven: false as const,
      automaticRetryAllowed: false as const,
      fileMutationAllowed: false as const,
      evidenceDigestRecorded,
    }),
  });
}

/**
 * The trusted private Host supplies its actual durable ShunStore and a
 * pre-resolved plan-bound AuthorizedAction. No caller-supplied journal states
 * or evidence flags are accepted here. The journal independently validates
 * the action-intent digest against the durable row and refuses divergent IDs.
 *
 * Even NOT_FOUND is not positive evidence of nonexecution, because the
 * caller may supply the wrong identity or storage may have been replaced.
 */
export class SqliteFileMutationRecoveryReader {
  private readonly journal: SqliteFileMutationJournal;

  constructor(store: ShunStore) {
    if (!(store instanceof ShunStore))
      throw new Error('FILE_RECOVERY_JOURNAL_CONFIGURATION_REFUSED');
    try {
      this.journal = new SqliteFileMutationJournal(store);
    } catch {
      throw new Error('FILE_RECOVERY_JOURNAL_CONFIGURATION_REFUSED');
    }
  }

  read(action: AuthorizedAction): FileMutationRecoveryReadbackResult {
    try {
      const row = this.journal.lookup(action);
      if (!row.ok) {
        if (row.code === 'NOT_FOUND') return snapshot('NO_MATCHING_RECORD_UNPROVEN', false, false);
        return { ok: false, code: 'FILE_RECOVERY_JOURNAL_REFUSED' };
      }
      // The evidence digest is a historical receipt reference only — never
      // proof of current post-state, even when the row says COMMITTED.
      if (row.state === 'STARTED') {
        if (row.evidenceSha256 !== null)
          return { ok: false, code: 'FILE_RECOVERY_JOURNAL_REFUSED' };
        return snapshot('STARTED_RECONCILE_REQUIRED', true, false);
      }
      if (row.state === 'UNCERTAIN') {
        return snapshot('UNCERTAIN_RECONCILE_REQUIRED', true, row.evidenceSha256 !== null);
      }
      if (row.state === 'COMMITTED_VERIFIED' && row.evidenceSha256 !== null) {
        return snapshot('COMMITTED_REVALIDATION_REQUIRED', true, true);
      }
      return { ok: false, code: 'FILE_RECOVERY_JOURNAL_REFUSED' };
    } catch {
      return { ok: false, code: 'FILE_RECOVERY_JOURNAL_REFUSED' };
    }
  }
}
