// T07 F04A: advisory crash-recovery disposition ONLY. The caller's report
// is untrusted: this does not read a durable ledger, prove post-state, authorize
// retry, mint an approval, or perform any OS operation. Even a caller-reported
// "completed" record requires fresh, independent Host verification.
//
// The actual F04 Host must bind the journal row to task/action/intent, prove
// durable readback, re-open the exact Win32 objects via checked handles and
// independently classify effects before it may create ANY positive receipt.
import { types } from 'node:util';

export type ReportedMutationJournalState =
  | 'ABSENT'
  | 'STARTED'
  | 'UNCERTAIN'
  | 'OBSERVED_NOT_VERIFIED'
  | 'COMPLETED_CLAIMED';

export type MutationRecoveryDisposition = Readonly<{
  schema: 'shun.files.mutation-recovery-advisory.v02';
  source: 'CALLER_REPORTED_UNTRUSTED';
  requiredNextStep:
    | 'TRUSTED_JOURNAL_READ'
    | 'RECONCILE_JOURNAL_AND_POSTSTATE'
    | 'INDEPENDENT_POSTSTATE_AND_RECEIPT_VERIFICATION';
  semanticVerified: false;
  journalTrusted: false;
  automaticRetryAllowed: false;
  fileMutationAllowed: false;
  completedEffectProven: false;
}>;

export type MutationRecoveryDispositionResult =
  | Readonly<{ ok: true; disposition: MutationRecoveryDisposition }>
  | Readonly<{ ok: false; code: 'FILE_RECOVERY_RECORD_REFUSED' }>;

function exactPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  if (types.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  return (
    names.length === 1 &&
    names[0] === 'journalState' &&
    descriptors.journalState !== undefined &&
    Object.hasOwn(descriptors.journalState, 'value')
  );
}

/**
 * Conservative UI/recovery planning based on an UNTRUSTED status label.
 * No input can promote the state to safe-to-retry or completed. This is not
 * the trusted Host's crash classifier; it cannot substitute for journal
 * readback, grant currentness or independently attested OS post-state.
 */
export function describeUntrustedMutationRecovery(
  input: unknown,
): MutationRecoveryDispositionResult {
  try {
    if (!exactPlainRecord(input))
      return { ok: false, code: 'FILE_RECOVERY_RECORD_REFUSED' };
    const state = input.journalState;
    let requiredNextStep: MutationRecoveryDisposition['requiredNextStep'];
    switch (state) {
      case 'ABSENT':
        // Even a reported absence cannot prove an attempt never ran.
        requiredNextStep = 'TRUSTED_JOURNAL_READ';
        break;
      case 'STARTED':
      case 'UNCERTAIN':
        requiredNextStep = 'RECONCILE_JOURNAL_AND_POSTSTATE';
        break;
      case 'OBSERVED_NOT_VERIFIED':
      case 'COMPLETED_CLAIMED':
        requiredNextStep = 'INDEPENDENT_POSTSTATE_AND_RECEIPT_VERIFICATION';
        break;
      default:
        return { ok: false, code: 'FILE_RECOVERY_RECORD_REFUSED' };
    }
    return Object.freeze({
      ok: true as const,
      disposition: Object.freeze({
        schema: 'shun.files.mutation-recovery-advisory.v02' as const,
        source: 'CALLER_REPORTED_UNTRUSTED' as const,
        requiredNextStep,
        semanticVerified: false as const,
        journalTrusted: false as const,
        automaticRetryAllowed: false as const,
        fileMutationAllowed: false as const,
        completedEffectProven: false as const,
      }),
    });
  } catch {
    return { ok: false, code: 'FILE_RECOVERY_RECORD_REFUSED' };
  }
}
