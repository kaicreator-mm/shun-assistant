// T04 SEPARATE task semantic verifier for one R0 file.search action. It is
// NOT the effect path, NOT the journal, and cannot mint, alter or replay any
// journal row or receipt. After the journaled runner reports
// EXECUTED_NOT_SEMANTICALLY_VERIFIED, the trusted host application layer may
// call this to decide a task-level semantic verdict from:
//   1. the durable journal readback (state + committed receipt digest),
//   2. the host-owned oracle evidence captured around the single effect,
//   3. the verifier's OWN fresh independent expected-state walk plus its own
//      matcher re-check of every expected match name.
// Only an all-green conjunction yields taskSemantic PASS; anything else —
// including any inability to re-observe the scope — stays UNCERTAIN.
import { type AuthorizedAction, canonicalJson, type ExecutionReceipt } from '@shun/contracts';
import {
  captureOracleWalk,
  isR0SearchAction,
  oracleGlobMatch,
  oracleReceiptDigestMatches,
} from './r0-independent-poststate-oracle.ts';
import type { SqliteR0EffectJournal } from './sqlite-r0-effect-journal.ts';
import type { R0SearchEffectEvidence } from './trusted-windows-r0-effect.ts';

export type R0TaskSemanticCode =
  | 'SEMANTIC_JOURNAL_NOT_OBSERVED'
  | 'SEMANTIC_RECEIPT_DIGEST_MISMATCH'
  | 'SEMANTIC_EVIDENCE_INCOMPLETE'
  | 'SEMANTIC_EXPECTATION_UNAVAILABLE'
  | 'SEMANTIC_EXPECTATION_MISMATCH';

export type R0TaskSemanticVerdict =
  | { ok: true; taskSemantic: 'PASS'; expectedMatchCount: number; verifiedMatchCount: number }
  | { ok: false; taskSemantic: 'UNCERTAIN'; code: R0TaskSemanticCode };

export type R0TaskSemanticInput = Readonly<{
  action: AuthorizedAction;
  journal: SqliteR0EffectJournal;
  receipt: ExecutionReceipt;
  evidence: R0SearchEffectEvidence | null;
}>;

/**
 * Binds the semantic verdict to the durable evidence chain: the journal's
 * committed receipt digest must equal the digest of the receipt handed in,
 * the effect-time oracle evidence must be all-green, and the verifier's own
 * third observation of the scope must reproduce the expected match set with
 * every name satisfying the frozen query under the oracle's matcher.
 */
export function verifyR0SearchTaskSemantics(input: R0TaskSemanticInput): R0TaskSemanticVerdict {
  try {
    const { action, journal, receipt, evidence } = input;
    if (!isR0SearchAction(action)) return refused('SEMANTIC_JOURNAL_NOT_OBSERVED');
    const readback = journal.lookup(action);
    if (
      !readback.ok ||
      readback.state !== 'OBSERVED_NOT_SEMANTICALLY_VERIFIED' ||
      readback.receiptSha256 === null
    )
      return refused('SEMANTIC_JOURNAL_NOT_OBSERVED');

    if (
      receipt.actionId !== action.actionId ||
      receipt.terminal !== 'SUCCEEDED' ||
      receipt.sideEffectEvidence.postStateVerified !== true ||
      receipt.sideEffectEvidence.recoveryClassification !== 'COMPLETED_VERIFIED' ||
      !oracleReceiptDigestMatches(readback.receiptSha256, canonicalJson(receipt))
    )
      return refused('SEMANTIC_RECEIPT_DIGEST_MISMATCH');

    if (
      evidence === null ||
      evidence.effectObserved !== true ||
      evidence.fingerprintUnchanged !== true ||
      evidence.independentMatchesEqual !== true
    )
      return refused('SEMANTIC_EVIDENCE_INCOMPLETE');

    const root = action.action.parameters.root;
    const query = action.action.parameters.query;
    if (typeof root !== 'string' || typeof query !== 'string')
      return refused('SEMANTIC_JOURNAL_NOT_OBSERVED');
    const now = captureOracleWalk(root, query);
    if (!now.ok) return refused('SEMANTIC_EXPECTATION_UNAVAILABLE');
    // Read-only search: the verification-time world must still contain the
    // same match set the effect-time oracle verified (bound-limited recheck).
    if (now.walk.matches.length !== evidence.matchedCount)
      return refused('SEMANTIC_EXPECTATION_MISMATCH');
    for (const rel of now.walk.matches) {
      const name = rel.split('\\').pop()?.split('/').pop();
      if (typeof name !== 'string' || name.length === 0 || !oracleGlobMatch(name, query))
        return refused('SEMANTIC_EXPECTATION_MISMATCH');
    }
    return {
      ok: true,
      taskSemantic: 'PASS',
      expectedMatchCount: now.walk.matches.length,
      verifiedMatchCount: evidence.matchedCount,
    };
  } catch {
    return { ok: false, taskSemantic: 'UNCERTAIN', code: 'SEMANTIC_EXPECTATION_UNAVAILABLE' };
  }
}

function refused(code: R0TaskSemanticCode): R0TaskSemanticVerdict {
  return { ok: false, taskSemantic: 'UNCERTAIN', code };
}
