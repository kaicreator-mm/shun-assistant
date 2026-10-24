// T04 SEPARATE task semantic verifier for one R0 file.search action. It is
// NOT the effect path, NOT the journal, and cannot mint, alter or replay any
// journal row or receipt. After the journaled runner reports
// EXECUTED_NOT_SEMANTICALLY_VERIFIED, the trusted host application layer may
// call this to decide a task-level semantic verdict from:
//   1. the durable journal readback (state + committed receipt digest),
//   2. the durable phase receipt readback (R2 P1-02): the receipt's
//      journalRef must cite the real persisted phase receipt, whose
//      commitment carries the effect-time expected-state and post-state
//      fingerprints bound to the same task/action/intent,
//   3. the host-owned oracle evidence captured around the single effect,
//   4. the verifier's OWN fresh independent walk — its identity fingerprint
//      (including content digests) must still equal the effect-time
//      post-state, and every expected match name must satisfy the frozen
//      query under the oracle's matcher.
// Only an all-green conjunction yields taskSemantic PASS; anything else —
// including any inability to re-observe the scope, or a content swap that
// preserves superficial size/mtime — stays UNCERTAIN.
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
  | 'SEMANTIC_PHASE_RECEIPT_MISMATCH'
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

const PHASE_TABLE = 'recipe_r0_effect_phase_v02';

/**
 * Binds the semantic verdict to the durable evidence chain: the journal's
 * committed receipt digest must equal the digest of the receipt handed in,
 * the cited phase receipt must exist with a consistent commitment, the
 * effect-time oracle evidence must be all-green, and the verifier's own
 * third observation of the scope must reproduce the effect-time post-state
 * fingerprint and match set.
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

    // The positive receipt must cite the real durable phase receipt of this
    // exact attempt — a constant table name or unknown digest is refused.
    const journalRef = receipt.sideEffectEvidence.journalRef;
    if (typeof journalRef !== 'string' || !journalRef.startsWith(`${PHASE_TABLE}:`))
      return refused('SEMANTIC_PHASE_RECEIPT_MISMATCH');
    const phase = journal.lookupEffectPhase(action);
    if (
      !phase.ok ||
      `${PHASE_TABLE}:${phase.phaseReceiptSha256}` !== journalRef ||
      phase.commitment.postStateSha256.length !== 64
    )
      return refused('SEMANTIC_PHASE_RECEIPT_MISMATCH');

    if (
      evidence === null ||
      evidence.effectObserved !== true ||
      evidence.fingerprintUnchanged !== true ||
      evidence.independentMatchesEqual !== true ||
      evidence.postStateSha256 !== phase.commitment.postStateSha256
    )
      return refused('SEMANTIC_EVIDENCE_INCOMPLETE');

    const root = action.action.parameters.root;
    const query = action.action.parameters.query;
    if (typeof root !== 'string' || typeof query !== 'string')
      return refused('SEMANTIC_JOURNAL_NOT_OBSERVED');
    const now = captureOracleWalk(root, query);
    if (!now.ok) return refused('SEMANTIC_EXPECTATION_UNAVAILABLE');
    // Read-only search: the verification-time world must still be the
    // identity fingerprint the effect-time oracle verified — including
    // content digests, so a swap preserving superficial size/mtime cannot
    // pass (bound-limited recheck).
    if (now.walk.fingerprint !== phase.commitment.postStateSha256)
      return refused('SEMANTIC_EXPECTATION_MISMATCH');
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
