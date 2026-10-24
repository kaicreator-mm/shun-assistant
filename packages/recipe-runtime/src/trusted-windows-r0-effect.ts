// T04 trusted private Windows host effect: composes the independently
// reviewed native R0 search port with the SEPARATE post-state oracle from
// r0-independent-poststate-oracle.ts. A positive receipt (SUCCEEDED +
// COMPLETED_VERIFIED + postStateVerified=true) exists ONLY when the oracle —
// a different implementation, never the native walker re-read — reproduces
// the observation and fingerprints the scope as unchanged. Every other
// outcome is the conservative UNCERTAIN receipt; the journaled capability
// then keeps STARTED/UNCERTAIN and never replays. This function must only be
// wired by the fixed private host bootstrap, never by Recipe/model/HTTP.
import {
  type AuthorizedAction,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import {
  captureOracleWalk,
  isR0SearchAction,
  type OracleWalk,
  oracleMatchesObservation,
  oracleWalksEqual,
} from './r0-independent-poststate-oracle.ts';
import { type LocalFileSearchObservation, observeScopedFileSearch } from './scoped-file-search.ts';

const UNCERTAIN = 'R0_NATIVE_EFFECT_UNCERTAIN';
const PROVIDER_VERSION = '0.2.0';
const JOURNAL_REF = 'recipe_r0_effect_journal_v02';

/** Host-side summary for the separate task semantic verifier. No paths. */
export type R0SearchEffectEvidence = Readonly<{
  effectObserved: boolean;
  fingerprintUnchanged: boolean;
  independentMatchesEqual: boolean;
  inspectedEntries: number;
  matchedCount: number;
  verificationTimeIso: string;
}>;

export type TrustedR0SearchResult = Readonly<{
  receipt: ExecutionReceipt;
  evidence: R0SearchEffectEvidence;
}>;

function uncertainReceipt(actionId: string, startedAt: string): ExecutionReceipt {
  return ExecutionReceiptSchema.parse({
    actionId,
    environmentId: 'local-windows-user',
    providerId: 'shun-win32-r0-native',
    providerVersion: PROVIDER_VERSION,
    startedAt,
    finishedAt: new Date(Math.max(Date.now(), Date.parse(startedAt))).toISOString(),
    terminal: 'UNCERTAIN',
    outputRefs: [],
    sideEffectEvidence: {
      sideEffectClass: 'R0',
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      postStateVerified: false,
    },
  });
}

function observationShape(observation: LocalFileSearchObservation): boolean {
  return (
    observation.kind === 'R0_LOCAL_FILE_SEARCH_OBSERVATION' &&
    observation.truncated === false &&
    observation.semanticVerified === false &&
    observation.cloudDisclosure === false &&
    Number.isSafeInteger(observation.inspectedEntries) &&
    observation.inspectedEntries >= 0 &&
    observation.inspectedEntries <= 4096 &&
    Array.isArray(observation.paths) &&
    observation.paths.length <= 128
  );
}

/**
 * Exactly one genuine native scan per invocation, bracketed by two
 * independent oracle walks of the same bounded scope. The receipt carries no
 * file names, absolute paths or content — only the verified classification.
 * The host-owned evidence sink (optionally supplied by the trusted bootstrap)
 * lets the separate task semantic verifier check expectations afterwards.
 */
export function executeTrustedWindowsR0Search(
  action: AuthorizedAction,
  evidenceSink?: (evidence: R0SearchEffectEvidence) => void,
): Promise<ExecutionReceipt> {
  return (async () => {
    const startedAt = new Date().toISOString();
    const emitUncertain = (fingerprintUnchanged = false, walk: OracleWalk | null = null) => {
      evidenceSink?.({
        effectObserved: false,
        fingerprintUnchanged,
        independentMatchesEqual: false,
        inspectedEntries: walk?.inspectedEntries ?? 0,
        matchedCount: walk?.matches.length ?? 0,
        verificationTimeIso: new Date().toISOString(),
      });
      return uncertainReceipt(action.actionId, startedAt);
    };
    try {
      if (process.platform !== 'win32') throw new Error(UNCERTAIN);
      if (!isR0SearchAction(action)) throw new Error(UNCERTAIN);
      const root = action.action.parameters.root;
      const query = action.action.parameters.query;
      if (typeof root !== 'string' || typeof query !== 'string') throw new Error(UNCERTAIN);

      const before = captureOracleWalk(root, query);
      if (!before.ok) throw new Error(UNCERTAIN);

      let observation: LocalFileSearchObservation;
      try {
        observation = observeScopedFileSearch(action);
      } catch {
        // Native refusal (junction/reparse/UNC/missing addon/bounds): no
        // verified effect. The durable STARTED row stays conservatively
        // UNKNOWN — the oracle cannot prove a scan never half-ran.
        throw new Error(UNCERTAIN);
      }
      if (!observationShape(observation)) throw new Error(UNCERTAIN);

      const after = captureOracleWalk(root, query);
      if (!after.ok) throw new Error(UNCERTAIN);
      const unchanged = oracleWalksEqual(before.walk, after.walk);
      const matchesEqual = oracleMatchesObservation(after.walk, observation.paths);
      if (!unchanged || !matchesEqual) {
        // Read-only R0 must not mutate; a match-set divergence between two
        // independent implementations is a common-mode or drift failure.
        evidenceSink?.({
          effectObserved: true,
          fingerprintUnchanged: unchanged,
          independentMatchesEqual: matchesEqual,
          inspectedEntries: after.walk.inspectedEntries,
          matchedCount: after.walk.matches.length,
          verificationTimeIso: new Date().toISOString(),
        });
        return uncertainReceipt(action.actionId, startedAt);
      }
      const receipt = ExecutionReceiptSchema.parse({
        actionId: action.actionId,
        environmentId: 'local-windows-user',
        providerId: 'shun-win32-r0-native',
        providerVersion: PROVIDER_VERSION,
        startedAt,
        finishedAt: new Date(Math.max(Date.now(), Date.parse(startedAt))).toISOString(),
        terminal: 'SUCCEEDED',
        outputRefs: [],
        sideEffectEvidence: {
          sideEffectClass: 'R0',
          recoveryClassification: 'COMPLETED_VERIFIED',
          postStateVerified: true,
          journalRef: JOURNAL_REF,
        },
      });
      evidenceSink?.({
        effectObserved: true,
        fingerprintUnchanged: true,
        independentMatchesEqual: true,
        inspectedEntries: after.walk.inspectedEntries,
        matchedCount: after.walk.matches.length,
        verificationTimeIso: new Date().toISOString(),
      });
      return receipt;
    } catch {
      // Never disclose scope paths, native errors or partial scans.
      return emitUncertain();
    }
  })();
}
