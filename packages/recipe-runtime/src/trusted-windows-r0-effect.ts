// T04 trusted private Windows host effect: composes the independently
// reviewed native R0 search port with the SEPARATE post-state oracle from
// r0-independent-poststate-oracle.ts.
//
// Receipt phase ordering (R2 P1-02): a positive receipt (SUCCEEDED +
// COMPLETED_VERIFIED + postStateVerified=true) is minted ONLY after
//   1. the bounded native scan completed inside two independent oracle
//      walks whose identity fingerprints (including content digests) match,
//   2. the exact task/action/intent + immutable expected-state commitment
//      (pre-state fingerprint, observation digest, post-state fingerprint)
//      has been durably persisted as a phase receipt in the trusted host's
//      journal AND re-read back with a consistent digest, and
//   3. the receipt cites that real phase receipt digest (journalRef) —
//      never a constant table name.
// Without a trusted phase journal port, no positive receipt exists at all:
// every other outcome is the conservative UNCERTAIN receipt; the journaled
// capability then keeps STARTED/UNCERTAIN and never replays. The separate
// journal recordObservation (receipt digest after the effect returns)
// belongs to JournaledR0SearchCapability. This function must only be wired
// by the fixed private host bootstrap, never by Recipe/model/HTTP.
import { createHash } from 'node:crypto';
import {
  type AuthorizedAction,
  canonicalJson,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import {
  captureOracleWalk,
  isR0SearchAction,
  type OracleInstrument,
  type OracleWalk,
  oracleMatchesObservation,
  oracleWalksEqual,
} from './r0-independent-poststate-oracle.ts';
import { type LocalFileSearchObservation, observeScopedFileSearch } from './scoped-file-search.ts';

const UNCERTAIN = 'R0_NATIVE_EFFECT_UNCERTAIN';
const PROVIDER_VERSION = '0.2.0';
const PHASE_TABLE = 'recipe_r0_effect_phase_v02';

/** The immutable expected-state commitment persisted by the trusted host. */
export type R0EffectPhaseCommitment = Readonly<{
  expectedStateSha256: string;
  observationSha256: string;
  postStateSha256: string;
}>;

/**
 * Host-owned phase receipt port backed by the durable effect journal. The
 * trusted bootstrap wires the SAME SQLite store the journaled capability
 * reserves in; a phase receipt can only exist for a durably reserved
 * attempt identity.
 */
export type R0EffectPhasePort = Readonly<{
  recordEffectPhase: (
    action: AuthorizedAction,
    commitment: R0EffectPhaseCommitment,
  ) => { ok: true; phaseReceiptSha256: string } | { ok: false };
  lookupEffectPhase: (
    action: AuthorizedAction,
  ) =>
    | { ok: true; commitment: R0EffectPhaseCommitment; phaseReceiptSha256: string }
    | { ok: false };
}>;

/** Host-side summary for the separate task semantic verifier. No paths. */
export type R0SearchEffectEvidence = Readonly<{
  effectObserved: boolean;
  fingerprintUnchanged: boolean;
  independentMatchesEqual: boolean;
  inspectedEntries: number;
  matchedCount: number;
  verificationTimeIso: string;
  postStateSha256: string;
}>;

export type TrustedR0SearchPorts = Readonly<{
  phaseJournal?: R0EffectPhasePort;
  evidenceSink?: (evidence: R0SearchEffectEvidence) => void;
  instrument?: OracleInstrument;
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

/** Digest over the bounded observation, independent of any file content. */
function observationDigest(observation: LocalFileSearchObservation): string {
  return createHash('sha256')
    .update(
      canonicalJson({
        kind: observation.kind,
        paths: [...observation.paths].sort(),
        inspectedEntries: observation.inspectedEntries,
        truncated: observation.truncated,
      }),
    )
    .digest('hex');
}

/**
 * Exactly one genuine native scan per invocation, bracketed by two
 * independent oracle walks of the same bounded scope. The receipt carries no
 * file names, absolute paths or content — only the verified classification.
 * The host-owned evidence sink lets the separate task semantic verifier check
 * expectations afterwards against the effect-time post-state fingerprint.
 */
export function executeTrustedWindowsR0Search(
  action: AuthorizedAction,
  ports: TrustedR0SearchPorts = {},
): Promise<ExecutionReceipt> {
  return (async () => {
    const startedAt = new Date().toISOString();
    const emitUncertain = (
      fingerprintUnchanged = false,
      walk: OracleWalk | null = null,
      matchesEqual = false,
    ) => {
      ports.evidenceSink?.({
        effectObserved: walk !== null,
        fingerprintUnchanged,
        independentMatchesEqual: matchesEqual,
        inspectedEntries: walk?.inspectedEntries ?? 0,
        matchedCount: walk?.matches.length ?? 0,
        verificationTimeIso: new Date().toISOString(),
        postStateSha256: walk?.fingerprint ?? '',
      });
      return uncertainReceipt(action.actionId, startedAt);
    };
    try {
      if (process.platform !== 'win32') throw new Error(UNCERTAIN);
      if (!isR0SearchAction(action)) throw new Error(UNCERTAIN);
      const root = action.action.parameters.root;
      const query = action.action.parameters.query;
      if (typeof root !== 'string' || typeof query !== 'string') throw new Error(UNCERTAIN);

      const instrument = ports.instrument ?? {};
      const before = captureOracleWalk(root, query, instrument);
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

      const after = captureOracleWalk(root, query, instrument);
      if (!after.ok) throw new Error(UNCERTAIN);
      const unchanged = oracleWalksEqual(before.walk, after.walk);
      const matchesEqual = oracleMatchesObservation(after.walk, observation.paths);
      if (!unchanged || !matchesEqual) {
        // Read-only R0 must not mutate; a match-set divergence between two
        // independent implementations is a common-mode or drift failure.
        // The content-bound fingerprint also catches a swap that preserves
        // superficial size/mtime.
        ports.evidenceSink?.({
          effectObserved: true,
          fingerprintUnchanged: unchanged,
          independentMatchesEqual: matchesEqual,
          inspectedEntries: after.walk.inspectedEntries,
          matchedCount: after.walk.matches.length,
          verificationTimeIso: new Date().toISOString(),
          postStateSha256: after.walk.fingerprint,
        });
        return uncertainReceipt(action.actionId, startedAt);
      }

      // Phase receipt first: the immutable commitment is durably persisted
      // against the reserved attempt identity and re-read back before any
      // positive classification exists. Absence, corruption or divergence
      // all degrade to UNCERTAIN.
      const phaseJournal = ports.phaseJournal;
      if (!phaseJournal) throw new Error(UNCERTAIN);
      const commitment: R0EffectPhaseCommitment = {
        expectedStateSha256: before.walk.fingerprint,
        observationSha256: observationDigest(observation),
        postStateSha256: after.walk.fingerprint,
      };
      let phaseReceiptSha256: string | null = null;
      const recorded = phaseJournal.recordEffectPhase(action, commitment);
      if (!recorded.ok) throw new Error(UNCERTAIN);
      phaseReceiptSha256 = recorded.phaseReceiptSha256;
      const readback = phaseJournal.lookupEffectPhase(action);
      if (
        !readback.ok ||
        readback.phaseReceiptSha256 !== phaseReceiptSha256 ||
        readback.commitment.expectedStateSha256 !== commitment.expectedStateSha256 ||
        readback.commitment.observationSha256 !== commitment.observationSha256 ||
        readback.commitment.postStateSha256 !== commitment.postStateSha256
      )
        throw new Error(UNCERTAIN);

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
          journalRef: `${PHASE_TABLE}:${phaseReceiptSha256}`,
        },
      });
      ports.evidenceSink?.({
        effectObserved: true,
        fingerprintUnchanged: true,
        independentMatchesEqual: true,
        inspectedEntries: after.walk.inspectedEntries,
        matchedCount: after.walk.matches.length,
        verificationTimeIso: new Date().toISOString(),
        postStateSha256: after.walk.fingerprint,
      });
      return receipt;
    } catch {
      // Never disclose scope paths, native errors or partial scans.
      return emitUncertain();
    }
  })();
}
