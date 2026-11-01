/**
 * J09 durable Host store for opt-in future-build Shadow candidates
 * (Owner authorization OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE).
 *
 * Implements the frozen `MetaFeedbackHostPort` contract from
 * domain-computer/feedback/meta-feedback.ts against real SQLite:
 *
 *   - `authorizeCurrentFeedback` resolves CURRENT opt-in consent bound to a
 *     genuine recorded outcome receipt (trusted Host composition records both
 *     artifacts; neither is ever HTTP input).
 *   - `runMetaFeedbackWorkflow` persists ONLY a `FUTURE_BUILD_SHADOW`,
 *     `active:false` candidate and atomically rechecks consentRef/
 *     currentnessRef at commit. Any promotion/activation shape is refused
 *     and never persisted; NO promote/activate API exists on this store.
 *
 * Digests use the same canonical shape as the computer package's adapter
 * (recursively key-sorted JSON) so the persisted digest is verifiable by
 * both sides.
 */
import { createHash, randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type {
  MetaFeedbackAuthorizationRequest,
  MetaFeedbackAuthorization,
  MetaFeedbackHostPort,
  MetaFeedbackSelection,
  MetaFeedbackShadowCandidate,
} from '../../../domain-computer/src/feedback/meta-feedback.ts';

const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/;

export interface MetaOutcomeReceiptInput {
  readonly caseRef: string;
  readonly revision: string;
  readonly sha256: string;
}

export interface MetaOptInConsentInput {
  readonly consentRef: string;
  readonly revision: string;
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly sourceDigest: string;
  readonly operatorId: string;
  readonly operatorSubjectRef: string;
  readonly authorizationRevision: string;
  readonly currentnessRef: string;
  readonly optIn: boolean;
  readonly expiresAt: string;
}

export interface StoredShadowCandidate {
  readonly candidateId: string;
  readonly candidateDigest: string;
  readonly lifecycle: 'FUTURE_BUILD_SHADOW';
  readonly active: false;
  readonly payloadJson: string;
  readonly createdAt: string;
}

/** Snake-case SQLite row shape of `meta_opt_in_consents`. */
interface ConsentRow {
  readonly consent_ref: string;
  readonly revision: string;
  readonly case_ref: string;
  readonly source_revision: string;
  readonly source_digest: string;
  readonly operator_id: string;
  readonly operator_subject_ref: string;
  readonly authorization_revision: string;
  readonly currentness_ref: string;
  readonly opt_in: number;
  readonly expires_at: string;
}

function isSafeRef(value: unknown): value is string {
  return typeof value === 'string' && SAFE_REF.test(value);
}

function isIsoUtc(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    ISO_UTC.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(Date.parse(value)).toISOString() === value
  );
}

/** Same canonical shape as the adapter's `stableValue`/`digestCandidate`. */
function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => [key, stableValue((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

export function canonicalCandidateDigest(candidate: MetaFeedbackShadowCandidate): string {
  return createHash('sha256').update(JSON.stringify(stableValue(candidate)), 'utf8').digest('hex');
}

/**
 * Durable opt-in Shadow candidate store. The file must be an absolute path on
 * local disk (same rule as the other trusted Host SQLite stores).
 */
export class HostMetaShadowStore implements MetaFeedbackHostPort {
  readonly #db: DatabaseSync;

  constructor(file: string) {
    if (typeof file !== 'string' || !isAbsolute(file) || file.endsWith(':memory:')) {
      throw new TypeError('META_SHADOW_DURABLE_FILE_REQUIRED');
    }
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_outcome_receipts (
      case_ref TEXT NOT NULL,
      revision TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      PRIMARY KEY (case_ref, revision)
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_opt_in_consents (
      consent_ref TEXT PRIMARY KEY,
      revision TEXT NOT NULL,
      case_ref TEXT NOT NULL,
      source_revision TEXT NOT NULL,
      source_digest TEXT NOT NULL,
      operator_id TEXT NOT NULL,
      operator_subject_ref TEXT NOT NULL,
      authorization_revision TEXT NOT NULL,
      currentness_ref TEXT NOT NULL,
      opt_in INTEGER NOT NULL,
      expires_at TEXT NOT NULL
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_shadow_candidates (
      candidate_id TEXT PRIMARY KEY,
      candidate_digest TEXT NOT NULL,
      lifecycle TEXT NOT NULL CHECK (lifecycle = 'FUTURE_BUILD_SHADOW'),
      active INTEGER NOT NULL CHECK (active = 0),
      payload_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
  }

  /** Trusted Host composition records a genuine journey outcome receipt. */
  recordOutcomeReceipt(input: MetaOutcomeReceiptInput): void {
    if (
      !isSafeRef(input.caseRef) ||
      !isSafeRef(input.revision) ||
      !SHA256.test(input.sha256)
    ) {
      throw new TypeError('META_RECEIPT_INVALID');
    }
    this.#db
      .prepare(
        'INSERT OR REPLACE INTO meta_outcome_receipts(case_ref,revision,sha256,recorded_at) VALUES(?,?,?,?)',
      )
      .run(input.caseRef, input.revision, input.sha256, new Date().toISOString());
  }

  /** Trusted operator opt-in (a separate, explicit human action). */
  recordOptInConsent(input: MetaOptInConsentInput): void {
    if (
      !isSafeRef(input.consentRef) ||
      !isSafeRef(input.revision) ||
      !isSafeRef(input.caseRef) ||
      !isSafeRef(input.sourceRevision) ||
      !SHA256.test(input.sourceDigest) ||
      !isSafeRef(input.operatorId) ||
      !isSafeRef(input.operatorSubjectRef) ||
      !isSafeRef(input.authorizationRevision) ||
      !isSafeRef(input.currentnessRef) ||
      !isIsoUtc(input.expiresAt)
    ) {
      throw new TypeError('META_CONSENT_INVALID');
    }
    this.#db
      .prepare(
        `INSERT OR REPLACE INTO meta_opt_in_consents(
           consent_ref,revision,case_ref,source_revision,source_digest,
           operator_id,operator_subject_ref,authorization_revision,
           currentness_ref,opt_in,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        input.consentRef,
        input.revision,
        input.caseRef,
        input.sourceRevision,
        input.sourceDigest,
        input.operatorId,
        input.operatorSubjectRef,
        input.authorizationRevision,
        input.currentnessRef,
        input.optIn ? 1 : 0,
        input.expiresAt,
      );
  }

  /**
   * Resolve CURRENT opt-in consent bound to the latest recorded genuine
   * outcome receipt for the case. Throwing (or a non-AUTHORIZED shape) maps
   * to FEEDBACK_AUTHORITY_UNAVAILABLE / FEEDBACK_AUTHORIZATION_INVALID in
   * the adapter — never to a stored candidate.
   */
  async authorizeCurrentFeedback(input: MetaFeedbackAuthorizationRequest): Promise<unknown> {
    if (
      input.scope !== 'META_FEEDBACK_SHADOW' ||
      !isSafeRef(input.caseRef) ||
      !isSafeRef(input.sourceRevision)
    ) {
      throw new Error('META_AUTHORITY_REFUSED');
    }
    const consent = this.#db
      .prepare(
        'SELECT * FROM meta_opt_in_consents WHERE case_ref=? AND source_revision=? AND opt_in=1',
      )
      .get(input.caseRef, input.sourceRevision) as ConsentRow | undefined;
    if (consent === undefined) throw new Error('META_OPT_IN_MISSING');
    const expiresAt: string = consent.expires_at;
    const nowIso = new Date().toISOString();
    if (!isIsoUtc(expiresAt) || Date.parse(expiresAt) <= Date.parse(nowIso)) {
      throw new Error('META_CONSENT_EXPIRED');
    }
    // The receipt this consent points at must be the CURRENT recorded
    // revision for the case — a stale receipt cannot authorize feedback.
    const receipt = this.#db
      .prepare(
        'SELECT revision, sha256 FROM meta_outcome_receipts WHERE case_ref=? ORDER BY recorded_at DESC, revision DESC LIMIT 1',
      )
      .get(input.caseRef) as { revision: string; sha256: string } | undefined;
    if (
      receipt === undefined ||
      receipt.revision !== input.sourceRevision ||
      receipt.sha256 !== consent.source_digest
    ) {
      throw new Error('META_RECEIPT_NOT_CURRENT');
    }
    return {
      status: 'AUTHORIZED',
      scope: 'META_FEEDBACK_SHADOW',
      candidateId: `meta-shadow-${randomUUID()}`,
      caseRef: consent.case_ref,
      sourceRevision: consent.source_revision,
      sourceDigest: consent.source_digest,
      evidenceOwnerRef: consent.operator_subject_ref,
      operatorSubjectRef: consent.operator_subject_ref,
      operatorId: consent.operator_id,
      consentRef: consent.consent_ref,
      consentRevision: consent.revision,
      consentExpiresAt: consent.expires_at,
      authorizationRevision: consent.authorization_revision,
      currentnessRef: consent.currentness_ref,
      selection: input.selection,
    } satisfies MetaFeedbackAuthorization;
  }

  /**
   * Persist only a future-build Shadow candidate. Atomically rechecks the
   * consentRef/currentnessRef record; refuses (and never persists) any
   * promotion/activation shape. Idempotent for the identical candidate.
   */
  async runMetaFeedbackWorkflow(input: {
    readonly candidate: MetaFeedbackShadowCandidate;
    readonly authorization: MetaFeedbackAuthorization;
  }): Promise<unknown> {
    const { candidate, authorization } = input;
    if (
      candidate.kind !== 'META_FEEDBACK' ||
      candidate.lifecycle !== 'FUTURE_BUILD_SHADOW' ||
      candidate.active !== false
    ) {
      throw new Error('META_PROMOTION_REFUSED');
    }
    const digest = canonicalCandidateDigest(candidate);
    if (digest !== canonicalDigestOfAuthorizationBinding(candidate, authorization)) {
      throw new Error('META_CANDIDATE_PROVENANCE_MISMATCH');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const consent = this.#db
        .prepare('SELECT * FROM meta_opt_in_consents WHERE consent_ref=?')
        .get(authorization.consentRef) as ConsentRow | undefined;
      const nowIso = new Date().toISOString();
      if (
        consent === undefined ||
        consent.opt_in !== 1 ||
        !isIsoUtc(consent.expires_at) ||
        Date.parse(consent.expires_at) <= Date.parse(nowIso) ||
        consent.currentness_ref !== authorization.currentnessRef ||
        consent.revision !== authorization.consentRevision
      ) {
        this.#db.exec('ROLLBACK');
        throw new Error('META_CONSENT_NOT_CURRENT');
      }
      const existing = this.#db
        .prepare('SELECT candidate_digest FROM meta_shadow_candidates WHERE candidate_id=?')
        .get(candidate.candidateId) as { candidate_digest: string } | undefined;
      if (existing !== undefined) {
        this.#db.exec('COMMIT');
        if (existing.candidate_digest !== digest) throw new Error('META_CANDIDATE_CONFLICT');
        return {
          status: 'SHADOW_STORED',
          candidateRef: candidate.candidateId,
          candidateDigest: digest,
          active: false,
        };
      }
      this.#db
        .prepare(
          `INSERT INTO meta_shadow_candidates(
             candidate_id,candidate_digest,lifecycle,active,payload_json,created_at)
           VALUES(?,?,?,0,?,?)`,
        )
        .run(
          candidate.candidateId,
          digest,
          candidate.lifecycle,
          JSON.stringify(candidate),
          nowIso,
        );
      this.#db.exec('COMMIT');
      return {
        status: 'SHADOW_STORED',
        candidateRef: candidate.candidateId,
        candidateDigest: digest,
        active: false,
      };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /** Read back a persisted candidate (verification/evidence path only). */
  readShadowCandidate(candidateId: string): StoredShadowCandidate | undefined {
    if (!isSafeRef(candidateId)) return undefined;
    const row = this.#db
      .prepare('SELECT * FROM meta_shadow_candidates WHERE candidate_id=?')
      .get(candidateId) as
      | {
          candidate_id: string;
          candidate_digest: string;
          lifecycle: string;
          active: number;
          payload_json: string;
          created_at: string;
        }
      | undefined;
    if (row === undefined) return undefined;
    return {
      candidateId: row.candidate_id,
      candidateDigest: row.candidate_digest,
      lifecycle: 'FUTURE_BUILD_SHADOW',
      active: false,
      payloadJson: row.payload_json,
      createdAt: row.created_at,
    };
  }

  listShadowCandidates(): readonly StoredShadowCandidate[] {
    return (
      this.#db
        .prepare('SELECT candidate_id FROM meta_shadow_candidates ORDER BY created_at')
        .all() as { candidate_id: string }[]
    ).map((row) => this.readShadowCandidate(row.candidate_id) as StoredShadowCandidate);
  }

  close(): void {
    this.#db.close();
  }

  #rollback(): void {
    try {
      this.#db.exec('ROLLBACK');
    } catch {
      /* retain unknown; never a false receipt */
    }
  }
}

/**
 * The candidate must carry exactly the authorization's provenance (operator,
 * consent, currentness). Any drift between the two halves is a provenance
 * forgery and is refused before the transaction.
 */
function canonicalDigestOfAuthorizationBinding(
  candidate: MetaFeedbackShadowCandidate,
  authorization: MetaFeedbackAuthorization,
): string {
  if (
    candidate.candidateId !== authorization.candidateId ||
    candidate.provenance.operatorId !== authorization.operatorId ||
    candidate.provenance.operatorSubjectRef !== authorization.operatorSubjectRef ||
    candidate.provenance.consentRef !== authorization.consentRef ||
    candidate.provenance.consentRevision !== authorization.consentRevision ||
    candidate.provenance.consentExpiresAt !== authorization.consentExpiresAt ||
    candidate.provenance.authorizationRevision !== authorization.authorizationRevision ||
    candidate.provenance.currentnessRef !== authorization.currentnessRef ||
    candidate.source.caseRef !== authorization.caseRef ||
    candidate.source.revision !== authorization.sourceRevision ||
    candidate.source.sha256 !== authorization.sourceDigest
  ) {
    throw new Error('META_CANDIDATE_PROVENANCE_MISMATCH');
  }
  return canonicalCandidateDigest(candidate);
}
