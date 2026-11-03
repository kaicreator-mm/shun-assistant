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
 *   - Consent is single-current per (caseRef, sourceRevision): only the most
 *     recently declared consent row authorizes, where recency is a durable
 *     transactional declaration-order sequence — never string ordering of the
 *     opaque revision. A later opt-out supersedes every historical opt-in row
 *     and immediately revokes the experiences derived from that source; a
 *     later opt-in authorizes new records but never resurrects revoked ones.
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
  MetaFeedbackAuthorization,
  MetaFeedbackAuthorizationRequest,
  MetaFeedbackHostPort,
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

/**
 * Closed-world normalized verified experience shared across Cases.
 * Every identifier must be a registered vocabulary code; tags and constraint
 * codes are bounded catalogued tokens — never free text, paths or secrets.
 */
export type MetaVerifiedOutcome = 'VERIFIED_PASS' | 'VERIFIED_FAIL';

export interface MetaVerifiedExperienceInput {
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly sourceDigest: string;
  readonly capabilityId: string;
  readonly taskClass: string;
  readonly patternId: string;
  readonly verifiedOutcome: MetaVerifiedOutcome;
  readonly tags: readonly string[];
  readonly constraintCodes: readonly string[];
}

/** Advisory-only query result; carries no executable authority surface. */
export interface MetaVerifiedExperienceRecord {
  readonly experienceId: string;
  readonly capabilityId: string;
  readonly taskClass: string;
  readonly patternId: string;
  readonly verifiedOutcome: MetaVerifiedOutcome;
  readonly tags: readonly string[];
  readonly constraintCodes: readonly string[];
  readonly provenance: Readonly<{
    readonly sourceCaseRef: string;
    readonly sourceRevision: string;
    readonly sourceDigest: string;
    readonly receiptRecordedAt: string;
    readonly consentRef: string;
  }>;
  readonly advisoryOnly: true;
  readonly feedbackCandidateRef: string | undefined;
  readonly recordedAt: string;
}

export interface MetaExperienceQueryInput {
  /** The Case asking; never an equality gate against the source Case. */
  readonly targetCaseRef: string;
  readonly capabilityId: string;
  readonly taskClass?: string;
  readonly limit?: number;
}

const EXPERIENCE_CODE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_EXPERIENCE_TAGS = 8;
const MAX_EXPERIENCE_CONSTRAINT_CODES = 16;
const DEFAULT_EXPERIENCE_QUERY_LIMIT = 10;
const MAX_EXPERIENCE_QUERY_LIMIT = 20;

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
  readonly declaration_seq: number;
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
  return createHash('sha256')
    .update(JSON.stringify(stableValue(candidate)), 'utf8')
    .digest('hex');
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
      expires_at TEXT NOT NULL,
      declaration_seq INTEGER NOT NULL DEFAULT 0
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_shadow_candidates (
      candidate_id TEXT PRIMARY KEY,
      candidate_digest TEXT NOT NULL,
      lifecycle TEXT NOT NULL CHECK (lifecycle = 'FUTURE_BUILD_SHADOW'),
      active INTEGER NOT NULL CHECK (active = 0),
      payload_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_experience_vocabulary (
      kind TEXT NOT NULL CHECK (kind IN ('capability','task_class','pattern','tag','constraint_code')),
      code TEXT NOT NULL,
      registered_at TEXT NOT NULL,
      PRIMARY KEY (kind, code)
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_verified_experiences (
      experience_id TEXT PRIMARY KEY,
      case_ref TEXT NOT NULL,
      source_revision TEXT NOT NULL,
      source_digest TEXT NOT NULL,
      capability_id TEXT NOT NULL,
      task_class TEXT NOT NULL,
      pattern_id TEXT NOT NULL,
      verified_outcome TEXT NOT NULL CHECK (verified_outcome IN ('VERIFIED_PASS','VERIFIED_FAIL')),
      tags_json TEXT NOT NULL,
      constraint_codes_json TEXT NOT NULL,
      experience_digest TEXT NOT NULL,
      consent_ref TEXT NOT NULL,
      receipt_recorded_at TEXT NOT NULL,
      feedback_candidate_ref TEXT,
      recorded_at TEXT NOT NULL,
      revoked_at TEXT
    )`);
    this.#db.exec(`CREATE INDEX IF NOT EXISTS idx_meta_experiences_capability
      ON meta_verified_experiences(capability_id, task_class, revoked_at)`);
    this.#db.exec(`CREATE INDEX IF NOT EXISTS idx_meta_experiences_source
      ON meta_verified_experiences(case_ref, source_revision)`);
    this.#migrateConsentDeclarationOrder();
  }

  /**
   * Trusted Host composition records a genuine journey outcome receipt.
   * A receipt revision is immutable evidence: re-recording the identical
   * digest is an idempotent no-op, while the same revision with a different
   * digest is an evidence forgery and conflicts instead of replacing.
   */
  recordOutcomeReceipt(input: MetaOutcomeReceiptInput): void {
    if (!isSafeRef(input.caseRef) || !isSafeRef(input.revision) || !SHA256.test(input.sha256)) {
      throw new TypeError('META_RECEIPT_INVALID');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.#db
        .prepare('SELECT sha256 FROM meta_outcome_receipts WHERE case_ref=? AND revision=?')
        .get(input.caseRef, input.revision) as { sha256: string } | undefined;
      if (existing !== undefined) {
        this.#db.exec('COMMIT');
        if (existing.sha256 !== input.sha256) throw new Error('META_RECEIPT_CONFLICT');
        return;
      }
      this.#db
        .prepare(
          'INSERT INTO meta_outcome_receipts(case_ref,revision,sha256,recorded_at) VALUES(?,?,?,?)',
        )
        .run(input.caseRef, input.revision, input.sha256, new Date().toISOString());
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /**
   * Trusted operator consent action (a separate, explicit human action).
   * Serialized current-consent update for the exact (caseRef, sourceRevision):
   * each write takes the next declaration-order sequence value, so the latest
   * declaration supersedes every earlier consent row. An
   * opt-out also immediately revokes every still-eligible experience derived
   * from that source, so withdrawn consent excludes existing records at once
   * and across restarts; a later opt-in authorizes new records only and never
   * resurrects the revoked ones.
   */
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
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      // The sequence value is assigned under the write lock, so it reflects
      // real declaration order regardless of how revision strings compare.
      const nextSeq = (
        this.#db
          .prepare(
            `SELECT COALESCE(MAX(declaration_seq),0)+1 AS next_seq
             FROM meta_opt_in_consents WHERE case_ref=? AND source_revision=?`,
          )
          .get(input.caseRef, input.sourceRevision) as { next_seq: number }
      ).next_seq;
      this.#db
        .prepare(
          `INSERT OR REPLACE INTO meta_opt_in_consents(
             consent_ref,revision,case_ref,source_revision,source_digest,
             operator_id,operator_subject_ref,authorization_revision,
             currentness_ref,opt_in,expires_at,declaration_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
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
          nextSeq,
        );
      if (!input.optIn) {
        this.#db
          .prepare(
            `UPDATE meta_verified_experiences SET revoked_at=?
             WHERE case_ref=? AND source_revision=? AND revoked_at IS NULL`,
          )
          .run(new Date().toISOString(), input.caseRef, input.sourceRevision);
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#rollback();
      throw error;
    }
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
    // Only the CURRENT consent can authorize feedback: a newer opt-out for
    // the same source supersedes every historical opt_in=1 row.
    const consent = this.#currentConsent(input.caseRef, input.sourceRevision);
    if (consent === undefined || consent.opt_in !== 1) {
      throw new Error('META_OPT_IN_MISSING');
    }
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
        consent.revision !== authorization.consentRevision ||
        !this.#isCurrentConsent(consent)
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
        .run(candidate.candidateId, digest, candidate.lifecycle, JSON.stringify(candidate), nowIso);
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

  // ---------------------------------------------------------------------
  // Closed-world cross-Case verified experience (advisory-only).
  // All identifiers come from an explicit trusted-Host vocabulary; the store
  // rejects anything outside it, so no free text, path or secret-shaped
  // value can enter the shared table.
  // ---------------------------------------------------------------------

  registerMetaCapabilityId(capabilityId: string): void {
    this.#registerVocabularyCode('capability', capabilityId);
  }

  registerMetaTaskClass(taskClass: string): void {
    this.#registerVocabularyCode('task_class', taskClass);
  }

  registerMetaPatternId(patternId: string): void {
    this.#registerVocabularyCode('pattern', patternId);
  }

  registerMetaExperienceTag(tag: string): void {
    this.#registerVocabularyCode('tag', tag);
  }

  registerMetaConstraintCode(code: string): void {
    this.#registerVocabularyCode('constraint_code', code);
  }

  #registerVocabularyCode(kind: MetaExperienceVocabularyKind, code: string): void {
    if (!isExperienceCode(code)) throw new TypeError('META_EXPERIENCE_VOCABULARY_INVALID');
    this.#db
      .prepare(
        'INSERT OR IGNORE INTO meta_experience_vocabulary(kind,code,registered_at) VALUES(?,?,?)',
      )
      .run(kind, code, new Date().toISOString());
  }

  #isVocabularyRegistered(kind: MetaExperienceVocabularyKind, code: string): boolean {
    if (!isExperienceCode(code)) return false;
    return (
      this.#db
        .prepare('SELECT code FROM meta_experience_vocabulary WHERE kind=? AND code=?')
        .get(kind, code) !== undefined
    );
  }

  /**
   * Persist a privacy-minimized verified experience bound to the CURRENT
   * genuine outcome receipt and an unexpired explicit Meta opt-in consent of
   * its source Case. Idempotent for the identical normalized record.
   */
  recordSharedExperience(input: MetaVerifiedExperienceInput): {
    status: 'STORED' | 'ALREADY_STORED';
    experienceId: string;
    experienceDigest: string;
  } {
    const normalized = normalizeExperienceInput(input);
    const vocabulary: readonly [MetaExperienceVocabularyKind, string][] = [
      ['capability', normalized.capabilityId],
      ['task_class', normalized.taskClass],
      ['pattern', normalized.patternId],
      ...normalized.tags.map((tag): [MetaExperienceVocabularyKind, string] => ['tag', tag]),
      ...normalized.constraintCodes.map((code): [MetaExperienceVocabularyKind, string] => [
        'constraint_code',
        code,
      ]),
    ];
    for (const [kind, code] of vocabulary) {
      if (!this.#isVocabularyRegistered(kind, code)) {
        throw new TypeError('META_EXPERIENCE_VOCABULARY_UNKNOWN');
      }
    }
    const digest = canonicalExperienceDigest(normalized);
    const experienceId = `meta-exp-${digest}`;
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#assertCurrentExperienceEvidence(normalized);
      const existing = this.#db
        .prepare(
          'SELECT experience_digest, consent_ref FROM meta_verified_experiences WHERE experience_id=?',
        )
        .get(experienceId) as { experience_digest: string; consent_ref: string } | undefined;
      if (existing !== undefined) {
        this.#db.exec('COMMIT');
        if (
          existing.experience_digest !== digest ||
          existing.consent_ref !== normalized.consentRef
        ) {
          throw new Error('META_EXPERIENCE_CONFLICT');
        }
        return { status: 'ALREADY_STORED', experienceId, experienceDigest: digest };
      }
      this.#db
        .prepare(
          `INSERT INTO meta_verified_experiences(
             experience_id,case_ref,source_revision,source_digest,
             capability_id,task_class,pattern_id,verified_outcome,
             tags_json,constraint_codes_json,experience_digest,
             consent_ref,receipt_recorded_at,feedback_candidate_ref,recorded_at,revoked_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,NULL)`,
        )
        .run(
          experienceId,
          normalized.caseRef,
          normalized.sourceRevision,
          normalized.sourceDigest,
          normalized.capabilityId,
          normalized.taskClass,
          normalized.patternId,
          normalized.verifiedOutcome,
          JSON.stringify(normalized.tags),
          JSON.stringify(normalized.constraintCodes),
          digest,
          normalized.consentRef,
          normalized.receiptRecordedAt,
          new Date().toISOString(),
        );
      this.#db.exec('COMMIT');
      return { status: 'STORED', experienceId, experienceDigest: digest };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /**
   * Advisory-only cross-Case retrieval. The asking Case is provenance
   * metadata, never an authorization gate: any Case may retrieve eligible
   * experience recorded by another Case. Currentness (receipt, consent,
   * revocation, integrity) is revalidated inside one read snapshot so the
   * result is consistent at a single point in time.
   */
  querySharedExperiences(input: MetaExperienceQueryInput): readonly MetaVerifiedExperienceRecord[] {
    if (
      !isSafeRef(input.targetCaseRef) ||
      !isExperienceCode(input.capabilityId) ||
      (input.taskClass !== undefined && !isExperienceCode(input.taskClass)) ||
      (input.limit !== undefined &&
        (!Number.isInteger(input.limit) ||
          input.limit < 1 ||
          input.limit > MAX_EXPERIENCE_QUERY_LIMIT))
    ) {
      throw new TypeError('META_EXPERIENCE_QUERY_INVALID');
    }
    if (!this.#isVocabularyRegistered('capability', input.capabilityId)) {
      throw new TypeError('META_EXPERIENCE_QUERY_INVALID');
    }
    if (
      input.taskClass !== undefined &&
      !this.#isVocabularyRegistered('task_class', input.taskClass)
    ) {
      throw new TypeError('META_EXPERIENCE_QUERY_INVALID');
    }
    const limit = input.limit ?? DEFAULT_EXPERIENCE_QUERY_LIMIT;
    // Overscan a bounded window so stale/malformed exclusions do not starve
    // the requested result count; the returned set is still capped at limit.
    const scanLimit = Math.min(limit * 4, 80);
    // One deferred read transaction wraps candidate selection AND every
    // currentness re-read, so the result is consistent at one snapshot even
    // when another store handle commits a newer receipt/revocation mid-query.
    this.#db.exec('BEGIN DEFERRED');
    try {
      const rows = (
        input.taskClass === undefined
          ? this.#db
              .prepare(
                `SELECT * FROM meta_verified_experiences
                 WHERE capability_id=? AND revoked_at IS NULL
                 ORDER BY recorded_at DESC, experience_id ASC LIMIT ?`,
              )
              .all(input.capabilityId, scanLimit)
          : this.#db
              .prepare(
                `SELECT * FROM meta_verified_experiences
                 WHERE capability_id=? AND task_class=? AND revoked_at IS NULL
                 ORDER BY recorded_at DESC, experience_id ASC LIMIT ?`,
              )
              .all(input.capabilityId, input.taskClass, scanLimit)
      ) as unknown as ExperienceRow[];
      const records: MetaVerifiedExperienceRecord[] = [];
      for (const row of rows) {
        const record = this.#revalidateExperienceRow(row);
        if (record !== undefined) records.push(record);
        if (records.length === limit) break;
      }
      this.#db.exec('COMMIT');
      return records;
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /**
   * Explicit Host revocation of experiences recorded from one source
   * (optionally narrowed to one receipt revision). Revoked records are
   * excluded from every later query; the rows are retained for provenance.
   */
  revokeSourceExperiences(input: {
    readonly caseRef: string;
    readonly sourceRevision?: string;
  }): number {
    if (
      !isSafeRef(input.caseRef) ||
      (input.sourceRevision !== undefined && !isSafeRef(input.sourceRevision))
    ) {
      throw new TypeError('META_EXPERIENCE_REVOKE_INVALID');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result =
        input.sourceRevision === undefined
          ? this.#db
              .prepare(
                'UPDATE meta_verified_experiences SET revoked_at=? WHERE case_ref=? AND revoked_at IS NULL',
              )
              .run(new Date().toISOString(), input.caseRef)
          : this.#db
              .prepare(
                'UPDATE meta_verified_experiences SET revoked_at=? WHERE case_ref=? AND source_revision=? AND revoked_at IS NULL',
              )
              .run(new Date().toISOString(), input.caseRef, input.sourceRevision);
      this.#db.exec('COMMIT');
      return Number(result.changes);
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /**
   * Attach an existing persisted Shadow feedback candidate as advisory
   * metadata of an experience. The candidate row itself is never touched:
   * it stays `FUTURE_BUILD_SHADOW` and inactive; this creates no promotion,
   * activation or approval surface.
   */
  attachExperienceFeedbackMetadata(input: {
    readonly experienceId: string;
    readonly candidateId: string;
  }): void {
    if (!isSafeRef(input.experienceId) || !isSafeRef(input.candidateId)) {
      throw new TypeError('META_EXPERIENCE_FEEDBACK_INVALID');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const experience = this.#db
        .prepare(
          'SELECT experience_id FROM meta_verified_experiences WHERE experience_id=? AND revoked_at IS NULL',
        )
        .get(input.experienceId);
      if (experience === undefined) {
        this.#db.exec('ROLLBACK');
        throw new Error('META_EXPERIENCE_NOT_FOUND');
      }
      const candidate = this.#db
        .prepare('SELECT lifecycle, active FROM meta_shadow_candidates WHERE candidate_id=?')
        .get(input.candidateId) as { lifecycle: string; active: number } | undefined;
      if (
        candidate === undefined ||
        candidate.lifecycle !== 'FUTURE_BUILD_SHADOW' ||
        candidate.active !== 0
      ) {
        this.#db.exec('ROLLBACK');
        throw new Error('META_FEEDBACK_CANDIDATE_INVALID');
      }
      this.#db
        .prepare(
          'UPDATE meta_verified_experiences SET feedback_candidate_ref=? WHERE experience_id=?',
        )
        .run(input.candidateId, input.experienceId);
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /**
   * Currentness re-check shared by record and query paths: the referenced
   * receipt must still be the Case's CURRENT revision with the exact digest,
   * and the CURRENT consent for the source must be an unexpired opt-in —
   * never merely a historical opt_in=1 row.
   */
  #assertCurrentExperienceEvidence(normalized: NormalizedExperience): void {
    const receipt = this.#latestReceipt(normalized.caseRef);
    if (
      receipt === undefined ||
      receipt.revision !== normalized.sourceRevision ||
      receipt.sha256 !== normalized.sourceDigest
    ) {
      throw new Error('META_EXPERIENCE_NOT_CURRENT');
    }
    const consent = this.#currentConsent(normalized.caseRef, normalized.sourceRevision);
    if (consent === undefined || consent.opt_in !== 1) {
      throw new Error('META_EXPERIENCE_NOT_CURRENT');
    }
    if (!isIsoUtc(consent.expires_at) || Date.parse(consent.expires_at) <= Date.now()) {
      throw new Error('META_CONSENT_EXPIRED');
    }
    normalized.consentRef = consent.consent_ref;
    normalized.receiptRecordedAt = receipt.recorded_at;
  }

  #latestReceipt(
    caseRef: string,
  ): { revision: string; sha256: string; recorded_at: string } | undefined {
    return this.#db
      .prepare(
        'SELECT revision, sha256, recorded_at FROM meta_outcome_receipts WHERE case_ref=? ORDER BY recorded_at DESC, revision DESC LIMIT 1',
      )
      .get(caseRef) as { revision: string; sha256: string; recorded_at: string } | undefined;
  }

  /**
   * The CURRENT consent for one (caseRef, sourceRevision): the latest entry of
   * the durable transactional declaration-order sequence (never lexicographic
   * ordering of the opaque revision string). Historical rows stay as
   * provenance, but only this row's opt_in state is authoritative for
   * write-time authorization and read-time revalidation alike.
   */
  #currentConsent(caseRef: string, sourceRevision: string): ConsentRow | undefined {
    return this.#db
      .prepare(
        `SELECT * FROM meta_opt_in_consents
         WHERE case_ref=? AND source_revision=?
         ORDER BY declaration_seq DESC, rowid DESC
         LIMIT 1`,
      )
      .get(caseRef, sourceRevision) as ConsentRow | undefined;
  }

  /** True when `consent` is still the newest declared consent for its source. */
  #isCurrentConsent(consent: ConsentRow): boolean {
    const current = this.#currentConsent(consent.case_ref, consent.source_revision);
    return current !== undefined && current.consent_ref === consent.consent_ref;
  }

  /**
   * Safe migration for databases created before `declaration_seq` existed:
   * add the column, then backfill one sequence per (caseRef, sourceRevision)
   * in original insertion order so the legacy "latest declaration wins"
   * semantics carry over and later writes continue the sequence. The write
   * lock plus the in-transaction recheck keep concurrent constructors from
   * racing the ALTER.
   */
  #migrateConsentDeclarationOrder(): void {
    if (this.#consentDeclarationSeqColumnExists()) return;
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      if (this.#consentDeclarationSeqColumnExists()) {
        this.#db.exec('COMMIT');
        return;
      }
      this.#db.exec(
        'ALTER TABLE meta_opt_in_consents ADD COLUMN declaration_seq INTEGER NOT NULL DEFAULT 0',
      );
      const legacyRows = this.#db
        .prepare(
          'SELECT rowid AS rid, case_ref, source_revision FROM meta_opt_in_consents ORDER BY rowid ASC',
        )
        .all() as unknown as { rid: number; case_ref: string; source_revision: string }[];
      const nextSeqBySource = new Map<string, number>();
      const assignSeq = this.#db.prepare(
        'UPDATE meta_opt_in_consents SET declaration_seq=? WHERE rowid=?',
      );
      for (const row of legacyRows) {
        const key = `${row.case_ref}\u0000${row.source_revision}`;
        const seq = (nextSeqBySource.get(key) ?? 0) + 1;
        nextSeqBySource.set(key, seq);
        assignSeq.run(seq, row.rid);
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  #consentDeclarationSeqColumnExists(): boolean {
    const columns = this.#db
      .prepare('PRAGMA table_info(meta_opt_in_consents)')
      .all() as unknown as { name?: unknown }[];
    return columns.some((column) => column.name === 'declaration_seq');
  }

  /** Revalidate one stored row at query time; `undefined` excludes the row. */
  #revalidateExperienceRow(row: ExperienceRow): MetaVerifiedExperienceRecord | undefined {
    let tags: string[];
    let constraintCodes: string[];
    try {
      const parsedTags: unknown = JSON.parse(row.tags_json);
      const parsedCodes: unknown = JSON.parse(row.constraint_codes_json);
      if (!isStringArray(parsedTags) || !isStringArray(parsedCodes)) return undefined;
      tags = parsedTags;
      constraintCodes = parsedCodes;
    } catch {
      return undefined;
    }
    const digest = canonicalExperienceDigest({
      caseRef: row.case_ref,
      sourceRevision: row.source_revision,
      sourceDigest: row.source_digest,
      capabilityId: row.capability_id,
      taskClass: row.task_class,
      patternId: row.pattern_id,
      verifiedOutcome: row.verified_outcome as MetaVerifiedOutcome,
      tags,
      constraintCodes,
    });
    if (digest !== row.experience_digest) return undefined;
    const receipt = this.#latestReceipt(row.case_ref);
    if (
      receipt === undefined ||
      receipt.revision !== row.source_revision ||
      receipt.sha256 !== row.source_digest ||
      receipt.recorded_at !== row.receipt_recorded_at
    ) {
      return undefined;
    }
    // Read-time revalidation uses the CURRENT consent for the source: after a
    // newer opt-out the bound historical opt-in row no longer authorizes the
    // record, even before its physical revocation is observed.
    const consent = this.#currentConsent(row.case_ref, row.source_revision);
    if (
      consent === undefined ||
      consent.opt_in !== 1 ||
      !isIsoUtc(consent.expires_at) ||
      Date.parse(consent.expires_at) <= Date.now()
    ) {
      return undefined;
    }
    return {
      experienceId: row.experience_id,
      capabilityId: row.capability_id,
      taskClass: row.task_class,
      patternId: row.pattern_id,
      verifiedOutcome: row.verified_outcome as MetaVerifiedOutcome,
      tags,
      constraintCodes,
      provenance: {
        sourceCaseRef: row.case_ref,
        sourceRevision: row.source_revision,
        sourceDigest: row.source_digest,
        receiptRecordedAt: row.receipt_recorded_at,
        consentRef: row.consent_ref,
      },
      advisoryOnly: true,
      feedbackCandidateRef: row.feedback_candidate_ref ?? undefined,
      recordedAt: row.recorded_at,
    };
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

// ---------------------------------------------------------------------------
// Closed-world verified-experience helpers
// ---------------------------------------------------------------------------

type MetaExperienceVocabularyKind =
  | 'capability'
  | 'task_class'
  | 'pattern'
  | 'tag'
  | 'constraint_code';

/** Snake-case SQLite row shape of `meta_verified_experiences`. */
interface ExperienceRow {
  readonly experience_id: string;
  readonly case_ref: string;
  readonly source_revision: string;
  readonly source_digest: string;
  readonly capability_id: string;
  readonly task_class: string;
  readonly pattern_id: string;
  readonly verified_outcome: string;
  readonly tags_json: string;
  readonly constraint_codes_json: string;
  readonly experience_digest: string;
  readonly consent_ref: string;
  readonly receipt_recorded_at: string;
  readonly feedback_candidate_ref: string | null;
  readonly recorded_at: string;
  readonly revoked_at: string | null;
}

/**
 * Normalized record fed to persistence; `consentRef`/`receiptRecordedAt` are
 * resolved from the CURRENT evidence inside the write transaction.
 */
interface NormalizedExperience {
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly sourceDigest: string;
  readonly capabilityId: string;
  readonly taskClass: string;
  readonly patternId: string;
  readonly verifiedOutcome: MetaVerifiedOutcome;
  readonly tags: readonly string[];
  readonly constraintCodes: readonly string[];
  consentRef: string;
  receiptRecordedAt: string;
}

function isExperienceCode(value: unknown): value is string {
  return typeof value === 'string' && EXPERIENCE_CODE.test(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && expected.every((key, index) => actual[index] === key);
}

/**
 * Fail-closed normalization: exact key set, bounded sizes, no duplicate
 * tags/codes, closed-world grammar for every identifier. Callers cannot
 * smuggle free text, absolute paths, secrets or oversized payloads in.
 */
function normalizeExperienceInput(input: MetaVerifiedExperienceInput): NormalizedExperience {
  if (
    typeof input !== 'object' ||
    input === null ||
    !hasExactKeys(input as unknown as Record<string, unknown>, [
      'caseRef',
      'sourceRevision',
      'sourceDigest',
      'capabilityId',
      'taskClass',
      'patternId',
      'verifiedOutcome',
      'tags',
      'constraintCodes',
    ]) ||
    !isSafeRef(input.caseRef) ||
    !isSafeRef(input.sourceRevision) ||
    !SHA256.test(input.sourceDigest) ||
    !isExperienceCode(input.capabilityId) ||
    !isExperienceCode(input.taskClass) ||
    !isExperienceCode(input.patternId) ||
    (input.verifiedOutcome !== 'VERIFIED_PASS' && input.verifiedOutcome !== 'VERIFIED_FAIL') ||
    !isStringArray(input.tags) ||
    input.tags.length > MAX_EXPERIENCE_TAGS ||
    !isStringArray(input.constraintCodes) ||
    input.constraintCodes.length > MAX_EXPERIENCE_CONSTRAINT_CODES
  ) {
    throw new TypeError('META_EXPERIENCE_INVALID');
  }
  if (new Set(input.tags).size !== input.tags.length) {
    throw new TypeError('META_EXPERIENCE_INVALID');
  }
  if (new Set(input.constraintCodes).size !== input.constraintCodes.length) {
    throw new TypeError('META_EXPERIENCE_INVALID');
  }
  if (!input.tags.every(isExperienceCode) || !input.constraintCodes.every(isExperienceCode)) {
    throw new TypeError('META_EXPERIENCE_INVALID');
  }
  return {
    caseRef: input.caseRef,
    sourceRevision: input.sourceRevision,
    sourceDigest: input.sourceDigest,
    capabilityId: input.capabilityId,
    taskClass: input.taskClass,
    patternId: input.patternId,
    verifiedOutcome: input.verifiedOutcome,
    tags: [...input.tags].sort(),
    constraintCodes: [...input.constraintCodes].sort(),
    consentRef: '',
    receiptRecordedAt: '',
  };
}

/**
 * Digest over the closed-world normalized shape (same canonical key-sorted
 * JSON as every other digest in this store), so tampering with any stored
 * field breaks the digest and excludes the row as malformed.
 */
function canonicalExperienceDigest(input: {
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly sourceDigest: string;
  readonly capabilityId: string;
  readonly taskClass: string;
  readonly patternId: string;
  readonly verifiedOutcome: MetaVerifiedOutcome;
  readonly tags: readonly string[];
  readonly constraintCodes: readonly string[];
}): string {
  return createHash('sha256')
    .update(
      JSON.stringify(
        stableValue({
          schema: 'meta/verified-experience-v1',
          caseRef: input.caseRef,
          sourceRevision: input.sourceRevision,
          sourceDigest: input.sourceDigest,
          capabilityId: input.capabilityId,
          taskClass: input.taskClass,
          patternId: input.patternId,
          verifiedOutcome: input.verifiedOutcome,
          tags: [...input.tags].sort(),
          constraintCodes: [...input.constraintCodes].sort(),
        }),
      ),
      'utf8',
    )
    .digest('hex');
}
