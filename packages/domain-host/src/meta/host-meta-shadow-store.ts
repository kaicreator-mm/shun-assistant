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

export interface MetaVerifiedExperienceInput {
  readonly capabilityId: string;
  readonly taskClass: string;
  readonly patternId: string;
  readonly outcome: 'COMPLETED_VERIFIED' | 'REFUSED_VERIFIED';
  readonly tags: readonly string[];
  readonly constraints: readonly string[];
}

export interface MetaSharedExperienceQuery {
  readonly targetCaseRef: string;
  readonly capabilityId: string;
  readonly taskClass?: string;
  readonly tags?: readonly string[];
  readonly limit?: number;
}

export interface MetaSharedExperienceResult {
  readonly sourceCaseRef: string;
  readonly sourceRevision: string;
  readonly sourceDigest: string;
  readonly experience: MetaVerifiedExperienceInput;
  readonly feedback?: {
    readonly rating: 'HELPFUL' | 'NOT_HELPFUL';
    readonly category: string;
    readonly correction?: string;
  };
  readonly crossCase: boolean;
  readonly advisoryOnly: true;
}

export interface MetaOutcomeReceiptInput {
  readonly caseRef: string;
  readonly revision: string;
  readonly sha256: string;
  /** Closed-world summary derived by trusted Host from verified outcome evidence. */
  readonly experience?: MetaVerifiedExperienceInput;
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

interface ConsentCurrentnessRow {
  readonly consent_ref: string;
  readonly opt_in: number;
}

interface MetaExperienceRow {
  readonly case_ref: string;
  readonly revision: string;
  readonly source_digest: string;
  readonly capability_id: string;
  readonly task_class: string;
  readonly pattern_id: string;
  readonly outcome: string;
  readonly experience_json: string;
  readonly recorded_at: string;
  readonly revoked: number;
}

const EXPERIENCE_CODE = /^[a-z][a-z0-9._-]{0,63}$/;
const EXPERIENCE_OUTCOMES = new Set(['COMPLETED_VERIFIED', 'REFUSED_VERIFIED']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isExperienceCode(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    EXPERIENCE_CODE.test(value) &&
    !/(secret|password|credential|private|rawprompt|rawanswer|absolute.path)/i.test(value)
  );
}

function parseMetaVerifiedExperience(value: unknown): MetaVerifiedExperienceInput | undefined {
  if (
    !isRecord(value) ||
    Object.keys(value).sort().join('|') !==
      ['capabilityId', 'constraints', 'outcome', 'patternId', 'tags', 'taskClass'].sort().join('|') ||
    !isExperienceCode(value.capabilityId) ||
    !isExperienceCode(value.taskClass) ||
    !isExperienceCode(value.patternId) ||
    typeof value.outcome !== 'string' ||
    !EXPERIENCE_OUTCOMES.has(value.outcome) ||
    !Array.isArray(value.tags) ||
    !Array.isArray(value.constraints) ||
    value.tags.length > 16 ||
    value.constraints.length > 16 ||
    !value.tags.every(isExperienceCode) ||
    !value.constraints.every(isExperienceCode) ||
    new Set(value.tags).size !== value.tags.length ||
    new Set(value.constraints).size !== value.constraints.length
  ) {
    return undefined;
  }
  return Object.freeze({
    capabilityId: value.capabilityId,
    taskClass: value.taskClass,
    patternId: value.patternId,
    outcome: value.outcome as MetaVerifiedExperienceInput['outcome'],
    tags: Object.freeze([...value.tags].sort()),
    constraints: Object.freeze([...value.constraints].sort()),
  });
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
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_opt_in_currentness (
      case_ref TEXT NOT NULL,
      source_revision TEXT NOT NULL,
      consent_ref TEXT NOT NULL,
      opt_in INTEGER NOT NULL CHECK (opt_in IN (0,1)),
      updated_at TEXT NOT NULL,
      PRIMARY KEY (case_ref, source_revision)
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS meta_verified_experiences (
      case_ref TEXT NOT NULL,
      revision TEXT NOT NULL,
      source_digest TEXT NOT NULL,
      capability_id TEXT NOT NULL,
      task_class TEXT NOT NULL,
      pattern_id TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK (outcome IN ('COMPLETED_VERIFIED','REFUSED_VERIFIED')),
      experience_json TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
      PRIMARY KEY (case_ref, revision)
    )`);
    this.#db.exec('CREATE INDEX IF NOT EXISTS meta_experience_capability_task_idx ON meta_verified_experiences(capability_id,task_class,revoked,recorded_at)');
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
    const experience =
      input.experience === undefined ? undefined : parseMetaVerifiedExperience(input.experience);
    if (input.experience !== undefined && experience === undefined) {
      throw new TypeError('META_EXPERIENCE_INVALID');
    }
    const recordedAt = new Date().toISOString();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#db.prepare(
        'INSERT OR REPLACE INTO meta_outcome_receipts(case_ref,revision,sha256,recorded_at) VALUES(?,?,?,?)',
      ).run(input.caseRef, input.revision, input.sha256, recordedAt);
      if (experience) {
        this.#db.prepare(`INSERT OR REPLACE INTO meta_verified_experiences(
          case_ref,revision,source_digest,capability_id,task_class,pattern_id,outcome,
          experience_json,recorded_at,revoked
        ) VALUES(?,?,?,?,?,?,?,?,?,0)`).run(
          input.caseRef,
          input.revision,
          input.sha256,
          experience.capabilityId,
          experience.taskClass,
          experience.patternId,
          experience.outcome,
          JSON.stringify(experience),
          recordedAt,
        );
      } else {
        this.#db.prepare(
          'DELETE FROM meta_verified_experiences WHERE case_ref=? AND revision=?',
        ).run(input.caseRef, input.revision);
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#rollback();
      throw error;
    }
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
    const recordedAt = new Date().toISOString();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#db.prepare(
        `INSERT OR REPLACE INTO meta_opt_in_consents(
           consent_ref,revision,case_ref,source_revision,source_digest,
           operator_id,operator_subject_ref,authorization_revision,
           currentness_ref,opt_in,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      ).run(
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
      this.#db.prepare(`INSERT INTO meta_opt_in_currentness(
        case_ref,source_revision,consent_ref,opt_in,updated_at
      ) VALUES(?,?,?,?,?)
      ON CONFLICT(case_ref,source_revision) DO UPDATE SET
        consent_ref=excluded.consent_ref,
        opt_in=excluded.opt_in,
        updated_at=excluded.updated_at`).run(
        input.caseRef,
        input.sourceRevision,
        input.consentRef,
        input.optIn ? 1 : 0,
        recordedAt,
      );
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
    const currentness = this.#db.prepare(
      'SELECT consent_ref,opt_in FROM meta_opt_in_currentness WHERE case_ref=? AND source_revision=?',
    ).get(input.caseRef, input.sourceRevision) as ConsentCurrentnessRow | undefined;
    if (!currentness || currentness.opt_in !== 1) throw new Error('META_OPT_IN_MISSING');
    const consent = this.#db.prepare(
      'SELECT * FROM meta_opt_in_consents WHERE consent_ref=?',
    ).get(currentness.consent_ref) as ConsentRow | undefined;
    if (
      consent === undefined ||
      consent.case_ref !== input.caseRef ||
      consent.source_revision !== input.sourceRevision ||
      consent.opt_in !== 1
    ) throw new Error('META_OPT_IN_MISSING');
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
      const currentness = this.#db.prepare(
        'SELECT consent_ref,opt_in FROM meta_opt_in_currentness WHERE case_ref=? AND source_revision=?',
      ).get(authorization.caseRef, authorization.sourceRevision) as ConsentCurrentnessRow | undefined;
      const nowIso = new Date().toISOString();
      if (
        consent === undefined ||
        currentness === undefined ||
        currentness.opt_in !== 1 ||
        currentness.consent_ref !== authorization.consentRef ||
        consent.case_ref !== authorization.caseRef ||
        consent.source_revision !== authorization.sourceRevision ||
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

  /**
   * Read-only cross-Case reuse of verified, privacy-minimized experience.
   * The target Case is context only; source Case equality is never an access
   * gate. Every result is advisory and is revalidated against the latest
   * outcome receipt and current opt-in consent at query time.
   */
  querySharedExperiences(input: MetaSharedExperienceQuery): readonly MetaSharedExperienceResult[] {
    const allowedKeys = ['capabilityId', 'limit', 'tags', 'targetCaseRef', 'taskClass'];
    if (
      !isRecord(input) ||
      Object.keys(input).some((key) => !allowedKeys.includes(key)) ||
      !isSafeRef(input.targetCaseRef) ||
      !isExperienceCode(input.capabilityId) ||
      (input.taskClass !== undefined && !isExperienceCode(input.taskClass)) ||
      (input.limit !== undefined &&
        (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 20)) ||
      (input.tags !== undefined &&
        (!Array.isArray(input.tags) ||
          input.tags.length > 16 ||
          !input.tags.every(isExperienceCode) ||
          new Set(input.tags).size !== input.tags.length))
    ) {
      throw new TypeError('META_EXPERIENCE_QUERY_INVALID');
    }
    const limit = input.limit ?? 10;
    const rows = (input.taskClass
      ? this.#db.prepare(`SELECT * FROM meta_verified_experiences
          WHERE capability_id=? AND task_class=? AND revoked=0
          ORDER BY recorded_at DESC LIMIT 256`).all(input.capabilityId, input.taskClass)
      : this.#db.prepare(`SELECT * FROM meta_verified_experiences
          WHERE capability_id=? AND revoked=0
          ORDER BY recorded_at DESC LIMIT 256`).all(input.capabilityId)) as MetaExperienceRow[];
    const results: MetaSharedExperienceResult[] = [];
    for (const row of rows) {
      if (
        !isSafeRef(row.case_ref) ||
        !isSafeRef(row.revision) ||
        !SHA256.test(row.source_digest) ||
        row.revoked !== 0
      ) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(row.experience_json) as unknown;
      } catch {
        continue;
      }
      const experience = parseMetaVerifiedExperience(parsed);
      if (
        !experience ||
        experience.capabilityId !== row.capability_id ||
        experience.taskClass !== row.task_class ||
        experience.patternId !== row.pattern_id ||
        experience.outcome !== row.outcome ||
        (input.tags !== undefined && !input.tags.every((tag) => experience.tags.includes(tag)))
      ) continue;
      const latestReceipt = this.#db.prepare(
        'SELECT revision,sha256 FROM meta_outcome_receipts WHERE case_ref=? ORDER BY recorded_at DESC,revision DESC LIMIT 1',
      ).get(row.case_ref) as { revision: string; sha256: string } | undefined;
      if (
        !latestReceipt ||
        latestReceipt.revision !== row.revision ||
        latestReceipt.sha256 !== row.source_digest
      ) continue;
      const currentness = this.#db.prepare(
        'SELECT consent_ref,opt_in FROM meta_opt_in_currentness WHERE case_ref=? AND source_revision=?',
      ).get(row.case_ref, row.revision) as ConsentCurrentnessRow | undefined;
      if (!currentness || currentness.opt_in !== 1) continue;
      const consent = this.#db.prepare(
        'SELECT * FROM meta_opt_in_consents WHERE consent_ref=?',
      ).get(currentness.consent_ref) as ConsentRow | undefined;
      if (
        !consent ||
        consent.opt_in !== 1 ||
        consent.case_ref !== row.case_ref ||
        consent.source_revision !== row.revision ||
        consent.source_digest !== row.source_digest ||
        !isIsoUtc(consent.expires_at) ||
        Date.parse(consent.expires_at) <= Date.now()
      ) continue;
      const feedback = this.#readMatchingFeedback(row, currentness.consent_ref);
      results.push(Object.freeze({
        sourceCaseRef: row.case_ref,
        sourceRevision: row.revision,
        sourceDigest: row.source_digest,
        experience,
        ...(feedback ? { feedback } : {}),
        crossCase: row.case_ref !== input.targetCaseRef,
        advisoryOnly: true as const,
      }));
      if (results.length >= 256) break;
    }
    results.sort((a, b) => Number(b.crossCase) - Number(a.crossCase));
    return Object.freeze(results.slice(0, limit));
  }

  /** Host/operator invalidation. Revoked records never reappear in retrieval. */
  revokeSharedExperience(input: {
    readonly caseRef: string;
    readonly revision: string;
    readonly sourceDigest: string;
  }): boolean {
    if (
      !isRecord(input) ||
      Object.keys(input).sort().join('|') !== ['caseRef', 'revision', 'sourceDigest'].sort().join('|') ||
      !isSafeRef(input.caseRef) ||
      !isSafeRef(input.revision) ||
      !SHA256.test(input.sourceDigest)
    ) return false;
    const result = this.#db.prepare(`UPDATE meta_verified_experiences
      SET revoked=1 WHERE case_ref=? AND revision=? AND source_digest=? AND revoked=0`)
      .run(input.caseRef, input.revision, input.sourceDigest);
    return result.changes === 1;
  }

  #readMatchingFeedback(
    source: MetaExperienceRow,
    consentRef: string,
  ): MetaSharedExperienceResult['feedback'] | undefined {
    const rows = this.#db.prepare(`SELECT payload_json FROM meta_shadow_candidates
      WHERE lifecycle='FUTURE_BUILD_SHADOW' AND active=0
      ORDER BY created_at DESC LIMIT 256`).all() as { payload_json: string }[];
    for (const row of rows) {
      try {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        const sourceRef = payload.source as Record<string, unknown> | undefined;
        const provenance = payload.provenance as Record<string, unknown> | undefined;
        const feedback = payload.feedback as Record<string, unknown> | undefined;
        if (
          payload.kind !== 'META_FEEDBACK' ||
          payload.lifecycle !== 'FUTURE_BUILD_SHADOW' ||
          payload.active !== false ||
          sourceRef?.caseRef !== source.case_ref ||
          sourceRef?.revision !== source.revision ||
          sourceRef?.sha256 !== source.source_digest ||
          provenance?.consentRef !== consentRef ||
          !feedback ||
          (feedback.rating !== 'HELPFUL' && feedback.rating !== 'NOT_HELPFUL') ||
          !isExperienceCode(feedback.category) ||
          (feedback.correction !== undefined && !isExperienceCode(feedback.correction))
        ) continue;
        return Object.freeze({
          rating: feedback.rating,
          category: feedback.category,
          ...(typeof feedback.correction === 'string' ? { correction: feedback.correction } : {}),
        });
      } catch {
        continue;
      }
    }
    return undefined;
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
