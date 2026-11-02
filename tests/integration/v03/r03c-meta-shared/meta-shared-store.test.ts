/**
 * R03C-META-SHARED-SQLITE — cross-Case verified experience over the EXISTING
 * Host SQLite store (Issue #285, Execution Pack
 * .agent/execution/R03C-META-SHARED-SQLITE/MANIFEST.yaml@636bc865).
 *
 * Proves: closed-world privacy-minimized normalization, advisory-only
 * cross-Case retrieval (no sourceCase==targetCase gate), snapshot-consistent
 * currentness, receipt/consent staleness, explicit revocation, restart
 * durability, malformed/private/oversized rejection, Shadow-feedback
 * metadata attachment without promotion, receipt digest conflict and
 * concurrent submission/query safety.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import { afterEach, describe, expect, it } from 'vitest';
import {
  META_FEEDBACK_SCHEMA,
  type MetaFeedbackAuthorization,
  type MetaFeedbackSelection,
  type MetaFeedbackShadowCandidate,
} from '../../../../packages/domain-computer/src/feedback/meta-feedback.ts';
import {
  HostMetaShadowStore,
  type MetaVerifiedExperienceInput,
  type MetaVerifiedExperienceRecord,
} from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const STORE_MODULE = resolve(
  HERE,
  '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts',
);

const CAPABILITY = 'cap.doc.pdf-convert';
const TASK_CLASS = 'taskclass.document';
const PATTERN = 'pattern.two-step-verify';
const TAG_WINDOWS = 'tag.windows';
const TAG_HIGH_SUCCESS = 'tag.success-rate-high';
const CONSTRAINT_NO_ELEVATION = 'constraint.no-elevation';

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function hoursFromNow(hours: number): string {
  return new Date(Date.now() + hours * 3_600_000).toISOString();
}

function seedVocabulary(store: HostMetaShadowStore): void {
  store.registerMetaCapabilityId(CAPABILITY);
  store.registerMetaTaskClass(TASK_CLASS);
  store.registerMetaPatternId(PATTERN);
  store.registerMetaPatternId('pattern.single-pass');
  store.registerMetaExperienceTag(TAG_WINDOWS);
  store.registerMetaExperienceTag(TAG_HIGH_SUCCESS);
  store.registerMetaConstraintCode(CONSTRAINT_NO_ELEVATION);
}

/** Trusted Host composition records a genuine receipt, then explicit opt-in. */
function seedCase(
  store: HostMetaShadowStore,
  caseRef: string,
  receiptDigest: string,
  revision = 'outcome-r1',
  expiresAt = hoursFromNow(1),
): string {
  store.recordOutcomeReceipt({ caseRef, revision, sha256: receiptDigest });
  const consentRef = `consent-${caseRef}-${revision}`;
  store.recordOptInConsent({
    consentRef,
    revision: 'consent-rev-1',
    caseRef,
    sourceRevision: revision,
    sourceDigest: receiptDigest,
    operatorId: 'operator:shun-owner',
    operatorSubjectRef: 'operator:shun-owner',
    authorizationRevision: 'authz-rev-1',
    currentnessRef: `currentness:${caseRef}:${revision}`,
    optIn: true,
    expiresAt,
  });
  return consentRef;
}

function experienceInput(
  overrides: Partial<MetaVerifiedExperienceInput> = {},
): MetaVerifiedExperienceInput {
  return {
    caseRef: 'case-alpha',
    sourceRevision: 'outcome-r1',
    sourceDigest: sha256('evidence:case-alpha:outcome-r1'),
    capabilityId: CAPABILITY,
    taskClass: TASK_CLASS,
    patternId: PATTERN,
    verifiedOutcome: 'VERIFIED_PASS',
    tags: [TAG_HIGH_SUCCESS, TAG_WINDOWS],
    constraintCodes: [CONSTRAINT_NO_ELEVATION],
    ...overrides,
  };
}

const ADVISORY_RECORD_KEYS = [
  'advisoryOnly',
  'capabilityId',
  'constraintCodes',
  'experienceId',
  'feedbackCandidateRef',
  'patternId',
  'provenance',
  'recordedAt',
  'tags',
  'taskClass',
  'verifiedOutcome',
].sort();

const createdDirs: string[] = [];
const openStores: HostMetaShadowStore[] = [];

/** Asserted first-element access (biome forbids non-null assertions). */
function first<T>(items: readonly T[]): T {
  const item = items[0];
  if (item === undefined) throw new Error('expected at least one result');
  return item;
}

function makeStore(name: string): { store: HostMetaShadowStore; file: string } {
  const dir = mkdtempSync(join(tmpdir(), `meta-shared-${name}-`));
  createdDirs.push(dir);
  const file = join(dir, 'meta.sqlite');
  const store = new HostMetaShadowStore(file);
  openStores.push(store);
  return { store, file };
}

afterEach(() => {
  // Close every handle before removing the directory: Windows holds the
  // SQLite WAL files open and removal would fail with EPERM otherwise.
  for (const store of openStores.splice(0)) {
    try {
      store.close();
    } catch {
      /* already closed by the test body */
    }
  }
  while (createdDirs.length > 0) {
    const dir = createdDirs.pop();
    if (dir === undefined) break;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        /* a worker handle may still be releasing the file; retry briefly */
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
      }
    }
  }
});

describe('R03C shared Meta experience (existing Host SQLite)', () => {
  it('Case B retrieves Case A verified experience across Cases with provenance and advisory-only marker', () => {
    const { store } = makeStore('cross-case');
    seedVocabulary(store);
    const consentRef = seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    const recorded = store.recordSharedExperience(experienceInput());
    expect(recorded.status).toBe('STORED');

    // Case B asks. Case B has no receipt and no consent of its own: the
    // source Case stays provenance, never an equality gate.
    const results: readonly MetaVerifiedExperienceRecord[] = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
      taskClass: TASK_CLASS,
    });
    expect(results).toHaveLength(1);
    const record = first(results);
    expect(record.experienceId).toBe(recorded.experienceId);
    expect(record.advisoryOnly).toBe(true);
    expect(Object.keys(record).sort()).toEqual(ADVISORY_RECORD_KEYS);
    expect(record.provenance.sourceCaseRef).toBe('case-alpha');
    expect(record.provenance.sourceRevision).toBe('outcome-r1');
    expect(record.provenance.sourceDigest).toBe(sha256('evidence:case-alpha:outcome-r1'));
    expect(record.provenance.consentRef).toBe(consentRef);
    expect(record.capabilityId).toBe(CAPABILITY);
    expect(record.taskClass).toBe(TASK_CLASS);
    expect(record.verifiedOutcome).toBe('VERIFIED_PASS');
    // Normalized closed-world tokens only: sorted, bounded, catalogued.
    expect(record.tags).toEqual([TAG_HIGH_SUCCESS, TAG_WINDOWS].sort());
    expect(record.feedbackCandidateRef).toBeUndefined();
  });

  it('same-Case and cross-Case queries both work; neither becomes an authorization gate', () => {
    const { store } = makeStore('no-gate');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    const recorded = store.recordSharedExperience(experienceInput());

    const sameCase = store.querySharedExperiences({
      targetCaseRef: 'case-alpha',
      capabilityId: CAPABILITY,
    });
    const crossCase = store.querySharedExperiences({
      targetCaseRef: 'case-zeta-unknown',
      capabilityId: CAPABILITY,
    });
    expect(sameCase.map((record) => record.experienceId)).toEqual([recorded.experienceId]);
    expect(crossCase.map((record) => record.experienceId)).toEqual([recorded.experienceId]);
    // Advisory-only: results expose no executable action/authority surface.
    for (const record of [...sameCase, ...crossCase]) {
      expect(record.advisoryOnly).toBe(true);
      expect(JSON.stringify(record)).not.toMatch(/permit|grant|approval|activate|promote/i);
    }
  });

  it('SQLite close/reopen preserves the record and the query result', () => {
    const { store, file } = makeStore('durability');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    const recorded = store.recordSharedExperience(experienceInput());
    store.close();

    const reopened = new HostMetaShadowStore(file);
    try {
      const results = reopened.querySharedExperiences({
        targetCaseRef: 'case-beta',
        capabilityId: CAPABILITY,
      });
      expect(results).toHaveLength(1);
      expect(first(results).experienceId).toBe(recorded.experienceId);
      expect(first(results).provenance.sourceCaseRef).toBe('case-alpha');
      // Re-recording the identical normalized record stays idempotent.
      expect(reopened.recordSharedExperience(experienceInput()).status).toBe('ALREADY_STORED');
    } finally {
      reopened.close();
    }
  });

  it('a newer receipt revision makes the older experience stale and unreturned', () => {
    const { store } = makeStore('stale-receipt');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    const stale = store.recordSharedExperience(experienceInput());
    expect(stale.status).toBe('STORED');

    // Newer genuine receipt for the same Case: rev1 evidence is no longer
    // current, so its experience is excluded from advisory retrieval.
    store.recordOutcomeReceipt({
      caseRef: 'case-alpha',
      revision: 'outcome-r2',
      sha256: sha256('evidence:case-alpha:outcome-r2'),
    });
    expect(
      store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: CAPABILITY }),
    ).toHaveLength(0);

    // An experience bound to the new current receipt is returned.
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r2'), 'outcome-r2');
    const fresh = store.recordSharedExperience(
      experienceInput({
        sourceRevision: 'outcome-r2',
        sourceDigest: sha256('evidence:case-alpha:outcome-r2'),
        patternId: 'pattern.single-pass',
      }),
    );
    expect(fresh.status).toBe('STORED');
    const results = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
    });
    expect(results.map((record) => record.experienceId)).toEqual([fresh.experienceId]);
  });

  it('explicit revocation removes the source experience from every later query', () => {
    const { store } = makeStore('revocation');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    store.recordSharedExperience(experienceInput());

    expect(
      store.revokeSourceExperiences({ caseRef: 'case-alpha', sourceRevision: 'outcome-r1' }),
    ).toBe(1);
    expect(
      store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: CAPABILITY }),
    ).toHaveLength(0);
    // Revocation is idempotent; revoked rows stay excluded.
    expect(
      store.revokeSourceExperiences({ caseRef: 'case-alpha', sourceRevision: 'outcome-r1' }),
    ).toBe(0);

    // Whole-source revocation without a revision narrows nothing away.
    seedCase(store, 'case-gamma', sha256('evidence:case-gamma:outcome-r1'));
    store.recordSharedExperience(
      experienceInput({
        caseRef: 'case-gamma',
        sourceDigest: sha256('evidence:case-gamma:outcome-r1'),
      }),
    );
    expect(store.revokeSourceExperiences({ caseRef: 'case-gamma' })).toBe(1);
    expect(
      store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: CAPABILITY }),
    ).toHaveLength(0);
  });

  it('rejects malformed, unregistered, private, path/secret-shaped and oversized records', () => {
    const { store } = makeStore('negatives');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));

    // Closed world: grammar-valid but uncatalogued identifiers are rejected.
    expect(() =>
      store.recordSharedExperience(experienceInput({ capabilityId: 'cap.never-registered' })),
    ).toThrow('META_EXPERIENCE_VOCABULARY_UNKNOWN');
    expect(() =>
      store.recordSharedExperience(experienceInput({ taskClass: 'taskclass.unknown-class' })),
    ).toThrow('META_EXPERIENCE_VOCABULARY_UNKNOWN');
    // PII-shaped and arbitrary caller-chosen tokens cannot enter either.
    expect(() =>
      store.recordSharedExperience(experienceInput({ tags: ['tag.operator-jane-doe'] })),
    ).toThrow('META_EXPERIENCE_VOCABULARY_UNKNOWN');
    // Secret-shaped values pass no closed-world gate.
    expect(() => store.recordSharedExperience(experienceInput({ tags: ['password123'] }))).toThrow(
      'META_EXPERIENCE_VOCABULARY_UNKNOWN',
    );
    expect(() =>
      store.recordSharedExperience(experienceInput({ tags: ['sk-live-abc123'] })),
    ).toThrow('META_EXPERIENCE_VOCABULARY_UNKNOWN');
    // Raw absolute paths fail the normalized grammar outright.
    expect(() =>
      store.recordSharedExperience(experienceInput({ tags: ['C:\\Users\\ops\\secret.txt'] })),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(() =>
      store.recordSharedExperience(experienceInput({ constraintCodes: ['/etc/passwd'] })),
    ).toThrow('META_EXPERIENCE_INVALID');
    // Malformed schema: bad enum, duplicate tags, wrong digest, extra key.
    expect(() =>
      store.recordSharedExperience(
        experienceInput({
          verifiedOutcome: 'VERIFIED_OK',
        } as unknown as Partial<MetaVerifiedExperienceInput>),
      ),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(() =>
      store.recordSharedExperience(experienceInput({ tags: [TAG_WINDOWS, TAG_WINDOWS] })),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(() =>
      store.recordSharedExperience(experienceInput({ sourceDigest: 'not-a-digest' })),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(() =>
      store.recordSharedExperience({
        ...experienceInput(),
        note: 'free text',
      } as MetaVerifiedExperienceInput),
    ).toThrow('META_EXPERIENCE_INVALID');
    // Oversized input: count and length bounds.
    const nineTags = [
      'tag.windows',
      'tag.success-rate-high',
      'tag.batch-a',
      'tag.batch-b',
      'tag.batch-c',
      'tag.batch-d',
      'tag.batch-e',
      'tag.batch-f',
      'tag.batch-g',
    ];
    expect(() => store.recordSharedExperience(experienceInput({ tags: nineTags }))).toThrow(
      'META_EXPERIENCE_INVALID',
    );
    expect(() =>
      store.recordSharedExperience(experienceInput({ tags: [`tag.${'x'.repeat(64)}`] })),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(() =>
      store.recordSharedExperience(
        experienceInput({
          constraintCodes: Array.from(
            { length: 17 },
            (_, index) => `constraint.no-elevation-${index}`,
          ),
        }),
      ),
    ).toThrow('META_EXPERIENCE_INVALID');
    // Evidence currentness: receipt must be current with the exact digest.
    expect(() =>
      store.recordSharedExperience(experienceInput({ sourceRevision: 'outcome-never-recorded' })),
    ).toThrow('META_EXPERIENCE_NOT_CURRENT');
    expect(() =>
      store.recordSharedExperience(experienceInput({ sourceDigest: sha256('forged-evidence') })),
    ).toThrow('META_EXPERIENCE_NOT_CURRENT');
    // Query bounds: unknown identifiers and out-of-range limits are refused.
    expect(() =>
      store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: 'cap.unknown' }),
    ).toThrow('META_EXPERIENCE_QUERY_INVALID');
    expect(() =>
      store.querySharedExperiences({
        targetCaseRef: 'case-beta',
        capabilityId: CAPABILITY,
        limit: 0,
      }),
    ).toThrow('META_EXPERIENCE_QUERY_INVALID');
    expect(() =>
      store.querySharedExperiences({
        targetCaseRef: 'case-beta',
        capabilityId: CAPABILITY,
        limit: 21,
      }),
    ).toThrow('META_EXPERIENCE_QUERY_INVALID');
    // Expired opt-in consent excludes recording, not just retrieval.
    seedCase(
      store,
      'case-expired',
      sha256('evidence:case-expired:outcome-r1'),
      'outcome-r1',
      new Date(Date.parse('2020-01-01T00:00:00.000Z')).toISOString(),
    );
    expect(() =>
      store.recordSharedExperience(
        experienceInput({
          caseRef: 'case-expired',
          sourceDigest: sha256('evidence:case-expired:outcome-r1'),
        }),
      ),
    ).toThrow('META_CONSENT_EXPIRED');
  });

  it('same receipt revision with a different digest conflicts instead of replacing evidence', () => {
    const { store } = makeStore('receipt-conflict');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));

    // Identical re-record is an idempotent no-op that keeps original evidence.
    expect(() =>
      store.recordOutcomeReceipt({
        caseRef: 'case-alpha',
        revision: 'outcome-r1',
        sha256: sha256('evidence:case-alpha:outcome-r1'),
      }),
    ).not.toThrow();
    // Same revision, different digest: evidence forgery, never a replacement.
    expect(() =>
      store.recordOutcomeReceipt({
        caseRef: 'case-alpha',
        revision: 'outcome-r1',
        sha256: sha256('forged-evidence'),
      }),
    ).toThrow('META_RECEIPT_CONFLICT');
    // The genuine receipt still backs the current experience evidence.
    store.recordSharedExperience(experienceInput());
    expect(
      store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: CAPABILITY }),
    ).toHaveLength(1);
  });

  it('a matching Shadow feedback candidate may attach as metadata but stays FUTURE_BUILD_SHADOW and inactive', async () => {
    const { store } = makeStore('feedback-shadow');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    const recorded = store.recordSharedExperience(experienceInput());

    const selection: MetaFeedbackSelection = {
      selected: true,
      caseRef: 'case-alpha',
      sourceRevision: 'outcome-r1',
      rating: 'HELPFUL',
      category: 'OTHER',
    };
    const authorization = (await store.authorizeCurrentFeedback({
      scope: 'META_FEEDBACK_SHADOW',
      caseRef: 'case-alpha',
      sourceRevision: 'outcome-r1',
      selection,
    })) as MetaFeedbackAuthorization;
    expect(authorization.status).toBe('AUTHORIZED');
    const candidate: MetaFeedbackShadowCandidate = Object.freeze({
      schema: META_FEEDBACK_SCHEMA,
      candidateId: authorization.candidateId,
      kind: 'META_FEEDBACK',
      lifecycle: 'FUTURE_BUILD_SHADOW',
      active: false as const,
      source: Object.freeze({
        caseRef: authorization.caseRef,
        revision: authorization.sourceRevision,
        sha256: authorization.sourceDigest,
      }),
      feedback: Object.freeze({
        rating: selection.rating,
        category: selection.category,
      }),
      provenance: Object.freeze({
        operatorId: authorization.operatorId,
        operatorSubjectRef: authorization.operatorSubjectRef,
        consentRef: authorization.consentRef,
        consentRevision: authorization.consentRevision,
        consentExpiresAt: authorization.consentExpiresAt,
        authorizationRevision: authorization.authorizationRevision,
        currentnessRef: authorization.currentnessRef,
      }),
    });
    const stored = await store.runMetaFeedbackWorkflow({ candidate, authorization });
    expect(stored).toMatchObject({ status: 'SHADOW_STORED', active: false });

    store.attachExperienceFeedbackMetadata({
      experienceId: recorded.experienceId,
      candidateId: authorization.candidateId,
    });
    const results = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
    });
    expect(results).toHaveLength(1);
    expect(first(results).feedbackCandidateRef).toBe(authorization.candidateId);

    // The candidate itself is untouched: shadow, inactive, no promotion API.
    const readBack = store.readShadowCandidate(authorization.candidateId);
    expect(readBack).toBeDefined();
    expect(readBack?.lifecycle).toBe('FUTURE_BUILD_SHADOW');
    expect(readBack?.active).toBe(false);

    // Attaching a non-shadow/nonexistent candidate is refused.
    expect(() =>
      store.attachExperienceFeedbackMetadata({
        experienceId: recorded.experienceId,
        candidateId: 'meta-candidate-missing',
      }),
    ).toThrow('META_FEEDBACK_CANDIDATE_INVALID');
  });

  it('a query is snapshot-consistent against a second handle committing a newer receipt', () => {
    const { store, file } = makeStore('snapshot');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    store.recordSharedExperience(experienceInput());

    // A second connection begins an uncommitted newer receipt; the query
    // must observe one consistent snapshot where rev1 is still current.
    const writer = new DatabaseSync(file);
    try {
      writer.exec('PRAGMA busy_timeout=5000');
      writer.exec('BEGIN IMMEDIATE');
      writer
        .prepare(
          'INSERT INTO meta_outcome_receipts(case_ref,revision,sha256,recorded_at) VALUES(?,?,?,?)',
        )
        .run(
          'case-alpha',
          'outcome-r2',
          sha256('evidence:case-alpha:outcome-r2'),
          new Date().toISOString(),
        );
      const before = store.querySharedExperiences({
        targetCaseRef: 'case-beta',
        capabilityId: CAPABILITY,
      });
      expect(before).toHaveLength(1);
      expect(first(before).provenance.sourceRevision).toBe('outcome-r1');
      writer.exec('COMMIT');
      // After the commit the rev1 experience is stale and excluded.
      expect(
        store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: CAPABILITY }),
      ).toHaveLength(0);
    } finally {
      writer.close();
    }
  });

  it('the identical experience recorded through two handles is stored exactly once', () => {
    const { store, file } = makeStore('two-handles');
    seedVocabulary(store);
    seedCase(store, 'case-alpha', sha256('evidence:case-alpha:outcome-r1'));
    const first = store.recordSharedExperience(experienceInput());
    expect(first.status).toBe('STORED');

    const second = new HostMetaShadowStore(file);
    try {
      expect(second.recordSharedExperience(experienceInput()).status).toBe('ALREADY_STORED');
      expect(
        second.querySharedExperiences({ targetCaseRef: 'case-alpha', capabilityId: CAPABILITY }),
      ).toHaveLength(1);
      expect(
        store.querySharedExperiences({ targetCaseRef: 'case-alpha', capabilityId: CAPABILITY }),
      ).toHaveLength(1);
    } finally {
      second.close();
    }
  });

  it('concurrent submissions and queries across parallel handles do not duplicate or corrupt records', async () => {
    const { store, file } = makeStore('concurrent');
    seedVocabulary(store);
    for (const suffix of ['0', '1', '2', '3']) {
      store.registerMetaPatternId(`pattern.conc-${suffix}`);
    }
    const caseRefs = ['case-w0', 'case-w1', 'case-w2', 'case-w3'];
    for (const caseRef of caseRefs) {
      seedCase(store, caseRef, sha256(`evidence:${caseRef}:outcome-r1`));
    }

    // Each worker thread opens its own connection to the SAME SQLite file and
    // records + queries while the others do the same (WAL, busy_timeout).
    const workerSource = `
      const { parentPort, workerData } = require('node:worker_threads');
      (async () => {
        try {
          const module = await import(workerData.storeUrl);
          const store = new module.HostMetaShadowStore(workerData.file);
          let recorded = 0;
          for (const patternId of workerData.patternIds) {
            const result = store.recordSharedExperience({
              caseRef: workerData.caseRef,
              sourceRevision: workerData.sourceRevision,
              sourceDigest: workerData.sourceDigest,
              capabilityId: workerData.capabilityId,
              taskClass: workerData.taskClass,
              patternId,
              verifiedOutcome: 'VERIFIED_PASS',
              tags: ['tag.windows'],
              constraintCodes: ['constraint.no-elevation'],
            });
            if (result.status === 'STORED') recorded += 1;
          }
          const queried = store.querySharedExperiences({
            targetCaseRef: workerData.caseRef,
            capabilityId: workerData.capabilityId,
          });
          parentPort.postMessage({ ok: true, recorded, queried: queried.length, ids: queried.map((r) => r.experienceId) });
          store.close();
        } catch (error) {
          parentPort.postMessage({ ok: false, error: String(error && error.message ? error.message : error) });
        }
      })();
    `;
    const runs = await Promise.all(
      caseRefs.map(
        (caseRef) =>
          new Promise<{
            ok: boolean;
            recorded?: number;
            queried?: number;
            ids?: string[];
            error?: string;
          }>((resolveWorker, rejectWorker) => {
            const worker = new Worker(workerSource, {
              eval: true,
              workerData: {
                storeUrl: pathToFileURL(STORE_MODULE).href,
                file,
                caseRef,
                sourceRevision: 'outcome-r1',
                sourceDigest: sha256(`evidence:${caseRef}:outcome-r1`),
                capabilityId: CAPABILITY,
                taskClass: TASK_CLASS,
                patternIds: [
                  'pattern.conc-0',
                  'pattern.conc-1',
                  'pattern.conc-2',
                  'pattern.conc-3',
                ],
              },
            });
            worker.on('message', (message) => {
              if (message.ok) resolveWorker(message);
              else rejectWorker(new Error(message.error));
            });
            worker.on('error', rejectWorker);
            worker.on('exit', (code) => {
              if (code !== 0) rejectWorker(new Error(`worker exited ${code}`));
            });
          }),
      ),
    );
    // Every worker recorded its four distinct experiences exactly once and
    // queried a valid in-flight snapshot: at least its own four records, at
    // most the full set, never duplicated or malformed.
    for (const run of runs) {
      expect(run.recorded).toBe(4);
      expect(run.queried).toBeGreaterThanOrEqual(4);
      expect(run.queried).toBeLessThanOrEqual(16);
      expect(new Set(run.ids ?? []).size).toBe((run.ids ?? []).length);
    }
    // Two workers submitting the same source experience do not duplicate it.
    const duplicate = store.recordSharedExperience(
      experienceInput({
        caseRef: 'case-w0',
        sourceDigest: sha256('evidence:case-w0:outcome-r1'),
        patternId: 'pattern.conc-0',
        tags: [TAG_WINDOWS],
        constraintCodes: [CONSTRAINT_NO_ELEVATION],
      }),
    );
    expect(duplicate.status).toBe('ALREADY_STORED');

    // Final integrity: 16 unique records, every digest verifiable via query.
    const all = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
      limit: 20,
    });
    expect(all).toHaveLength(16);
    expect(new Set(all.map((record) => record.experienceId)).size).toBe(16);
    for (const record of all) {
      expect(record.advisoryOnly).toBe(true);
      expect(record.provenance.sourceCaseRef).toMatch(/^case-w[0-3]$/);
    }
    store.close();
  });
});
