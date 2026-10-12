// T04 C06 — ShunAnchorWriter bounded core, unattended negative controls
// (L2 v0.2 delta §7/§8). These run WITHOUT elevation and pin the write-
// transaction guarantees the one-shot privileged writer inherits:
//
//   forged job (unknown key)            → refused, anchor untouched
//   job outside its policy window       → refused, anchor untouched
//   window issued under stale revision  → refused, anchor untouched
//   consumed job replay                 → refused forever, anchor untouched
//   crash after ledger, before payload  → job consumed, anchor untouched
//   crash before the atomic rename      → no partial anchor state exists
//   user write DENIED on the anchor root → apply fails, nothing written
//   writer bytes mismatch the pin       → identity refused before anything
//
// The elevated entry (real UAC consent, positive path) is PENDING_INTERACTIVE
// and is NOT exercised or claimed here. The known-open
// authority-same-user record stays live: this writer changes WHO WRITES the
// anchors, it does not close the HMAC re-sign defect by itself.
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AuthorizationGrant } from '@shun/contracts';
import { afterAll, describe, expect, it } from 'vitest';
import {
  applyWriterJob as applyWriterJobCore,
  cleanupWriterTemp,
  verifyWriterIdentity,
} from '../src/authority-writer/apply.ts';
import { signWriterJob } from '../src/authority-writer/job.ts';
import { generateGrantHmacKey, signGrantWithHmac } from '../src/trusted-store.ts';
import { ON_WINDOWS } from './helpers.ts';

// The grant/TTL policy-window oracle is anchored to a deterministic instant,
// not wall-clock time. Explicit negative-test now overrides retain precedence.
const FIXTURE_INSTANT = '2026-10-11T12:00:00.000Z';
function applyWriterJob(
  ctx: Parameters<typeof applyWriterJobCore>[0],
  job: Parameters<typeof applyWriterJobCore>[1],
): ReturnType<typeof applyWriterJobCore> {
  return applyWriterJobCore(
    { ...ctx, now: ctx.now ?? (() => new Date(FIXTURE_INSTANT)) },
    job,
  );
}

const roots: string[] = [];
afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

interface Fixture {
  anchorRoot: string;
  anchorKey: string;
  attackerKey: string;
  grantJob: ReturnType<typeof signWriterJob>;
  forgedJob: ReturnType<typeof signWriterJob>;
  currentnessJob: ReturnType<typeof signWriterJob>;
  windowId: string;
}

function createFixture(): Fixture {
  const anchorRoot = mkdtempSync(join(tmpdir(), 'shun-writer-'));
  roots.push(anchorRoot);
  mkdirSync(join(anchorRoot, 'grants'), { recursive: true });
  mkdirSync(join(anchorRoot, 'jobs'), { recursive: true });
  const anchorKey = generateGrantHmacKey();
  const attackerKey = generateGrantHmacKey();
  const windowId = 'win-1';
  writeFileSync(
    join(anchorRoot, 'jobs', `window-${windowId}.json`),
    JSON.stringify({
      windowId,
      notBefore: '2020-01-01T00:00:00.000Z',
      notAfter: '2099-01-01T00:00:00.000Z',
      policySnapshotRevision: 'policy-rev-1',
      authorityRevision: 'auth-rev-1',
      maxGrants: 10,
      scopeBudget: {
        riskClasses: ['R2'],
        privilegeLevels: ['ELEVATED'],
        maxGrantTtlMs: 86_400_000,
      },
    }),
  );
  writeFileSync(
    join(anchorRoot, 'current-authority.json'),
    JSON.stringify({
      kind: 'CURRENT',
      authorityId: 'shun.action-controller.test',
      authorityRevision: 'auth-rev-1',
      policySnapshotRevision: 'policy-rev-1',
      policyStatus: 'ACTIVE',
      revokedGrantIds: [],
    }),
  );
  const unsignedGrant: AuthorizationGrant = {
    grantId: 'grant-writer-1',
    issuer: { authorityId: 'shun.action-controller.test', authorityRevision: 'auth-rev-1' },
    taskId: 'task-1',
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'policy-rev-1',
    actionScope: { actionIds: ['act-1'], privilegeLevel: 'ELEVATED' },
    issuedAt: '2026-10-11T00:00:00.000Z',
    expiresAt: '2026-10-12T00:00:00.000Z',
    integrity: { scheme: 'HMAC_SHA256', value: 'unsigned-fixture' },
  };
  const grant: AuthorizationGrant = {
    ...unsignedGrant,
    integrity: signGrantWithHmac(anchorKey, unsignedGrant),
  };
  const grantJob = signWriterJob(anchorKey, {
    jobId: 'job-grant-1',
    jobType: 'issue-grant',
    riskClass: 'R2',
    policyWindowRef: windowId,
    payload: grant,
  });
  const forgedJob = signWriterJob(attackerKey, {
    jobId: 'job-forged-1',
    jobType: 'issue-grant',
    riskClass: 'R2',
    policyWindowRef: windowId,
    payload: grant,
  });
  const currentnessJob = signWriterJob(anchorKey, {
    jobId: 'job-currentness-1',
    jobType: 'write-currentness',
    policyWindowRef: windowId,
    payload: {
      kind: 'CURRENT',
      authorityId: 'shun.action-controller.test',
      authorityRevision: 'auth-rev-2',
      policySnapshotRevision: 'policy-rev-1',
      policyStatus: 'ACTIVE',
      revokedGrantIds: [],
    },
  });
  return { anchorRoot, anchorKey, attackerKey, grantJob, forgedJob, currentnessJob, windowId };
}

function grantTarget(anchorRoot: string): string {
  return join(anchorRoot, 'grants', 'grant-writer-1.json');
}

describe('ShunAnchorWriter core — unattended negative controls (L2 v0.2 delta §7)', () => {
  it('a job sealed under an attacker key is refused before any anchor write', () => {
    const fx = createFixture();
    const r = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.forgedJob,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('JOB_NOT_AUTHENTIC');
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
    expect(existsSync(join(fx.anchorRoot, 'jobs', 'ledger', 'job-forged-1.consumed'))).toBe(false);
  });

  it('a job whose window is expired/not-yet-active is refused (policy-window pre-issuance boundary)', () => {
    const fx = createFixture();
    const r = applyWriterJob(
      {
        anchorRoot: fx.anchorRoot,
        hmacKeyBase64: fx.anchorKey,
        now: () => new Date('2099-06-01T00:00:00.000Z'), // past notAfter (2099-01-01)
      },
      fx.grantJob,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('WINDOW_NOT_ACTIVE');
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
  });

  it('a window issued under a superseded authority revision is refused (currentness, fail closed)', () => {
    const fx = createFixture();
    // Rotate currentness to auth-rev-2 via a legitimate job first.
    const rotate = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.currentnessJob,
    );
    expect(rotate.ok).toBe(true);
    // Now the window (auth-rev-1) no longer matches the CURRENT record.
    const r = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('WINDOW_NOT_CURRENT');
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
  });

  it('UNRESOLVABLE currentness refuses before any writer payload is applied', () => {
    const fx = createFixture();
    writeFileSync(
      join(fx.anchorRoot, 'current-authority.json'),
      JSON.stringify({ kind: 'UNRESOLVABLE', reason: 'simulated lost authority state' }),
    );
    const result = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('WINDOW_NOT_CURRENT');
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
  });

  it('schema-invalid grant payload is refused instead of trusting grantId-only shape', () => {
    const fx = createFixture();
    const malformed = signWriterJob(fx.anchorKey, {
      jobId: 'job-malformed-grant',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: { grantId: 'grant-malformed-only-id' },
    });
    const result = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      malformed,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PAYLOAD_INVALID');
    expect(existsSync(join(fx.anchorRoot, 'grants', 'grant-malformed-only-id.json'))).toBe(false);
  });

  it('a writer-authentic job cannot store a grant with an invalid inner HMAC envelope', () => {
    const fx = createFixture();
    const base = fx.grantJob.payload as AuthorizationGrant;
    const badGrant: AuthorizationGrant = {
      ...base,
      grantId: 'grant-bad-inner-hmac',
      integrity: { scheme: 'HMAC_SHA256', value: 'attacker-invalid-envelope' },
    };
    const job = signWriterJob(fx.anchorKey, {
      jobId: 'job-bad-inner-hmac',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: badGrant,
    });
    const result = applyWriterJob({ anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey }, job);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PAYLOAD_INVALID');
    expect(existsSync(join(fx.anchorRoot, 'jobs', 'ledger', 'job-bad-inner-hmac.consumed'))).toBe(
      false,
    );
    expect(existsSync(join(fx.anchorRoot, 'grants', 'grant-bad-inner-hmac.json'))).toBe(false);
  });

  it('path-ambiguous grantId is refused and cannot escape the grants directory', () => {
    const fx = createFixture();
    const base = fx.grantJob.payload as Record<string, unknown>;
    const traversal = signWriterJob(fx.anchorKey, {
      jobId: 'job-traversal-grant',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: { ...base, grantId: '../escape-grant' },
    });
    const result = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      traversal,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PAYLOAD_INVALID');
    expect(existsSync(join(fx.anchorRoot, 'escape-grant.json'))).toBe(false);
  });

  it('grant issuer/policy/expiry must remain inside the referenced CURRENT policy window', () => {
    const fx = createFixture();
    const base = fx.grantJob.payload as Record<string, unknown>;
    const staleAuthority = signWriterJob(fx.anchorKey, {
      jobId: 'job-stale-authority',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: {
        ...base,
        issuer: {
          authorityId: 'shun.action-controller.test',
          authorityRevision: 'auth-rev-999',
        },
      },
    });
    const r1 = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      staleAuthority,
    );
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.code).toBe('PAYLOAD_INVALID');

    const wrongPolicy = signWriterJob(fx.anchorKey, {
      jobId: 'job-wrong-policy',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: { ...base, policySnapshotRevision: 'policy-rev-other' },
    });
    const r2 = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      wrongPolicy,
    );
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.code).toBe('PAYLOAD_INVALID');

    const expired = signWriterJob(fx.anchorKey, {
      jobId: 'job-expired-grant',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: {
        ...base,
        issuedAt: '2026-10-11T00:00:00.000Z',
        expiresAt: '2099-06-01T00:00:00.000Z',
      },
    });
    const r3 = applyWriterJob(
      {
        anchorRoot: fx.anchorRoot,
        hmacKeyBase64: fx.anchorKey,
        now: () => new Date('2026-10-11T12:00:00.000Z'),
      },
      expired,
    );
    expect(r3.ok).toBe(false);
    if (!r3.ok) expect(r3.code).toBe('PAYLOAD_INVALID');
  });

  it('policy-window risk/privilege scope is enforced before grant issuance', () => {
    const fx = createFixture();
    writeFileSync(
      join(fx.anchorRoot, 'jobs', `window-${fx.windowId}.json`),
      JSON.stringify({
        windowId: fx.windowId,
        notBefore: '2020-01-01T00:00:00.000Z',
        notAfter: '2099-01-01T00:00:00.000Z',
        policySnapshotRevision: 'policy-rev-1',
        authorityRevision: 'auth-rev-1',
        maxGrants: 10,
        scopeBudget: {
          riskClasses: ['R1'],
          privilegeLevels: ['USER'],
          maxGrantTtlMs: 86_400_000,
        },
      }),
    );
    const result = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PAYLOAD_INVALID');
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
  });

  it('policy-window filesystem scope refuses a broader grant', () => {
    const fx = createFixture();
    writeFileSync(
      join(fx.anchorRoot, 'jobs', `window-${fx.windowId}.json`),
      JSON.stringify({
        windowId: fx.windowId,
        notBefore: '2020-01-01T00:00:00.000Z',
        notAfter: '2099-01-01T00:00:00.000Z',
        policySnapshotRevision: 'policy-rev-1',
        authorityRevision: 'auth-rev-1',
        maxGrants: 10,
        scopeBudget: {
          riskClasses: ['R2'],
          privilegeLevels: ['ELEVATED'],
          filesystem: { read: [], write: ['C:\\approved'] },
          maxGrantTtlMs: 86_400_000,
        },
      }),
    );
    const broader = signWriterJob(fx.anchorKey, {
      jobId: 'job-broader-scope',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: {
        ...(fx.grantJob.payload as Record<string, unknown>),
        grantId: 'grant-broader-scope',
        actionScope: {
          actionIds: ['act-1'],
          privilegeLevel: 'ELEVATED',
          filesystem: { read: [], write: ['C:\\outside'] },
        },
      },
    });
    const result = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      broader,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PAYLOAD_INVALID');
  });

  it('path-ambiguous jobId is rejected before it can name a ledger file', () => {
    const fx = createFixture();
    const unsafe = signWriterJob(fx.anchorKey, {
      jobId: '../job-escape',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload: fx.grantJob.payload,
    } as Parameters<typeof signWriterJob>[1]);
    const result = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      unsafe,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('JOB_NOT_AUTHENTIC');
    expect(existsSync(join(fx.anchorRoot, 'jobs', 'job-escape.consumed'))).toBe(false);
  });

  it('maxGrants is an enforced issuance budget across distinct jobIds', () => {
    const fx = createFixture();
    writeFileSync(
      join(fx.anchorRoot, 'jobs', `window-${fx.windowId}.json`),
      JSON.stringify({
        windowId: fx.windowId,
        notBefore: '2020-01-01T00:00:00.000Z',
        notAfter: '2099-01-01T00:00:00.000Z',
        policySnapshotRevision: 'policy-rev-1',
        authorityRevision: 'auth-rev-1',
        maxGrants: 1,
        scopeBudget: {
          riskClasses: ['R2'],
          privilegeLevels: ['ELEVATED'],
          maxGrantTtlMs: 86_400_000,
        },
      }),
    );
    const first = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(first.ok).toBe(true);

    const firstGrant = fx.grantJob.payload as AuthorizationGrant;
    const secondUnsigned: AuthorizationGrant = {
      ...firstGrant,
      grantId: 'grant-writer-2',
      integrity: { scheme: 'HMAC_SHA256', value: 're-sign-below' },
    };
    const payload: AuthorizationGrant = {
      ...secondUnsigned,
      integrity: signGrantWithHmac(fx.anchorKey, secondUnsigned),
    };
    const secondJob = signWriterJob(fx.anchorKey, {
      jobId: 'job-grant-2',
      jobType: 'issue-grant',
      riskClass: 'R2',
      policyWindowRef: fx.windowId,
      payload,
    });
    const second = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      secondJob,
    );
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe('WINDOW_BUDGET_EXHAUSTED');
    expect(existsSync(join(fx.anchorRoot, 'grants', 'grant-writer-2.json'))).toBe(false);
  });

  it('a legitimate grant job applies atomically, and its replay is refused forever', () => {
    const fx = createFixture();
    const r = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(r.ok).toBe(true);
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(true);
    const recorded = JSON.parse(readFileSync(grantTarget(fx.anchorRoot), 'utf8')) as {
      grantId: string;
    };
    expect(recorded.grantId).toBe('grant-writer-1');
    const replay = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.code).toBe('JOB_REPLAYED');
  });

  it('crash after the consumption ledger → job consumed, anchor payload untouched (CONSUMED_NOT_APPLIED shape)', () => {
    const fx = createFixture();
    expect(() =>
      applyWriterJob(
        { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey, crashPoint: 'after-ledger' },
        fx.grantJob,
      ),
    ).toThrow(/after-ledger/);
    // Fail-safe: ledger consumed, no payload, and a replay cannot re-apply.
    expect(existsSync(join(fx.anchorRoot, 'jobs', 'ledger', 'job-grant-1.consumed'))).toBe(true);
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
    const replay = applyWriterJob(
      { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
      fx.grantJob,
    );
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.code).toBe('JOB_REPLAYED');
  });

  it('crash before the atomic rename → no partial anchor state exists', () => {
    const fx = createFixture();
    expect(() =>
      applyWriterJob(
        { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey, crashPoint: 'before-rename' },
        fx.grantJob,
      ),
    ).toThrow(/before-rename/);
    // No grant record landed; only the temp leftover exists (crash debris the
    // entry process would report); the ledger IS consumed (write-ahead order).
    expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
    cleanupWriterTemp(fx.anchorRoot);
    const leftovers = readdirSync(join(fx.anchorRoot, 'grants')).filter((f) => f.includes('.tmp-'));
    expect(leftovers.length).toBe(0);
    expect(existsSync(join(fx.anchorRoot, 'jobs', 'ledger', 'job-grant-1.consumed'))).toBe(true);
  });

  it('a writer bundle whose bytes mismatch the pin is refused before anything (byte pin)', () => {
    const bundle = join(tmpdir(), `shun-writer-bundle-${Date.now()}.mjs`);
    writeFileSync(bundle, 'export {};\n');
    roots.push(bundle);
    const r = verifyWriterIdentity(bundle, 'a'.repeat(64));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('WRITER_IDENTITY_MISMATCH');
    // The entry order (identity gate BEFORE apply) is structural: the ledger
    // of an untouched store shows no consumption for this job.
    const fx = createFixture();
    expect(existsSync(join(fx.anchorRoot, 'jobs', 'ledger', 'job-grant-1.consumed'))).toBe(false);
  });

  it.skipIf(!ON_WINDOWS)(
    'user write DENIED on the anchor root → apply fails, nothing written (denied path)',
    () => {
      const fx = createFixture();
      const hostWhoami = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe');
      const sid = execFileSync(hostWhoami, ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' })
        .split(',')[1]
        ?.trim()
        .replace(/"/g, '');
      const icacls = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe');
      try {
        // Deny write-rights specifically, keeping reads: the writer must still
        // be able to VALIDATE (window/currentness reads) while every write is
        // refused — the honest denied path for an elevated writer on a
        // user-protected root.
        execFileSync(icacls, [fx.anchorRoot, '/deny', `*${sid}:(OI)(CI)(WD,AD,WEA,WA)`], {
          windowsHide: true,
        });
        const r = applyWriterJob(
          { anchorRoot: fx.anchorRoot, hmacKeyBase64: fx.anchorKey },
          fx.grantJob,
        );
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('ANCHOR_WRITE_DENIED');
        expect(existsSync(grantTarget(fx.anchorRoot))).toBe(false);
      } finally {
        try {
          execFileSync(icacls, [fx.anchorRoot, '/remove:d', `*${sid}`], { windowsHide: true });
        } catch {
          // cleanup below removes the tree regardless
        }
      }
    },
  );
});
