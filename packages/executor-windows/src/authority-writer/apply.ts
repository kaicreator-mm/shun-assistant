// ShunAnchorWriter apply layer (L2 v0.2 delta §7) — the one-shot, atomic,
// crash-honest write transaction of the bounded privileged trusted writer.
//
// Per job: (1) job integrity + policy-window currency, (2) WRITE-AHEAD
// consumption ledger (replay refusal forever after), (3) payload write via
// temp + fsync + atomic rename — a crash before the rename leaves the anchor
// untouched, so no partial anchor state ever exists; a crash after the ledger
// marker is the documented fail-safe CONSUMED_NOT_APPLIED shape. Every
// refusal leaves the anchor byte-identical.
//
// This module is the UNATTENDED-VALIDATABLE core: identity verification,
// integrity/window/replay negatives and both crash points are testable
// without elevation. The elevated process entry and the real UAC positive
// path are PENDING_INTERACTIVE and are never claimed validated.
import { createHash } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  type AuthorizationGrant,
  type CurrentAuthorityState,
  CurrentAuthorityStateSchema,
  pathWithin,
} from '@shun/contracts';
import {
  isSafeAnchorId,
  jobPayloadAsCurrentness,
  jobPayloadAsGrant,
  type PolicyWindow,
  PolicyWindowSchema,
  verifyWriterJob,
  type WriterJob,
} from './job.ts';

export type WriterRefusalCode =
  | 'WRITER_IDENTITY_MISMATCH'
  | 'JOB_NOT_AUTHENTIC'
  | 'JOB_MALFORMED'
  | 'WINDOW_NOT_CURRENT'
  | 'WINDOW_NOT_ACTIVE'
  | 'WINDOW_BUDGET_EXHAUSTED'
  | 'JOB_REPLAYED'
  | 'PAYLOAD_INVALID'
  | 'ANCHOR_WRITE_DENIED';

export type ApplyResult =
  | { ok: true; appliedAt: string; target: string }
  | { ok: false; code: WriterRefusalCode; reason: string };

/** Test-only crash injection points (documented, never used in production). */
export type CrashPoint = 'after-ledger' | 'before-rename';

export interface ApplyContext {
  /** The authorization anchor root (L2 v0.2 delta §3). */
  anchorRoot: string;
  /** Anchor key (base64) — under v0.2 deployment, writer-only readable. */
  hmacKeyBase64: string;
  /** Injectable clock (tests pin time; production uses the real clock). */
  now?: () => Date;
  /** Test-only crash injection. */
  crashPoint?: CrashPoint;
}

/**
 * Writer byte-pin verification (delta §5): the measured bundle must equal the
 * writer-pin's digest — unreadable bytes fail closed like any mismatch.
 */
export function verifyWriterIdentity(
  writerBundlePath: string,
  expectedSha256: string,
): { ok: true } | { ok: false; code: WriterRefusalCode; reason: string } {
  let measured: string;
  try {
    measured = createHash('sha256').update(readFileSync(writerBundlePath)).digest('hex');
  } catch {
    return {
      ok: false,
      code: 'WRITER_IDENTITY_MISMATCH',
      reason: `writer bundle unreadable — refusing to apply anything (fail closed): ${writerBundlePath}`,
    };
  }
  if (measured !== expectedSha256) {
    return {
      ok: false,
      code: 'WRITER_IDENTITY_MISMATCH',
      reason: `writer bytes do not match the writer-pin (${measured} != ${expectedSha256}) — refusing to apply anything (fail closed)`,
    };
  }
  return { ok: true };
}

/** Atomic durable write: temp file + fsync + rename (no partial anchor state). */
function atomicWrite(target: string, text: string, crashPoint?: CrashPoint): void {
  const temp = `${target}.tmp-${process.pid}-${Math.random().toString(36).slice(2)}`;
  const fd = openSync(temp, 'wx');
  try {
    writeSync(fd, text, null, 'utf8');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (crashPoint === 'before-rename') {
    // Simulated crash: the temp file exists, the anchor is untouched.
    throw new Error(`simulated crash at before-rename (${temp} left behind)`);
  }
  renameSync(temp, target);
}

export function applyWriterJob(ctx: ApplyContext, rawJob: unknown): ApplyResult {
  const now = ctx.now ?? (() => new Date());

  // 1. Job integrity: a forged order never reaches the ledger.
  const verdict = verifyWriterJob(ctx.hmacKeyBase64, rawJob);
  if (!verdict.ok) return { ok: false, code: 'JOB_NOT_AUTHENTIC', reason: verdict.reason };
  const job: WriterJob = verdict.job;

  // 2. Policy window: the referenced window must EXIST in the anchor root,
  //    be ACTIVE at apply time, and be CURRENT against the store's own
  //    currentness record (window issued under a superseded revision voids
  //    the job — same currentness discipline as grants, L2 v0.1 §4.6.1).
  const window = readPolicyWindow(ctx.anchorRoot, job.policyWindowRef);
  if (!window.ok) return window;
  const clock = now();
  if (clock < new Date(window.window.notBefore) || clock > new Date(window.window.notAfter)) {
    return {
      ok: false,
      code: 'WINDOW_NOT_ACTIVE',
      reason: `policy window ${job.policyWindowRef} is not active at apply time (${clock.toISOString()})`,
    };
  }
  const currency = readCurrentness(ctx.anchorRoot);
  if (!currency.ok) return currency;
  if (currency.state.kind !== 'CURRENT') {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: `current authority/policy state is UNRESOLVABLE — policy window ${job.policyWindowRef} cannot authorize issuance`,
    };
  }
  if (
    currency.state.authorityRevision !== window.window.authorityRevision ||
    currency.state.policySnapshotRevision !== window.window.policySnapshotRevision
  ) {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: `policy window ${job.policyWindowRef} was issued under a superseded authority/policy revision — refusing (fail closed)`,
    };
  }

  // 3. Payload validation BEFORE any anchor write.
  let target: string;
  let text: string;
  let grantForBudget: AuthorizationGrant | undefined;
  if (job.jobType === 'issue-grant') {
    const grant = jobPayloadAsGrant(job);
    if (!grant) {
      return {
        ok: false,
        code: 'PAYLOAD_INVALID',
        reason: 'issue-grant payload is not a valid frozen AuthorizationGrant',
      };
    }
    if (!isSafeAnchorId(grant.grantId)) {
      return {
        ok: false,
        code: 'PAYLOAD_INVALID',
        reason: `grantId ${JSON.stringify(grant.grantId)} is not a canonical Windows-safe anchor identifier`,
      };
    }
    const grantViolation = grantWindowViolation(
      grant,
      job.riskClass,
      window.window,
      currency.state,
      clock,
    );
    if (grantViolation) {
      return { ok: false, code: 'PAYLOAD_INVALID', reason: grantViolation };
    }
    grantForBudget = grant;
    target = join(ctx.anchorRoot, 'grants', `${grant.grantId}.json`);
    text = `${JSON.stringify(grant, null, 2)}\n`;
  } else {
    const state = jobPayloadAsCurrentness(job);
    if (!state) {
      return {
        ok: false,
        code: 'PAYLOAD_INVALID',
        reason: 'write-currentness payload is not a valid frozen CurrentAuthorityState',
      };
    }
    target = join(ctx.anchorRoot, 'current-authority.json');
    text = `${JSON.stringify(state, null, 2)}\n`;
  }

  // 4. Write-ahead consumption ledger: replay refusal FOREVER after this
  //    point. Crash here = consumed-but-unapplied (fail-safe, receipt-visible).
  try {
    mkdirSync(join(ctx.anchorRoot, 'jobs', 'ledger'), { recursive: true });
  } catch (e) {
    return {
      ok: false,
      code: 'ANCHOR_WRITE_DENIED',
      reason: `consumption ledger unusable: ${String(e)}`,
    };
  }
  const marker = join(ctx.anchorRoot, 'jobs', 'ledger', `${job.jobId}.consumed`);
  if (existsSync(marker)) {
    return {
      ok: false,
      code: 'JOB_REPLAYED',
      reason: `job ${job.jobId} was already consumed — replay refused`,
    };
  }
  if (grantForBudget) {
    const reservation = reserveWindowGrantSlot(ctx.anchorRoot, window.window, job.jobId);
    if (!reservation.ok) return reservation;
  }
  const appliedAt = now().toISOString();
  try {
    atomicWrite(marker, `${appliedAt}\n`);
  } catch (e) {
    return {
      ok: false,
      code: 'ANCHOR_WRITE_DENIED',
      reason: `consumption ledger write refused: ${String(e)}`,
    };
  }
  if (ctx.crashPoint === 'after-ledger') {
    throw new Error('simulated crash at after-ledger (job consumed, payload not applied)');
  }

  // 5. Payload write: temp + fsync + atomic rename.
  try {
    mkdirSync(join(ctx.anchorRoot, 'grants'), { recursive: true });
    atomicWrite(target, text, ctx.crashPoint);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (ctx.crashPoint === 'before-rename') throw e;
    return {
      ok: false,
      code: 'ANCHOR_WRITE_DENIED',
      reason: `anchor write refused${code ? ` (${code})` : ''}: ${String(e)}`,
    };
  }
  return { ok: true, appliedAt, target };
}

function grantWindowViolation(
  grant: AuthorizationGrant,
  riskClass: WriterJob['riskClass'],
  window: PolicyWindow,
  current: Extract<CurrentAuthorityState, { kind: 'CURRENT' }>,
  now: Date,
): string | undefined {
  if (!riskClass || !window.scopeBudget.riskClasses.includes(riskClass)) {
    return `grant risk class ${riskClass ?? '(missing)'} is outside policy-window scopeBudget`;
  }
  if (!window.scopeBudget.privilegeLevels.includes(grant.actionScope.privilegeLevel)) {
    return `grant privilege ${grant.actionScope.privilegeLevel} is outside policy-window scopeBudget`;
  }
  if (
    grant.issuer.authorityId !== current.authorityId ||
    grant.issuer.authorityRevision !== window.authorityRevision ||
    grant.policySnapshotRevision !== window.policySnapshotRevision
  ) {
    return 'grant issuer/policy revision is outside the CURRENT policy window';
  }

  const issuedMs = Date.parse(grant.issuedAt);
  const expiresMs = Date.parse(grant.expiresAt);
  const startMs = Date.parse(window.notBefore);
  const endMs = Date.parse(window.notAfter);
  if (
    issuedMs < startMs ||
    issuedMs > now.getTime() ||
    expiresMs <= issuedMs ||
    expiresMs > endMs ||
    expiresMs <= now.getTime() ||
    expiresMs - issuedMs > window.scopeBudget.maxGrantTtlMs
  ) {
    return 'grant issuedAt/expiresAt exceeds the approved policy-window time/TTL budget';
  }

  const covered = (paths: readonly string[], prefixes: readonly string[] | undefined): boolean =>
    paths.length === 0 ||
    (prefixes !== undefined &&
      prefixes.length > 0 &&
      paths.every((path) => prefixes.some((prefix) => pathWithin(path, prefix))));

  const grantFs = grant.actionScope.filesystem;
  if (grantFs) {
    const budgetFs = window.scopeBudget.filesystem;
    if (!covered(grantFs.write, budgetFs?.write)) {
      return 'grant filesystem write scope exceeds policy-window scopeBudget';
    }
    if (!covered(grantFs.read, [...(budgetFs?.read ?? []), ...(budgetFs?.write ?? [])])) {
      return 'grant filesystem read scope exceeds policy-window scopeBudget';
    }
  }

  if (grant.actionScope.network?.allowed) {
    const budgetNetwork = window.scopeBudget.network;
    if (!budgetNetwork?.allowed) return 'grant network access exceeds policy-window scopeBudget';
    const grantDomains = grant.actionScope.network.domains;
    const budgetDomains = budgetNetwork.domains;
    if (budgetDomains !== undefined) {
      if (!grantDomains || grantDomains.length === 0) {
        return 'domain-unbounded grant network scope exceeds bounded policy-window domains';
      }
      if (!grantDomains.every((domain) => budgetDomains.includes(domain))) {
        return 'grant network domains exceed policy-window scopeBudget';
      }
    }
  }

  const grantRegistry = grant.actionScope.registry?.write ?? [];
  if (!covered(grantRegistry, window.scopeBudget.registry?.write)) {
    return 'grant registry write scope exceeds policy-window scopeBudget';
  }
  return undefined;
}

function reserveWindowGrantSlot(
  anchorRoot: string,
  window: PolicyWindow,
  jobId: string,
): { ok: true } | { ok: false; code: WriterRefusalCode; reason: string } {
  const dir = join(anchorRoot, 'jobs', 'window-budget', window.windowId);
  try {
    mkdirSync(dir, { recursive: true });
  } catch (error) {
    return {
      ok: false,
      code: 'ANCHOR_WRITE_DENIED',
      reason: `window budget ledger unusable: ${String(error)}`,
    };
  }

  let slot = 0;
  while (slot < window.maxGrants) {
    const file = join(dir, `${slot}.slot`);
    try {
      const existing = readFileSync(file, 'utf8').trim();
      if (existing === jobId) {
        return {
          ok: false,
          code: 'JOB_REPLAYED',
          reason: `job ${jobId} already reserved grant budget — replay refused`,
        };
      }
      slot += 1;
      continue;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        return {
          ok: false,
          code: 'ANCHOR_WRITE_DENIED',
          reason: `window budget slot unreadable: ${String(error)}`,
        };
      }
    }

    let fd: number | undefined;
    try {
      fd = openSync(file, 'wx');
      writeSync(fd, `${jobId}\n`, null, 'utf8');
      fsyncSync(fd);
      closeSync(fd);
      return { ok: true };
    } catch (error) {
      if (fd !== undefined) closeSync(fd);
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST') continue;
      return {
        ok: false,
        code: 'ANCHOR_WRITE_DENIED',
        reason: `window budget reservation failed: ${String(error)}`,
      };
    }
  }
  return {
    ok: false,
    code: 'WINDOW_BUDGET_EXHAUSTED',
    reason: `policy window ${window.windowId} exhausted maxGrants=${window.maxGrants}`,
  };
}

function readPolicyWindow(
  anchorRoot: string,
  windowId: string,
): { ok: true; window: PolicyWindow } | { ok: false; code: WriterRefusalCode; reason: string } {
  const file = join(anchorRoot, 'jobs', `window-${windowId}.json`);
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: `policy window record unreadable: ${windowId}`,
    };
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: `policy window record corrupt: ${windowId}`,
    };
  }
  const parsed = PolicyWindowSchema.safeParse(decoded);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: `policy window record corrupt: ${windowId}`,
    };
  }
  return { ok: true, window: parsed.data };
}

function readCurrentness(
  anchorRoot: string,
):
  | { ok: true; state: CurrentAuthorityState }
  | { ok: false; code: WriterRefusalCode; reason: string } {
  const file = join(anchorRoot, 'current-authority.json');
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: 'currentness record unreadable (fail closed)',
    };
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: 'currentness record corrupt (fail closed)',
    };
  }
  const parsed = CurrentAuthorityStateSchema.safeParse(decoded);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'WINDOW_NOT_CURRENT',
      reason: 'currentness record corrupt (fail closed)',
    };
  }
  return { ok: true, state: parsed.data };
}

/** Remove a writer temp leftover after an injected before-rename crash (tests). */
export function cleanupWriterTemp(anchorRoot: string): void {
  const grants = join(anchorRoot, 'grants');
  if (!existsSync(grants)) return;
  for (const f of readdirSync(grants)) {
    if (f.includes('.tmp-')) rmSync(join(grants, f), { force: true });
  }
}
