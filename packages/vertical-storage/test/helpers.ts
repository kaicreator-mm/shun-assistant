// Shared test infrastructure: a real-local-filesystem B-039 fixture builder
// (injected cache growth, similarly-sized protected decoys, protected user
// assets, secret-shaped canaries) and an in-memory authorization authority
// double that issues HMAC-integrity grants bound to exact plan hashes — the
// trusted substrate seam (L2 §4.6.1) this package consumes via contracts.
import { createHmac, randomBytes } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { type CurrentAuthorityState, canonicalJson } from '@shun/contracts';
import { afterEach } from 'vitest';
import type { StorageDiagnoseRuntime } from '../src/index.ts';

const FIXTURE_ROOTS: string[] = [];

/** Unique per-test fixture root under the OS temp dir (on the real Windows volume). */
export async function makeFixtureRoot(label: string): Promise<string> {
  const root = path.join(
    await fsp.realpath(os.tmpdir()),
    `shun-t07-${label}-${randomBytes(4).toString('hex')}`,
  );
  await fsp.mkdir(root, { recursive: true });
  FIXTURE_ROOTS.push(root);
  return root;
}

afterEach(async () => {
  while (FIXTURE_ROOTS.length > 0) {
    const root = FIXTURE_ROOTS.pop();
    if (!root) continue;
    await fsp.rm(root, { recursive: true, force: true }).catch(() => {});
  }
});

/** The target volume string for a path (e.g. "C:"), as C-003 input expects. */
export function volumeOf(p: string): string {
  return `${p[0]}:`.toUpperCase();
}

export interface PlantedFile {
  relativePath: string;
  bytes: number;
  /** Exact filler content; defaults to deterministic non-secret bytes. */
  content?: string;
}

/** Plant files of an exact size under a directory (deterministic content). */
export async function plantFiles(baseDir: string, files: PlantedFile[]): Promise<number> {
  let total = 0;
  for (const f of files) {
    const target = path.join(baseDir, ...f.relativePath.split('/'));
    await fsp.mkdir(path.dirname(target), { recursive: true });
    const payload = f.content ?? 'a'.repeat(f.bytes);
    const sized =
      payload.length >= f.bytes ? payload.slice(0, f.bytes) : payload.padEnd(f.bytes, 'x');
    await fsp.writeFile(target, sized, 'utf8');
    total += Buffer.byteLength(sized, 'utf8');
  }
  return total;
}

export const CANARY_PRIVATE_KEY =
  '-----BEGIN TEST CANARY PRIVATE KEY----- shun-canary-7f3a91d0 -----END TEST CANARY PRIVATE KEY-----';
export const CANARY_USERNAME = 'shun-canary-user-jo.doE';

/**
 * The B-039 reference fixture: hidden injected growth (cache), a similarly
 * sized USER_CREATED_UNKNOWN decoy, a protected decoy cache-named folder, and
 * a protected user asset containing canary-shaped secret content.
 */
export async function plantB039Fixture(root: string): Promise<{
  cacheDir: string;
  decoyDir: string;
  protectedCacheNamedDir: string;
  protectedPhotos: string;
  cacheBytesPlanted: number;
  decoyBytesPlanted: number;
}> {
  const cacheDir = path.join(root, 'growth', 'appcache');
  const decoyDir = path.join(root, 'growth', 'collect');
  const protectedCacheNamedDir = path.join(root, 'keep', 'cache-like-protected');
  const protectedPhotos = path.join(root, 'keep', 'photos');

  const cacheBytesPlanted = await plantFiles(cacheDir, [
    { relativePath: 'chunk-0001.bin', bytes: 4096 },
    { relativePath: 'chunk-0002.bin', bytes: 4096, content: `junk ${CANARY_PRIVATE_KEY}` },
    { relativePath: 'nested/chunk-0003.bin', bytes: 2048 },
  ]);
  // Same total size as the cache: size alone must never pick the decoy.
  const decoyBytesPlanted = await plantFiles(decoyDir, [
    { relativePath: 'notes.txt', bytes: 5120, content: `user notes for ${CANARY_USERNAME}` },
    { relativePath: 'export.bin', bytes: 5120 },
  ]);
  await plantFiles(protectedCacheNamedDir, [{ relativePath: 'index.dat', bytes: 1024 }]);
  await plantFiles(protectedPhotos, [
    { relativePath: 'img-0001.jpg', bytes: 3072, content: `photo ${CANARY_PRIVATE_KEY}` },
    { relativePath: 'img-0002.jpg', bytes: 1536 },
  ]);
  return {
    cacheDir,
    decoyDir,
    protectedCacheNamedDir,
    protectedPhotos,
    cacheBytesPlanted,
    decoyBytesPlanted,
  };
}

// ---- In-memory authorization authority double (trusted substrate seam). ----

export interface AuthorityDouble {
  grantCount(): number;
  lastGrant(): Record<string, unknown>;
  issueGrant(request: {
    taskId: string;
    planHash: string;
    policySnapshotRevision: string;
    actionScope: {
      actionIds: string[];
      privilegeLevel: 'NONE' | 'USER' | 'ELEVATED';
      filesystem?: { read: string[]; write: string[] };
      network?: { allowed: boolean };
    };
    authorizationKind: 'EXPLICIT_APPROVAL' | 'AUTOMATIC' | 'DURABLE_POLICY';
    approvalRef?: string;
  }): Promise<Record<string, unknown>>;
  currentAuthority(): Promise<CurrentAuthorityState>;
  verifyIntegrity(grant: unknown, envelope: { scheme: string; value: string }): boolean;
  revokeLastGrant(): void;
  supersedePolicy(revision: string): void;
  breakCurrentness(): void;
}

export function makeAuthorityDouble(now: () => string): AuthorityDouble {
  const secret = randomBytes(32);
  let grantSeq = 0;
  let lastIssued: Record<string, unknown> | null = null;
  const issued: Record<string, unknown>[] = [];
  const authorityRevision = 'auth-rev-1';
  let policySnapshotRevision = 'policy-rev-1';
  const revokedGrantIds: string[] = [];
  let currentnessBroken = false;

  const sign = (grant: Record<string, unknown>): string => {
    const { integrity: _omit, ...rest } = grant;
    return createHmac('sha256', secret).update(canonicalJson(rest), 'utf8').digest('hex');
  };

  return {
    grantCount: () => issued.length,
    lastGrant: () => {
      if (!lastIssued) throw new Error('no grant issued');
      return lastIssued;
    },
    async issueGrant(request) {
      grantSeq += 1;
      const grant: Record<string, unknown> = {
        grantId: `grant-t07-${grantSeq}`,
        issuer: { authorityId: 'authority/test-double', authorityRevision },
        taskId: request.taskId,
        planHash: request.planHash,
        policySnapshotRevision,
        actionScope: request.actionScope,
        issuedAt: now(),
        expiresAt: new Date(Date.parse(now()) + 10 * 60_000).toISOString(),
        ...(request.approvalRef ? { approvalRef: request.approvalRef } : {}),
      };
      const envelope = { scheme: 'HMAC_SHA256', value: sign(grant) };
      const withIntegrity = { ...grant, integrity: envelope };
      issued.push(withIntegrity);
      lastIssued = withIntegrity;
      return withIntegrity;
    },
    async currentAuthority() {
      if (currentnessBroken) {
        return { kind: 'UNRESOLVABLE', reason: 'currentness record unreadable (test double)' };
      }
      return {
        kind: 'CURRENT',
        authorityId: 'authority/test-double',
        authorityRevision,
        policySnapshotRevision,
        policyStatus: 'ACTIVE',
        revokedGrantIds,
      };
    },
    verifyIntegrity(grant, envelope) {
      const g = grant as Record<string, unknown>;
      const { integrity: _omit, ...rest } = g;
      const expected = createHmac('sha256', secret)
        .update(canonicalJson(rest), 'utf8')
        .digest('hex');
      return envelope.scheme === 'HMAC_SHA256' && envelope.value === expected;
    },
    revokeLastGrant() {
      const g = lastIssued as { grantId?: string } | null;
      if (g?.grantId) revokedGrantIds.push(g.grantId);
    },
    supersedePolicy(revision: string) {
      policySnapshotRevision = revision;
    },
    breakCurrentness() {
      currentnessBroken = true;
    },
  };
}

/** Controllable ISO clock for deterministic receipts. */
export function makeClock(startIso = new Date().toISOString()): {
  now: () => string;
  advanceMs: (ms: number) => void;
} {
  let current = Date.parse(startIso);
  return {
    now: () => new Date(current).toISOString(),
    advanceMs: (ms: number) => {
      current += ms;
    },
  };
}

// ---- StorageDiagnoseRuntime wired to the authority double. ----

export function makeRuntime(options: {
  root: string;
  scopeRoots: string[];
  authority: AuthorityDouble;
  clock: { now: () => string };
}): StorageDiagnoseRuntime & {
  approvals: { planHash: string; summary: string }[];
  decision: { approved: boolean };
} {
  const approvals: { planHash: string; summary: string }[] = [];
  const decision = { approved: true };
  return {
    approvals,
    decision,
    ports: {
      async requestApproval(request) {
        approvals.push({ planHash: request.planHash, summary: request.summary });
        return {
          approvalId: `approval-t07-${approvals.length}`,
          approved: decision.approved,
          reason: decision.approved ? undefined : 'user declined (test double)',
        };
      },
      issueGrant: (request) => options.authority.issueGrant(request),
      currentAuthority: () => options.authority.currentAuthority(),
      verifyIntegrity: (grant, envelope) => options.authority.verifyIntegrity(grant, envelope),
    },
    scope: { roots: options.scopeRoots },
    evidenceDir: path.join(options.root, 'evidence'),
    policySnapshotRevision: 'policy-rev-1',
    rankingPolicyRevision: 'ranking-rev-1',
    environmentId: 'env-local-windows-t07',
    providerId: 'storage.cleaner.local-windows',
    providerVersion: '0.1.0-t07',
    clock: options.clock.now,
  };
}
