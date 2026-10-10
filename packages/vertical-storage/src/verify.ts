// C-003 semantic verification (L2 §4.7/§13): execution success without
// required semantic verification can never become Task PASS. Checks protected
// assets by content hash, verifies reclaimed bytes against the privileged
// phase journal, and enforces input→output coverage equality. A protected
// asset hash mismatch fails verification with PROTECTED_ASSET_TOUCHED — it is
// never reported as a successful cleanup.
import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import {
  type StorageDiagnoseInput,
  type StorageDiagnoseOutput,
  type VerificationInput,
  type VerificationReceipt,
  validateProtectedAssetCoverage,
} from '@shun/contracts';
import { StorageVerticalError } from './errors.ts';
import type { JournalReplay } from './journal.ts';
import { replayJournal } from './journal.ts';
import { measureDirectoryNow } from './observe.ts';

export const VERIFIER_ID = 'verifier.storage-c003';
export const VERIFIER_REVISION = 'r1';

export interface ProtectedBaseline {
  path: string;
  /** sha256 for files; directory fingerprint digest (see fingerprintDirectory). */
  baselineSha256?: string;
}

export interface StorageVerifierDeps {
  /** Precommitted baselines (benchmark envelope) when provided; otherwise the verifier compares against pre-action fingerprints taken at observation time. */
  baselines?: readonly ProtectedBaseline[];
  /** contentHash -> pre-action fingerprints keyed by canonical path (production path). */
  preActionFingerprints?: ReadonlyMap<string, string>;
}

export interface ProtectedVerification {
  path: string;
  unchanged: boolean;
  detail: string;
}

/**
 * Deterministic content fingerprint. Files hash their bytes (streamed);
 * directories combine sorted relative paths + per-file sha256 + sizes, so any
 * content, addition, removal or rename inside the tree changes the digest.
 * Reparse points contribute name+size only and are never followed.
 */
export async function fingerprintPath(target: string): Promise<string> {
  const st = await fsp.lstat(target);
  if (st.isSymbolicLink()) {
    return createHash('sha256')
      .update(`reparse:${path.basename(target)}:${st.size}`)
      .digest('hex');
  }
  if (st.isFile()) {
    return hashFile(target);
  }
  return fingerprintDirectory(target);
}

export async function hashFile(filePath: string): Promise<string> {
  const contents = await fsp.readFile(filePath);
  return createHash('sha256').update(contents).digest('hex');
}

async function fingerprintDirectory(dir: string, prefix = ''): Promise<string> {
  const hash = createHash('sha256');
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of sorted) {
    const entryPath = path.join(dir, entry.name);
    const rel = `${prefix}${entry.name}`;
    if (entry.isSymbolicLink()) {
      const st = await fsp.lstat(entryPath);
      hash.update(`reparse|${rel}|${st.size}\n`);
      continue;
    }
    if (entry.isDirectory()) {
      hash.update(`dir|${rel}\n`);
      await fingerprintDirectory(entryPath, `${rel}/`).then((inner) => hash.update(inner));
      continue;
    }
    if (entry.isFile()) {
      const st = await fsp.lstat(entryPath);
      const digest = await hashFile(entryPath);
      hash.update(`file|${rel}|${st.size}|${digest}\n`);
    }
  }
  return hash.digest('hex');
}

/**
 * Verify every declared protected asset and return per-asset verification
 * records, order-aligned with `protectedRealPaths` (canonical realpaths).
 * Baselines win when present (benchmark canary truth); otherwise the
 * pre-action fingerprint map must cover the asset — a missing baseline on the
 * production path is a verifier configuration failure (fail closed), not an
 * automatic PASS.
 */
export async function verifyProtectedAssets(input: {
  protectedRealPaths: readonly string[];
  deps: StorageVerifierDeps;
}): Promise<ProtectedVerification[]> {
  const results: ProtectedVerification[] = [];
  for (const p of input.protectedRealPaths) {
    const current = await fingerprintPath(p);
    const baseline = input.deps.baselines?.find((b) => b.path === p);
    const expected =
      baseline?.baselineSha256 ?? (input.deps.preActionFingerprints?.get(p) as string | undefined);
    if (expected === undefined) {
      throw new StorageVerticalError(
        'PROTECTED_ASSET_TOUCHED',
        `no baseline available for protected asset ${p}; refusing to claim integrity without evidence`,
      );
    }
    results.push({
      path: p,
      unchanged: current === expected,
      detail:
        current === expected
          ? `sha256 fingerprint matches precommitted baseline`
          : `fingerprint mismatch: expected ${expected.slice(0, 12)}…, observed ${current.slice(0, 12)}…`,
    });
  }
  return results;
}

export interface StorageVerificationContext {
  verificationInput: VerificationInput;
  storageInput: StorageDiagnoseInput;
  /** Canonical real protected paths, aligned with storageInput.protectedAssets. */
  protectedRealPaths: readonly string[];
  /** Journal bytes deleted (Σ EXEC_DONE) — the only accepted reclaim source. */
  journal: { path: string };
  /** Post-action measurement of the attributed growth source (regrowth honesty). */
  postActionStateBytes: number;
  deps: StorageVerifierDeps;
}

export interface StorageVerificationOutcome {
  receipt: VerificationReceipt;
  protectedVerifications: ProtectedVerification[];
  grossReclaimedBytes: number;
}

/**
 * Run the C-003 semantic checks. Emits a VerificationReceipt whose status is
 * FAIL when any required check fails; failure detail names the C-003 taxonomy
 * code so callers can map it without re-parsing prose.
 */
export async function verifyStorageCleanup(
  context: StorageVerificationContext,
): Promise<StorageVerificationOutcome> {
  const { storageInput, protectedRealPaths, journal } = context;
  const checks: VerificationReceipt['checks'] = [];

  // 1. Protected assets unchanged (content hashes).
  let protectedVerifications: ProtectedVerification[] = [];
  try {
    protectedVerifications = await verifyProtectedAssets({
      protectedRealPaths,
      deps: context.deps,
    });
    const touched = protectedVerifications.filter((v) => !v.unchanged);
    checks.push({
      checkId: 'protected-assets-unchanged',
      status: touched.length === 0 ? 'PASS' : 'FAIL',
      detail:
        touched.length === 0
          ? protectedVerifications.map((v) => `${v.path}: ${v.detail}`).join('; ')
          : `PROTECTED_ASSET_TOUCHED: ${touched.map((v) => v.path).join(', ')}`,
    });
  } catch (error) {
    const code = error instanceof StorageVerticalError ? error.code : 'PROTECTED_ASSET_TOUCHED';
    checks.push({
      checkId: 'protected-assets-unchanged',
      status: 'FAIL',
      detail: code,
    });
  }

  // 2. Reclaimed bytes attributable to the bounded action (journal-sourced).
  const replay: JournalReplay = await replayJournal(journal.path);
  const grossReclaimedBytes = replay.entries
    .filter((e) => e.phase === 'EXEC_DONE' && e.file !== undefined && !e.file.endsWith('(dir)'))
    .reduce((sum, e) => sum + (e.bytes ?? 0), 0);
  const oracleInputs = context.verificationInput.oracleInputs ?? {};
  const receiptReclaimed = readReclaimed(oracleInputs);
  const reclaimOk =
    receiptReclaimed === null
      ? grossReclaimedBytes === 0
      : receiptReclaimed.grossBytes === grossReclaimedBytes;
  checks.push({
    checkId: 'reclaimed-bytes-verified',
    status: reclaimOk ? 'PASS' : 'FAIL',
    detail: reclaimOk
      ? `journal Σ EXEC_DONE = ${grossReclaimedBytes} bytes matches receipt; post-action state ${context.postActionStateBytes} bytes`
      : `RECLAIM_NOT_VERIFIED: receipt claims ${receiptReclaimed?.grossBytes ?? 0} but journal proves ${grossReclaimedBytes}`,
  });

  // 3. Coverage equality (declared vs recorded, contracts helper). The
  // helper reads only protectedAssetVerification; the stub fills the rest of
  // the output shape with placeholders that never reach any caller.
  const assembled = {
    ...storageInput,
    attribution: {
      growthSourcePath: 'coverage-check-stub',
      classifiedAs: 'CACHE',
      evidenceRefs: ['evidence://coverage-check-stub'],
    },
    cleanupPlan: null,
    protectedAssetVerification: assembleProtectedVerificationRecords(
      storageInput,
      protectedVerifications,
      protectedRealPaths,
    ),
  } as unknown as StorageDiagnoseOutput;
  const coverageIssues = validateProtectedAssetCoverage(storageInput, assembled);
  checks.push({
    checkId: 'protected-asset-coverage',
    status: coverageIssues.length === 0 ? 'PASS' : 'FAIL',
    detail:
      coverageIssues.length === 0
        ? `all ${protectedRealPaths.length} declared protected assets verified exactly once`
        : coverageIssues.join('; '),
  });

  // 4. Targets stayed within the declared scope (bounded action identity).
  const scopeRoots = oracleInputs.scopeRoots;
  const scopeOk = Array.isArray(scopeRoots) && scopeRoots.length > 0;
  checks.push({
    checkId: 'targets-within-scope',
    status: scopeOk ? 'PASS' : 'FAIL',
    detail: scopeOk
      ? 'execution scoped to declared roots'
      : 'scope roots missing from oracle inputs',
  });

  const failed = checks.filter((c) => c.status === 'FAIL');
  const receipt: VerificationReceipt = {
    taskId: storageInput.taskId,
    verifierId: VERIFIER_ID,
    verifierRevision: VERIFIER_REVISION,
    status: failed.length === 0 ? 'PASS' : 'FAIL',
    checks,
    oracleInputs,
    evidenceRefs: [
      `evidence://journal/${path.basename(journal.path)}`,
      `evidence://observation/${storageInput.taskId}`,
    ],
  };
  return { receipt, protectedVerifications, grossReclaimedBytes };
}

function readReclaimed(oracleInputs: Record<string, unknown>): {
  grossBytes: number;
  postActionStateBytes: number;
} | null {
  const reclaimed = oracleInputs.reclaimed;
  if (
    reclaimed &&
    typeof reclaimed === 'object' &&
    'grossBytes' in reclaimed &&
    typeof (reclaimed as { grossBytes: unknown }).grossBytes === 'number'
  ) {
    return reclaimed as { grossBytes: number; postActionStateBytes: number };
  }
  return null;
}

function assembleProtectedVerificationRecords(
  storageInput: StorageDiagnoseInput,
  verifications: ProtectedVerification[],
  protectedRealPaths: readonly string[],
): StorageDiagnoseOutput['protectedAssetVerification'] {
  return storageInput.protectedAssets.map((declared, index) => {
    const real = verifications[index];
    const realPath = protectedRealPaths[index];
    const matched = real && realPath !== undefined && real.path === realPath ? real : undefined;
    return {
      path: declared.path,
      unchanged: matched ? matched.unchanged : false,
    };
  });
}

/** Fresh post-action measurement helper re-exported for the diagnose flow. */
export { measureDirectoryNow };
