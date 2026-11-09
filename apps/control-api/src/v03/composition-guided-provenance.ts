/**
 * R02-E production Guided trust composition (R04 #404: per-user LocalAppData).
 *
 * The only production trust pin is a public SPKI digest in the fixed sibling
 * file under the per-interactive-user LocalAppData authority directory of
 * THIS Windows session. The trust root and pin are resolved from the
 * OS-provided session values with strict canonical/profile validation —
 * never from environment-controlled product paths, CLI, database or receipt
 * input. Runtime stays verify-only; first-run bootstrap lives in
 * scripts/bootstrap-guided-localappdata.ts, never here.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostGuidedService as HostGuidedServiceImpl } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  assertGuidedRegularCanonicalPath,
  assessGuidedTrustProtection,
  canonicalGuidedDatabasePath,
  createExternalGuidedProvenanceAuthority,
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  type GuidedAclAncestorInspector,
  type GuidedAclInspector,
  type GuidedTrustAclSnapshot,
  guidedPublicKeySpkiSha256,
  guidedReceiptFileName,
  inspectWindowsGuidedTrustAcl,
  listGuidedReceiptPaths,
  perUserGuidedTrustAncestorChain,
  perUserGuidedTrustDirectory,
  queryWindowsProcessUserSid,
  readGuidedTrustAnchor,
  resolveWindowsLocalAppDataBase,
} from '../real-storage/guided-provenance-issuance.ts';

const TRUST_PIN_FILE = 'guided-provenance-trust-pin.json';
const TRUST_PIN_SCHEMA = 'shun.guided.provenance-trust-pin.v1';
const TRUST_PIN_DIGEST = /^[0-9a-f]{64}$/;
const MAX_PIN_BYTES = 4096;
const MAX_TRUST_FILE_BYTES = 262_144;

export interface GuidedServiceTestOverrides {
  /** Temporary test trust directory; never accepted outside Vitest. */
  readonly trustDir: string;
  /** Must be the fixed sibling pin filename under trustDir's parent. */
  readonly pinPath: string;
  /** Fixture interactive-user SID for the per-user owner/DACL policy. */
  readonly ownerSid: string;
  readonly inspectAcl: GuidedAclInspector;
  readonly inspectAclAncestors: GuidedAclAncestorInspector;
}

function hasPath(snapshot: GuidedTrustAclSnapshot, path: string): boolean {
  const expected = resolve(path).toLowerCase();
  return snapshot.some((entry) => {
    if (!entry || typeof entry.path !== 'string') return false;
    try {
      return resolve(entry.path).toLowerCase() === expected;
    } catch {
      return false;
    }
  });
}

function assertRegularFile(path: string, code: string, maxBytes: number): void {
  let info: ReturnType<typeof lstatSync>;
  try {
    info = lstatSync(path);
  } catch {
    throw new Error(code);
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size <= 0 || info.size > maxBytes) {
    throw new Error(code);
  }
  try {
    assertGuidedRegularCanonicalPath(path, code);
  } catch {
    throw new Error(code);
  }
}

/**
 * Trust material was never provisioned for THIS Windows user. Startup still
 * fails closed with the precise coded error; this console record only
 * distinguishes "first run — setup required" from corrupted or aliased trust
 * files in the operator's boot output, and prints the one-time consented
 * bootstrap path. Never creates trust material.
 */
function refuseWithSetupRequiredRecord(path: string, code: string): never {
  try {
    lstatSync(path);
  } catch {
    console.error(`KEY_NOT_PROVISIONED ${path}`);
    console.error(
      'GUIDED_TRUST_SETUP_REQUIRED: run the one-time consented bootstrap ' +
        '(apps/control-api/scripts/bootstrap-guided-localappdata.ts --consent) as this Windows user',
    );
  }
  throw new Error(code);
}

/**
 * Node's lstat catches symbolic links. On Windows also inspect the native
 * FILE_ATTRIBUTE_REPARSE_POINT bit: a non-symlink reparse file must not be
 * treated as an ordinary pin file.
 */
function assertNoWindowsReparsePoint(path: string): void {
  if (process.platform !== 'win32') return;
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const powershell = resolve(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script = [
    '$ErrorActionPreference = "Stop"',
    '$item = Get-Item -LiteralPath $env:SHUN_GUIDED_PIN_PATH -Force -ErrorAction Stop',
    'if ($item.PSIsContainer) { throw "GUIDED_TRUST_PIN_NOT_REGULAR_FILE" }',
    'if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "GUIDED_TRUST_PIN_REPARSE_POINT" }',
    'if (-not ($item -is [System.IO.FileInfo])) { throw "GUIDED_TRUST_PIN_NOT_REGULAR_FILE" }',
  ].join('\n');
  try {
    execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
      timeout: 5000,
      windowsHide: true,
      env: { SystemRoot: systemRoot, SHUN_GUIDED_PIN_PATH: path },
    });
  } catch {
    throw new Error('GUIDED_TRUST_PIN_REPARSE_PROBE_FAILED');
  }
}

function readPinnedSpkiSha256(pinPath: string): string {
  assertRegularFile(pinPath, 'GUIDED_TRUST_PIN_UNTRUSTED', MAX_PIN_BYTES);
  assertNoWindowsReparsePoint(pinPath);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(pinPath, 'utf8'));
  } catch {
    throw new Error('GUIDED_TRUST_PIN_MALFORMED');
  }
  if (
    raw === null ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    Object.keys(raw).sort().join('|') !== ['schema', 'spkiSha256'].join('|')
  ) {
    throw new Error('GUIDED_TRUST_PIN_MALFORMED');
  }
  const value = raw as { readonly schema?: unknown; readonly spkiSha256?: unknown };
  if (
    value.schema !== TRUST_PIN_SCHEMA ||
    typeof value.spkiSha256 !== 'string' ||
    !TRUST_PIN_DIGEST.test(value.spkiSha256)
  ) {
    throw new Error('GUIDED_TRUST_PIN_MALFORMED');
  }
  return value.spkiSha256;
}

interface ResolvedTrustPaths {
  readonly trustDir: string;
  readonly pinPath: string;
  readonly ownerSid: string;
  readonly ancestorChain?: readonly string[];
}

function resolveTrustPaths(overrides?: GuidedServiceTestOverrides): ResolvedTrustPaths {
  if (overrides !== undefined) {
    if (process.env.VITEST === undefined) {
      throw new Error('GUIDED_TRUST_TEST_OVERRIDES_DISABLED');
    }
    if (
      !isAbsolute(overrides.trustDir) ||
      !isAbsolute(overrides.pinPath) ||
      typeof overrides.inspectAcl !== 'function' ||
      typeof overrides.inspectAclAncestors !== 'function' ||
      typeof overrides.ownerSid !== 'string' ||
      !overrides.ownerSid
    ) {
      throw new Error('GUIDED_TRUST_TEST_OVERRIDES_INVALID');
    }
    const trustDir = resolve(overrides.trustDir);
    const pinPath = resolve(overrides.pinPath);
    const expectedPinPath = resolve(dirname(trustDir), TRUST_PIN_FILE);
    if (pinPath.toLowerCase() !== expectedPinPath.toLowerCase()) {
      throw new Error('GUIDED_TRUST_TEST_PIN_PATH_INVALID');
    }
    // Injected non-default test trust directories stay tree-only: the
    // per-user ancestor policy binds only the resolved default root.
    return { trustDir, pinPath, ownerSid: overrides.ownerSid };
  }
  const localAppDataBase = resolveWindowsLocalAppDataBase();
  const trustDir = perUserGuidedTrustDirectory(localAppDataBase);
  const ownerSid = queryWindowsProcessUserSid();
  if (!ownerSid) {
    throw new Error('GUIDED_TRUST_OWNER_SID_UNRESOLVED');
  }
  return {
    trustDir,
    pinPath: resolve(dirname(trustDir), TRUST_PIN_FILE),
    ownerSid,
    ancestorChain: perUserGuidedTrustAncestorChain(localAppDataBase),
  };
}

function createAclInspectors(
  pinPath: string,
  overrides?: GuidedServiceTestOverrides,
): {
  inspectAcl: GuidedAclInspector;
  inspectAclAncestors: GuidedAclAncestorInspector;
} {
  const inspectAcl: GuidedAclInspector = (trustDir, extraPaths) => {
    const requested = [...new Set([...extraPaths, pinPath])];
    const snapshot = overrides
      ? overrides.inspectAcl(trustDir, requested)
      : inspectWindowsGuidedTrustAcl(trustDir, requested);
    if (!snapshot) throw new Error('GUIDED_TRUST_ACL_PROBE_FAILED');
    if (!hasPath(snapshot, pinPath)) throw new Error('GUIDED_TRUST_ACL_PIN_ROW_MISSING');
    return snapshot;
  };
  const inspectAclAncestors: GuidedAclAncestorInspector = (paths) => {
    const snapshot = overrides
      ? overrides.inspectAclAncestors(paths)
      : inspectWindowsGuidedTrustAcl(paths[0] ?? '', paths.slice(1), { recursive: false });
    if (!snapshot) throw new Error('GUIDED_TRUST_ANCESTOR_ACL_PROBE_FAILED');
    for (const path of paths) {
      if (!hasPath(snapshot, path)) throw new Error('GUIDED_TRUST_ANCESTOR_ACL_ROW_MISSING');
    }
    return snapshot;
  };
  return { inspectAcl, inspectAclAncestors };
}

/**
 * Construct the durable Host service only after the external trust pin,
 * anchor, exact database receipt and per-user ACL/ancestor policy are
 * proven. The Host constructor deliberately records provenance
 * initialization failure as UNKNOWN; a side-effect-free invalid relay probe
 * distinguishes a healthy service (REFUSED/RELAY_SCHEMA_REFUSED) from an
 * unavailable ledger.
 *
 * Test overrides are internal fixture injection only. Production callers
 * pass one argument and therefore use only the resolved per-user trust root
 * of the current Windows session.
 */
export function createProductionGuidedService(
  databaseFile: string,
  overrides?: GuidedServiceTestOverrides,
): HostGuidedService {
  if (typeof databaseFile !== 'string' || !databaseFile || databaseFile === ':memory:') {
    throw new Error('GUIDED_DATABASE_FILE_REQUIRED');
  }
  const { trustDir, pinPath, ownerSid, ancestorChain } = resolveTrustPaths(overrides);
  // First-run detection: a trust pin that was never provisioned for this
  // Windows user is a truthful SETUP_REQUIRED refusal (with the one-time
  // bootstrap path), never a silent DEMO fallback and never a misread of
  // corrupted material as "absent".
  if (!existsSync(pinPath)) {
    refuseWithSetupRequiredRecord(pinPath, 'GUIDED_TRUST_SETUP_REQUIRED');
  }
  try {
    assertRegularFile(pinPath, 'GUIDED_TRUST_PIN_UNTRUSTED', MAX_PIN_BYTES);
  } catch {
    refuseWithSetupRequiredRecord(pinPath, 'GUIDED_TRUST_PIN_UNTRUSTED');
  }
  assertNoWindowsReparsePoint(pinPath);

  const receipts = listGuidedReceiptPaths(trustDir);
  const { inspectAcl, inspectAclAncestors } = createAclInspectors(pinPath, overrides);
  const aclSnapshot = inspectAcl(trustDir, receipts);
  const ancestorSnapshot =
    ancestorChain !== undefined ? inspectAclAncestors(ancestorChain) : undefined;
  const aclReasons = assessGuidedTrustProtection(
    trustDir,
    [...receipts, pinPath],
    ownerSid,
    aclSnapshot,
    ancestorSnapshot,
    ancestorChain,
  );
  if (aclReasons.length > 0) {
    throw new Error(`GUIDED_TRUST_ACL_UNPROTECTED:${aclReasons.join(' | ')}`);
  }

  const pinnedSpkiSha256 = readPinnedSpkiSha256(pinPath);
  const anchorPath = resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE);
  try {
    assertRegularFile(anchorPath, 'GUIDED_TRUST_ANCHOR_UNTRUSTED', MAX_TRUST_FILE_BYTES);
  } catch {
    refuseWithSetupRequiredRecord(anchorPath, 'GUIDED_TRUST_ANCHOR_UNTRUSTED');
  }
  const anchor = readGuidedTrustAnchor(trustDir);
  if (
    anchor.spkiSha256 !== pinnedSpkiSha256 ||
    guidedPublicKeySpkiSha256(anchor.publicKeyPem) !== pinnedSpkiSha256
  ) {
    throw new Error('GUIDED_TRUST_PUBLIC_KEY_PIN_MISMATCH');
  }

  const canonicalPath = canonicalGuidedDatabasePath(databaseFile);
  const receiptPath = resolve(
    trustDir,
    GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
    guidedReceiptFileName(canonicalPath),
  );
  try {
    assertRegularFile(
      receiptPath,
      'GUIDED_PROVENANCE_RECEIPT_MISSING_OR_UNTRUSTED',
      MAX_TRUST_FILE_BYTES,
    );
  } catch {
    refuseWithSetupRequiredRecord(receiptPath, 'GUIDED_PROVENANCE_RECEIPT_MISSING_OR_UNTRUSTED');
  }
  if (!receipts.some((path) => resolve(path).toLowerCase() === receiptPath.toLowerCase())) {
    throw new Error('GUIDED_PROVENANCE_RECEIPT_NOT_IN_TRUST_TREE');
  }

  const authority = createExternalGuidedProvenanceAuthority({
    trustDir,
    pinnedSpkiSha256,
    ownerSid,
    ancestorChain,
    inspectAcl,
    inspectAclAncestors,
  });
  let service: HostGuidedService | undefined;
  try {
    service = new HostGuidedServiceImpl(resolve(databaseFile), Date.now, authority);
    const probe = service.decide(null);
    const probeCode = 'code' in probe ? probe.code : undefined;
    if (probe.status !== 'REFUSED' || probeCode !== 'RELAY_SCHEMA_REFUSED') {
      throw new Error(`V03_GUIDED_PROVENANCE_UNAVAILABLE:${probeCode ?? probe.status}`);
    }
    return service;
  } catch (error) {
    try {
      service?.close();
    } catch {
      // Preserve the original fail-closed startup reason.
    }
    throw error;
  }
}
