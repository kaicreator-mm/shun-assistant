/**
 * R02-E production Guided trust composition.
 *
 * The only production trust pin is a public SPKI digest in the fixed sibling
 * file under the source-pinned ProgramData authority directory. The pin is
 * never accepted from environment, CLI, database or receipt input.
 */
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostGuidedService as HostGuidedServiceImpl } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  assertGuidedRegularCanonicalPath,
  assessGuidedTrustProtection,
  canonicalGuidedDatabasePath,
  createExternalGuidedProvenanceAuthority,
  defaultGuidedProvenanceTrustDirectory,
  defaultGuidedTrustAncestorChain,
  guidedPublicKeySpkiSha256,
  guidedReceiptFileName,
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  listGuidedReceiptPaths,
  readGuidedTrustAnchor,
  inspectWindowsGuidedTrustAcl,
  type GuidedAclAncestorInspector,
  type GuidedAclInspector,
  type GuidedTrustAclSnapshot,
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
  ].join('\\n');
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
  if (value.schema !== TRUST_PIN_SCHEMA || typeof value.spkiSha256 !== 'string' ||
      !TRUST_PIN_DIGEST.test(value.spkiSha256)) {
    throw new Error('GUIDED_TRUST_PIN_MALFORMED');
  }
  return value.spkiSha256;
}

function resolveTrustPaths(overrides?: GuidedServiceTestOverrides): {
  trustDir: string;
  pinPath: string;
} {
  if (overrides !== undefined) {
    if (process.env.VITEST === undefined) {
      throw new Error('GUIDED_TRUST_TEST_OVERRIDES_DISABLED');
    }
    if (!isAbsolute(overrides.trustDir) || !isAbsolute(overrides.pinPath) ||
        typeof overrides.inspectAcl !== 'function' ||
        typeof overrides.inspectAclAncestors !== 'function') {
      throw new Error('GUIDED_TRUST_TEST_OVERRIDES_INVALID');
    }
    const trustDir = resolve(overrides.trustDir);
    const pinPath = resolve(overrides.pinPath);
    const expectedPinPath = resolve(dirname(trustDir), TRUST_PIN_FILE);
    if (pinPath.toLowerCase() !== expectedPinPath.toLowerCase()) {
      throw new Error('GUIDED_TRUST_TEST_PIN_PATH_INVALID');
    }
    return { trustDir, pinPath };
  }
  const trustDir = defaultGuidedProvenanceTrustDirectory();
  return { trustDir, pinPath: resolve(dirname(trustDir), TRUST_PIN_FILE) };
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
 * anchor, exact database receipt and ACL/ancestor policy are proven. The
 * Host constructor deliberately records provenance initialization failure
 * as UNKNOWN; a side-effect-free invalid relay probe distinguishes a healthy
 * service (REFUSED/RELAY_SCHEMA_REFUSED) from an unavailable ledger.
 *
 * Test overrides are internal fixture injection only. Production callers
 * pass one argument and therefore use only the fixed ProgramData trust root.
 */
export function createProductionGuidedService(
  databaseFile: string,
  overrides?: GuidedServiceTestOverrides,
): HostGuidedService {
  if (typeof databaseFile !== 'string' || !databaseFile || databaseFile === ':memory:') {
    throw new Error('GUIDED_DATABASE_FILE_REQUIRED');
  }
  const { trustDir, pinPath } = resolveTrustPaths(overrides);
  assertRegularFile(pinPath, 'GUIDED_TRUST_PIN_UNTRUSTED', MAX_PIN_BYTES);
  assertNoWindowsReparsePoint(pinPath);

  const receipts = listGuidedReceiptPaths(trustDir);
  const { inspectAcl, inspectAclAncestors } = createAclInspectors(pinPath, overrides);
  const aclSnapshot = inspectAcl(trustDir, receipts);
  const ancestorSnapshot = inspectAclAncestors(defaultGuidedTrustAncestorChain());
  const aclReasons = assessGuidedTrustProtection(
    trustDir,
    [pinPath],
    aclSnapshot,
    ancestorSnapshot,
  );
  if (aclReasons.length > 0) {
    throw new Error(`GUIDED_TRUST_ACL_UNPROTECTED:${aclReasons.join(' | ')}`);
  }

  const pinnedSpkiSha256 = readPinnedSpkiSha256(pinPath);
  const anchorPath = resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE);
  assertRegularFile(anchorPath, 'GUIDED_TRUST_ANCHOR_UNTRUSTED', MAX_TRUST_FILE_BYTES);
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
  assertRegularFile(receiptPath, 'GUIDED_PROVENANCE_RECEIPT_MISSING_OR_UNTRUSTED', MAX_TRUST_FILE_BYTES);
  if (!receipts.some((path) => resolve(path).toLowerCase() === receiptPath.toLowerCase())) {
    throw new Error('GUIDED_PROVENANCE_RECEIPT_NOT_IN_TRUST_TREE');
  }

  const authority = createExternalGuidedProvenanceAuthority({
    trustDir,
    pinnedSpkiSha256,
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
