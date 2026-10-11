// Interim fail-closed default for the C06 open architecture (N-R2-4, P2).
//
// The architecture terminal (SHUN_T04_C06_PROTECTED_TRUST_PRINCIPAL_
// ARCHITECTURE_R0, adjudicated by the Controller) requires that privileged
// side effects are REFUSED while the authorization anchors live on paths the
// same-user attacker can write — the default co-located deployment — instead
// of executing elevated effects under an anchor the attacker could have
// forged. Deployments that externalize the HMAC key to a genuinely protected
// path (and keep the store records out of same-user reach) keep working.
//
// Detection is a REAL access probe, not ACL theater: the guard attempts the
// actual same-user write (create/delete inside directories, open-for-write
// on files) and trusts only what the OS currently enforces for this token.
// Every probe error fails CLOSED (treated as forgeable). The writability
// trigger is exactly the adjudicated interim default; the readable-key
// re-sign attack remains the known-open C06 defect (the it.fails record)
// because under frozen HMAC any verifying principal is also a signing
// principal — that closure belongs to the L2 v0.2 privileged writer, not to
// this interim gate.
//
// Enforcement point (honest boundary): the launcher — the process that owns
// the UAC decision. A refusal here means no UAC consent is ever requested,
// so no elevated effect can occur. The elevated helper cannot mirror this
// check faithfully: its probes would run with the ADMIN token (over-reporting
// access) and a filtered-token view would need linked-token machinery that
// does not exist in this package; helper-side refusal semantics stay with the
// writer architecture.
import { execFileSync } from 'node:child_process';
import { closeSync, mkdirSync, openSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { privilegedSpawnEnv } from './safe-env.ts';
import { systemPowershellExe } from './system-exe.ts';
import { resolveGrantHmacKeyFile } from './trusted-store.ts';

export interface AnchorAssessment {
  /** true = the runtime user can rewrite anchors OR read the HMAC signing key. */
  forgeable: boolean;
  /** HMAC verifier/signing symmetry: readable key means caller can mint presentations. */
  keyReadable: boolean;
  reasons: string[];
}

/** Record files whose content the attacker could rewrite to forge the chain. */
const ANCHOR_RECORD_FILES = [
  'current-authority.json',
  'helper-pin.json',
  'system-tools.json',
  'writer-pin.json',
] as const;

/** Record directories the attacker could add/replace records in. */
const ANCHOR_RECORD_DIRS = ['grants', 'programs', 'jobs'] as const;

function fileReadable(path: string): boolean | undefined {
  try {
    const fd = openSync(path, 'r');
    closeSync(fd);
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') return false;
    return undefined;
  }
}

function fileWritable(path: string): boolean | undefined {
  // undefined = probe failed ⇒ callers must fail closed.
  try {
    const fd = openSync(path, 'r+');
    closeSync(fd);
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return false;
    if (code === 'EACCES' || code === 'EPERM') return false;
    return undefined;
  }
}

const PRIVILEGED_OWNER_SIDS = new Set(['S-1-5-18', 'S-1-5-32-544']);

interface OwnerRecord {
  path: string;
  owner?: string;
}

function anchorOwnerSnapshot(authorityDir: string, hmacKeyFile: string): OwnerRecord[] | undefined {
  if (process.platform !== 'win32') return undefined;
  const powershell = systemPowershellExe(authorityDir);
  if (!powershell) return undefined;
  // Fixed script, data only through a scrubbed environment. Scan the complete
  // anchor tree so dynamically-created grant/job/program-pin files cannot
  // hide a same-user owner beneath an admin-owned parent directory.
  const script = [
    '$root = $env:SHUN_OWNER_PROBE_ROOT',
    '$key = $env:SHUN_OWNER_PROBE_KEY',
    '$paths = New-Object System.Collections.Generic.List[string]',
    '$paths.Add($root)',
    'Get-ChildItem -LiteralPath $root -Force -Recurse | ForEach-Object { $paths.Add($_.FullName) }',
    'if ($key -and -not $paths.Contains($key)) { $paths.Add($key) }',
    '$rows = foreach ($p in $paths) {',
    '  try {',
    '    $acl = Get-Acl -LiteralPath $p',
    '    $owner = New-Object System.Security.Principal.NTAccount($acl.Owner)',
    '    [pscustomobject]@{ path = $p; owner = $owner.Translate([System.Security.Principal.SecurityIdentifier]).Value }',
    '  } catch { [pscustomobject]@{ path = $p; owner = $null } }',
    '}',
    '$rows | ConvertTo-Json -Compress',
  ].join('; ');
  const env = privilegedSpawnEnv();
  env.SHUN_OWNER_PROBE_ROOT = authorityDir;
  env.SHUN_OWNER_PROBE_KEY = hmacKeyFile;
  try {
    const out = execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 30_000,
      env,
      maxBuffer: 4 * 1024 * 1024,
    }).trim();
    const decoded = JSON.parse(out) as OwnerRecord | OwnerRecord[];
    const rows = Array.isArray(decoded) ? decoded : [decoded];
    return rows.length > 0 ? rows : undefined;
  } catch {
    return undefined;
  }
}

export function assessAnchorOwnership(
  authorityDir: string,
  hmacKeyFile: string = resolveGrantHmacKeyFile(authorityDir),
  requireKeyOwner = true,
): string[] {
  if (process.platform !== 'win32') {
    return ['authorization anchor ownership is only verifiable on Windows'];
  }
  const rows = anchorOwnerSnapshot(authorityDir, hmacKeyFile);
  if (!rows) return ['authorization anchor owner scan failed (fail closed)'];
  const reasons: string[] = [];
  const key = hmacKeyFile.toLowerCase();
  const root = authorityDir.toLowerCase();
  if (!rows.some((row) => row.path.toLowerCase() === root)) {
    reasons.push('authority store root absent from owner scan');
  }
  if (requireKeyOwner && !rows.some((row) => row.path.toLowerCase() === key)) {
    reasons.push('grant-hmac key absent from owner scan');
  }
  for (const row of rows) {
    // The filtered runtime token is intentionally denied READ_CONTROL on the
    // secret key. It proves key confidentiality with a direct read probe and
    // leaves key-owner verification to the elevated helper/writer. All other
    // anchor objects must expose their owner to the runtime read-only token.
    if (!requireKeyOwner && row.path.toLowerCase() === key) continue;
    if (!row.owner || !PRIVILEGED_OWNER_SIDS.has(row.owner)) {
      reasons.push(
        `anchor object owner is not Administrators/SYSTEM: ${row.path} (${row.owner ?? 'unresolvable'})`,
      );
    }
  }
  return reasons;
}

function dirWritable(path: string): boolean | undefined {
  const probe = join(
    path,
    `.shun-anchor-probe-${process.pid}-${Math.random().toString(36).slice(2)}`,
  );
  try {
    mkdirSync(path, { recursive: false });
    // Freshly creatable directory — attacker-equivalent create access.
    try {
      rmSync(path);
    } catch {
      // Creation is the forgeability signal; leave cleanup to the caller.
    }
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') return false;
    if (code !== 'EEXIST') return undefined;
  }
  try {
    writeFileSync(probe, '', { flag: 'wx' });
    try {
      unlinkSync(probe);
    } catch {
      // Created but not deletable — write access was still demonstrated.
    }
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') return false;
    return undefined;
  }
}

/**
 * Assess whether the authority store's trust chain is forgeable by a
 * same-user attacker. `hmacKeyFile` is the RESOLVED key path (the caller
 * resolves the co-located default and any externalized override it trusts —
 * resolveGrantHmacKeyFile); when omitted the co-located default is probed.
 */
export function assessAuthorityAnchors(
  authorityDir: string,
  hmacKeyFile: string = resolveGrantHmacKeyFile(authorityDir),
): AnchorAssessment {
  const reasons: string[] = [];
  const note = (what: string, writable: boolean | undefined): void => {
    if (writable !== false) {
      reasons.push(
        writable === true
          ? `${what} is same-user-writable`
          : `${what} writability probe failed (fail closed)`,
      );
    }
  };

  // The store root itself: whoever can create files here can replace every
  // record regardless of the individual files' state.
  note(`authority store root ${authorityDir}`, dirWritable(authorityDir));
  for (const dir of ANCHOR_RECORD_DIRS) {
    note(`${dir}/ record directory`, dirWritable(join(authorityDir, dir)));
  }
  for (const file of ANCHOR_RECORD_FILES) {
    note(file, fileWritable(join(authorityDir, file)));
  }
  note('grant-hmac key', fileWritable(hmacKeyFile));
  const keyReadable = fileReadable(hmacKeyFile);
  if (keyReadable !== false) {
    reasons.push(
      keyReadable === true
        ? 'grant-hmac key is same-user-readable (HMAC verification key is also signing authority)'
        : 'grant-hmac key readability probe failed (fail closed)',
    );
  }

  // A deny-to-self ACL is not protection when the same runtime user still
  // OWNS the object and can rewrite its DACL. Once the direct access probes
  // look protected, require privileged ownership as a second independent
  // fact. The query runs through the already pinned real system PowerShell.
  if (reasons.length === 0 && process.platform === 'win32') {
    reasons.push(...assessAnchorOwnership(authorityDir, hmacKeyFile, false));
  }

  return { forgeable: reasons.length > 0, keyReadable: keyReadable !== false, reasons };
}
