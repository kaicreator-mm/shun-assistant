// T04 P2-2 / N-R2-4 — interim fail-closed default for the open C06
// architecture: the privileged launcher REFUSES to even request UAC consent
// for side-effect-bearing ELEVATED actions while the authority anchors are
// same-user-writable (the default co-located deployment). Read-only (R0)
// observations are untouched; an anchor set the OS actually protects passes
// the gate.
//
// The probes are REAL access attempts (create/delete in directories,
// open-for-write on files). The negative controls below need no ACL work:
// any temp authority store IS same-user-writable — exactly the deployment
// shape the interim default refuses. The positive control simulates the
// protected posture with a real Windows deny ACE (unattended-safe); it
// proves the gate opens when the token genuinely cannot write, NOT OS
// enforcement against the owner — the owner could rewrite the DACL, which is
// precisely the residual the L2 v0.2 elevated-only anchor root closes.
//
// UAC discipline: the behavioral runs use a stub relay that writes
// UAC_DECLINED without ever calling Start-Process -Verb RunAs, so the suite
// never raises a secure-desktop prompt.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { assessAuthorityAnchors } from '../src/anchor-protection.ts';
import { PrivilegedWindowsExecutionBackend } from '../src/privileged-backend.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  ON_WINDOWS,
  type TestAuthority,
} from './helpers.ts';

/** Non-elevating stub relay: same argv shape, writes UAC_DECLINED, exits. */
const STUB_RELAY = `
param([string] $NodeExe, [string] $HelperBundle, [string] $HelperArgsJson, [string] $RelayFile)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
  $RelayFile,
  ((ConvertTo-Json @{ kind = 'UAC_DECLINED'; error = 'stub relay: no elevation in tests'; hresult = '0x800704C7' } -Compress) + [Environment]::NewLine),
  $utf8
)
exit 10
`;

function readLauncherDetail(runDir: string): { code?: string; reason?: string } {
  const detail = JSON.parse(readFileSync(join(runDir, 'receipt.json'), 'utf8')) as {
    launcherDetail?: { code?: string; reason?: string };
  };
  return detail.launcherDetail ?? {};
}

describe('anchor writability probe (unit)', () => {
  it('a writable authority store is forgeable, with reasons naming the anchors', () => {
    const dir = join(
      tmpdir(),
      `shun-anchor-probe-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(join(dir, 'grants'), { recursive: true });
    mkdirSync(join(dir, 'plans'), { recursive: true });
    writeFileSync(join(dir, 'current-authority.json'), '{}\n');
    writeFileSync(join(dir, 'helper-pin.json'), '{}\n');
    writeFileSync(join(dir, 'grant-hmac.key'), 'AAAA\n');
    try {
      const assessment = assessAuthorityAnchors(dir);
      expect(assessment.forgeable).toBe(true);
      expect(assessment.reasons.join('\n')).toContain('authority store root');
      expect(assessment.reasons.join('\n')).toContain('grant-hmac key');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('P2-2 — the privileged launcher refuses side effects under forgeable anchors', () => {
  let authority: TestAuthority;
  let backend: PrivilegedWindowsExecutionBackend;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-p22-');
    if (ON_WINDOWS) {
      const stubRelay = join(authority.root, 'stub-relay.ps1');
      writeFileSync(stubRelay, STUB_RELAY, 'utf8');
      authority.relayScript = stubRelay;
    }
    backend = new PrivilegedWindowsExecutionBackend({
      authorityDir: authority.authorityDir,
      workspaceRoot: authority.workspaceRoot,
      helperBundlePath: authority.helperBundle,
      relayScriptPath: authority.relayScript,
    });
  });
  afterAll(() => disposeTestAuthority(authority));

  function findRunDir(actionId: string): string {
    const executions = join(authority.workspaceRoot, 'executions');
    const runDirs = readdirSync(executions).filter((d) => d.startsWith(actionId));
    expect(runDirs.length).toBeGreaterThan(0);
    return join(executions, runDirs[0] as string);
  }

  it('ELEVATED mutating action + default co-located anchors → REFUSED ANCHOR_FORGEABLE_SAME_USER before any UAC work', async () => {
    const workspace = join(authority.workspaceRoot, 'p22-runs');
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'never.txt'), content: 'x' },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    const receipt = await backend.execute(built.action, built.grant);
    expect(receipt.terminal).toBe('REFUSED');
    const detail = readLauncherDetail(findRunDir(built.action.actionId));
    expect(detail.code).toBe('ANCHOR_FORGEABLE_SAME_USER');
    expect(detail.reason ?? '').toContain('same-user-writable');
    // The refusal precedes the relay and the envelope: the UAC flow never
    // started, so no elevation consent was ever requested.
    const runDir = findRunDir(built.action.actionId);
    expect(existsSync(join(runDir, 'relay.json'))).toBe(false);
    expect(existsSync(join(runDir, 'envelope.json'))).toBe(false);
  });

  it('ELEVATED read-only (R0) action is NOT gated by the anchor guard (observation unaffected)', async () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.read',
      parameters: { path: join(authority.workspaceRoot, 'anything.txt') },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R0',
      filesystemScope: { read: [authority.workspaceRoot], write: [] },
    });
    const receipt = await backend.execute(built.action, built.grant);
    const detail = readLauncherDetail(findRunDir(built.action.actionId));
    expect(detail.code).not.toBe('ANCHOR_FORGEABLE_SAME_USER');
    // The run proceeds past the anchor gate to the (stubbed) elevation
    // boundary — the R0 observation is never refused for anchor writability.
    expect(['UAC_DECLINED', 'REFUSED', 'UNCERTAIN']).toContain(receipt.terminal);
  });
});

describe.skipIf(!ON_WINDOWS)(
  'P2-2 — an anchor set the token cannot write passes the gate (real deny-ACE simulation)',
  () => {
    it('protected anchors are NOT forgeable — externalized-protected deployments stay usable', () => {
      const machinePs = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
      const dir = join(tmpdir(), `shun-p22-protected-${Date.now()}`);
      mkdirSync(join(dir, 'grants'), { recursive: true });
      mkdirSync(join(dir, 'plans'), { recursive: true });
      writeFileSync(join(dir, 'current-authority.json'), '{}\n');
      writeFileSync(join(dir, 'helper-pin.json'), '{}\n');
      writeFileSync(join(dir, 'grant-hmac.key'), 'AAAA\n');
      // Machine-anchored whoami (P3a lesson): PATH resolution under Git Bash
      // would hit coreutils whoami, which takes no /user flag.
      const hostWhoami = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe');
      // CSV: "DOMAIN\user","S-1-...","Type","Attribute" — the SID is field 2.
      const sid = execFileSync(hostWhoami, ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' })
        .split(',')[1]
        ?.trim()
        .replace(/"/g, '');
      expect(sid ?? '').toMatch(/^S-1-/);
      try {
        // Deny write (create + file write) for this token on the whole store.
        execFileSync(join(machinePs, 'icacls.exe'), [dir, '/deny', `*${sid}:(OI)(CI)W`], {
          windowsHide: true,
        });
        const assessment = assessAuthorityAnchors(dir);
        expect(assessment.forgeable).toBe(false);
      } finally {
        try {
          execFileSync(join(machinePs, 'icacls.exe'), [dir, '/remove:d', `*${sid}`], {
            windowsHide: true,
          });
        } catch {
          // Best-effort cleanup; the temp dir is removed below regardless.
        }
        rmSync(dir, { recursive: true, force: true });
      }
    });
  },
);
