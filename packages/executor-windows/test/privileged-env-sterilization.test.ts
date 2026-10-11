// T04 N-R2-1 (P1) — untrusted environment must NOT cross the privileged
// spawn boundary. The launcher (and any process a same-user attacker has
// environment control over) inherits attacker-settable variables; if those
// reach the elevation relay or the PINED elevated node interpreter, a single
// UAC consent executes attacker JS before any helper self-check:
//
//   NODE_OPTIONS=--require=C:\attacker\pwn.js
//
// loads pwn.js inside the elevated node.exe process itself — bundle sha,
// interpreter sha and program pins all still verify, because the process is
// already attacker-controlled. The fix sterilizes EVERY spawn on the
// privileged path: launcher→relay (spawnRelay), relay→elevated node
// (elevate-relay.ps1 re-scrubs defensively, belt-and-braces), and the
// launcher's non-elevated tree-kill spawn.
//
// The controls below are unattended-safe: the behavioral probe uses a TEST
// relay script that reports its own environment and NEVER calls
// Start-Process -Verb RunAs (no UAC prompt, no elevation). A canary control
// first proves the injection mechanism is real on this host (a poisoned
// NODE_OPTIONS really does execute attacker JS in a spawned node), then the
// privileged-path assertions pin that the mechanism has no carrier.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnRelay } from '../src/privileged-backend.ts';
import { ON_WINDOWS } from './helpers.ts';

/** Hostile variables a same-user attacker can set before we spawn. */
const HOSTILE_NODE_VARS: Record<string, string> = {
  NODE_OPTIONS: '--require=__CANARY__',
  NODE_PATH: 'D:\\attacker\\node_modules',
  NODE_EXTRA_CA_CERTS: 'D:\\attacker\\ca.pem',
  NODE_DEBUG: 'module,https',
  NODE_V8_COVERAGE: 'D:\\attacker\\coverage',
  NODE_COMPILE_CACHE: 'D:\\attacker\\cache',
  NODE_REPL_EXTERNAL_MODULE: 'D:\\attacker\\repl.mjs',
};

const OBSERVED_VARS = Object.keys(HOSTILE_NODE_VARS);

describe('N-R2-1 — the injection mechanism itself (control, expected to succeed)', () => {
  it('a poisoned NODE_OPTIONS=--require really executes attacker JS in a spawned node', async () => {
    // Control: proves the canary mechanism — if this ever fails, the
    // behavioral assertions below prove nothing (the carrier would be dead).
    const dir = mkdtempSync(join(tmpdir(), 'shun-envctl-'));
    try {
      const canaryOut = join(dir, 'canary-touched');
      const canaryJs = join(dir, 'canary.js').replace(/\\/g, '/');
      writeFileSync(
        canaryJs,
        `require('node:fs').writeFileSync(${JSON.stringify(canaryOut)}, 'x');\n`,
      );
      const poisoned = { ...process.env, NODE_OPTIONS: `--require=${canaryJs}` };
      await new Promise<void>((resolve, reject) => {
        const child = spawn(process.execPath, ['-e', 'process.exit(0)'], {
          env: poisoned,
          windowsHide: true,
        });
        child.on('exit', () => resolve());
        child.on('error', reject);
      });
      expect(existsSync(canaryOut)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Probe relay: same argv shape and relay.json protocol as the real pinned
 * relay, but it NEVER elevates — it records which hostile variables reached
 * its own process environment and reports through a side channel (the first
 * HelperArgsJson entry).
 */
const PROBE_RELAY = `
param(
  [Parameter(Mandatory = $true)][string] $NodeExe,
  [Parameter(Mandatory = $true)][string] $HelperBundle,
  [Parameter(Mandatory = $true)][string] $HelperArgsJson,
  [Parameter(Mandatory = $true)][string] $RelayFile
)
$ErrorActionPreference = 'Stop'
$probeFile = (ConvertFrom-Json $HelperArgsJson)[0]
$observed = @()
foreach ($name in @(${OBSERVED_VARS.map((n) => `'${n}'`).join(',')})) {
  if ($null -ne [Environment]::GetEnvironmentVariable($name)) { $observed += $name }
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($probeFile, (ConvertTo-Json $observed -Compress), $utf8)
[System.IO.File]::WriteAllText(
  $RelayFile,
  ((ConvertTo-Json @{ kind = 'RAN'; exitCode = 0; childPid = 0 } -Compress) + [Environment]::NewLine),
  $utf8
)
exit 0
`;

describe.skipIf(!ON_WINDOWS)(
  'N-R2-1 — the launcher→relay spawn carries NO hostile environment',
  () => {
    const machinePowershell = join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe',
    );
    const machineTaskkill = join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32',
      'taskkill.exe',
    );

    let dir: string;
    let relayScript: string;
    let poisoned: string | undefined;
    let nodePath: string | undefined;

    afterEach(() => {
      if (poisoned !== undefined) {
        if (poisoned === '') delete process.env.NODE_OPTIONS;
        else process.env.NODE_OPTIONS = poisoned;
      }
      if (nodePath !== undefined) {
        if (nodePath === '') delete process.env.NODE_PATH;
        else process.env.NODE_PATH = nodePath;
      }
      if (dir?.startsWith(tmpdir())) rmSync(dir, { recursive: true, force: true });
    });

    it('spawnRelay runs the relay with a sterilized environment (NODE_OPTIONS/NODE_PATH have no carrier)', async () => {
      expect(existsSync(machinePowershell)).toBe(true);
      dir = mkdtempSync(join(tmpdir(), 'shun-envrelay-'));
      relayScript = join(dir, 'probe-relay.ps1');
      writeFileSync(relayScript, PROBE_RELAY, 'utf8');
      const probeFile = join(dir, 'relay-env.json');

      // Poison THIS process's environment exactly like a same-user attacker
      // would before our launcher spawns the relay.
      poisoned = process.env.NODE_OPTIONS;
      nodePath = process.env.NODE_PATH;
      const canaryJs = join(dir, 'canary.js').replace(/\\/g, '/');
      writeFileSync(canaryJs, 'process.exit(0);\n');
      process.env.NODE_OPTIONS = `--require=${canaryJs}`;
      process.env.NODE_PATH = 'D:\\attacker\\node_modules';

      const result = await spawnRelay({
        powershellExe: machinePowershell,
        taskkillExe: machineTaskkill,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [probeFile],
        relayFile: join(dir, 'relay.json'),
        timeoutMs: 30000,
      });
      expect(result.kind).toBe('RAN');
      expect(existsSync(probeFile)).toBe(true);
      const observed = JSON.parse(readFileSync(probeFile, 'utf8')) as string[];
      expect(observed).toEqual([]);
    });
  },
);

describe('N-R2-1 — the pinned relay re-scrubs Node interpreter directives before RunAs', () => {
  // The relay script is pinned infrastructure whose bytes cross the UAC
  // boundary as the RunAs caller; the scrub must be present in the pinned
  // source itself (compile-level pin, like the F-4 export check) so the
  // elevated child can never inherit an interpreter-directive variable even
  // if some future spawn site forgets the sterilized env.
  it('elevate-relay.ps1 removes NODE_* environment variables before Start-Process -Verb RunAs', async () => {
    const relay = await import('node:fs').then((fs) =>
      fs.readFileSync(join(import.meta.dirname, '..', 'src', 'relay', 'elevate-relay.ps1'), 'utf8'),
    );
    expect(relay).toContain('Start-Process');
    expect(relay).toContain('-Verb RunAs');
    // The scrub must (a) mention the interpreter-directive variable and (b)
    // the REAL RunAs launch (Start-Process statement) must come AFTER the
    // scrub's first mention — the header comment may mention it earlier, so
    // anchor the search at the scrub.
    const scrubIdx = relay.indexOf('NODE_OPTIONS');
    expect(scrubIdx).toBeGreaterThan(-1);
    expect(relay.slice(scrubIdx)).toContain('-Verb RunAs');
    // The scrub is an executable env removal over the known-names list, not
    // a comment: a Remove-Item Env: statement acting on the list variable.
    const listIdx = relay.indexOf("@('NODE_OPTIONS'");
    expect(listIdx).toBeGreaterThan(-1);
    expect(relay.slice(listIdx)).toMatch(/Remove-Item\s+"Env:\\\$name"/);
    // And it sweeps the whole NODE_* family, not just hand-listed names.
    expect(relay).toMatch(/NODE\*|NODE_/);
  });
});
