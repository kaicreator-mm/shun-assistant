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
//
// The launcher→relay describe additionally pins the spawn LIFECYCLE
// deterministically (Issue #345): controlled startup delay before relay
// readiness, timeout tree-kill with bounded launcher-side cleanup of BOTH
// the relay tree AND the taskkill helper itself (P1-01: explicit helper
// disposition, direct-kill fallback when the helper fails, and orphan
// proof for both pids), spawn error and NO_RELAY classification, and an
// orphan-free process tree after both the RAN and TIMED_OUT outcomes.
import { spawn, spawnSync } from 'node:child_process';
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
 * HelperArgsJson entry). `preDelayMs` injects a controlled startup delay
 * before the relay becomes ready (deterministic readiness/timeout coverage).
 */
const probeRelayScript = (preDelayMs = 0): string => `
param(
  [Parameter(Mandatory = $true)][string] $NodeExe,
  [Parameter(Mandatory = $true)][string] $HelperBundle,
  [Parameter(Mandatory = $true)][string] $HelperArgsJson,
  [Parameter(Mandatory = $true)][string] $RelayFile
)
$ErrorActionPreference = 'Stop'
$probeFile = (ConvertFrom-Json $HelperArgsJson)[0]
${preDelayMs > 0 ? `Start-Sleep -Milliseconds ${preDelayMs}\n` : ''}$observed = @()
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

/** Relay that settles the spawn lifecycle without ever writing the relay file. */
const SILENT_EXIT_RELAY = `
param(
  [Parameter(Mandatory = $true)][string] $NodeExe,
  [Parameter(Mandatory = $true)][string] $HelperBundle,
  [Parameter(Mandatory = $true)][string] $HelperArgsJson,
  [Parameter(Mandatory = $true)][string] $RelayFile
)
$ErrorActionPreference = 'Stop'
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
    const machineTasklist = join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32',
      'tasklist.exe',
    );
    // Negative-path taskkill stubs (native Windows, always present):
    // - robocopy.exe exits nonzero (~16) fast for the argv shape, proving
    //   the launcher falls back to the direct relay-root kill when the
    //   helper reports failure without killing anything.
    // - cmd.exe IGNORES the /PID /T /F switches and drops into its
    //   interactive REPL reading the never-fed stdin pipe, proving the
    //   helper's OWN lifecycle is bounded and the stuck helper is reaped.
    const machineRobocopy = join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32',
      'robocopy.exe',
    );
    const machineCmd = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'cmd.exe');

    /**
     * Issue #345 evidence: on the GitHub windows-2025 executor the
     * sterilized-environment relay start is deterministically SLOW — the
     * PowerShell engine initializes for 29-51s across six healthy runs
     * (empty stdio, no script output; ~0.4s on a dev workstation) before
     * the probe script runs, and two runs crossed the former 60,000 ms
     * bound at ~60.3s. This budget (~3.5x the observed maximum) keeps the
     * assertion measuring ENVIRONMENT STERILIZATION instead of runner
     * startup latency; the timeout semantics themselves are pinned
     * deterministically by the dedicated lifecycle tests below, and a
     * future breach now carries structured lifecycle evidence
     * (spawned/outputBytes/taskkillExit/killConfirmed) instead of silence.
     */
    const RELAY_STARTUP_BUDGET_MS = 180000;

    let poisoned: string | undefined;
    let nodePath: string | undefined;
    let dirs: string[] = [];

    afterEach(() => {
      if (poisoned !== undefined) {
        if (poisoned === '') delete process.env.NODE_OPTIONS;
        else process.env.NODE_OPTIONS = poisoned;
        poisoned = undefined;
      }
      if (nodePath !== undefined) {
        if (nodePath === '') delete process.env.NODE_PATH;
        else process.env.NODE_PATH = nodePath;
        nodePath = undefined;
      }
      for (const dir of dirs) {
        if (dir.startsWith(tmpdir())) rmSync(dir, { recursive: true, force: true });
      }
      dirs = [];
    });

    const makeProbeDir = (script: string): { dir: string; relayScript: string } => {
      const dir = mkdtempSync(join(tmpdir(), 'shun-envrelay-'));
      dirs.push(dir);
      const relayScript = join(dir, 'probe-relay.ps1');
      writeFileSync(relayScript, script, 'utf8');
      return { dir, relayScript };
    };

    /**
     * Locale-independent orphan proof: poll the MACHINE tasklist until the
     * pid disappears. A live process always shows a CSV row quoting the
     * pid; "no tasks" banners differ per locale and never quote the pid.
     */
    const processGone = async (
      pid: number,
      deadlineMs = 15000,
      tasklistExe = machineTasklist,
    ): Promise<boolean> => {
      if (!Number.isSafeInteger(pid) || pid <= 0) {
        throw new Error(`processGone requires a positive PID; received ${pid}`);
      }
      const deadline = Date.now() + deadlineMs;
      for (;;) {
        // spawnSync keeps this tiny system probe bounded and avoids creating
        // another asynchronous child whose own cleanup would need proving.
        // Fail closed: a missing tasklist, timeout, spawn error, or nonzero
        // exit must never be interpreted as proof that the target is gone.
        const probe = spawnSync(
          tasklistExe,
          ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'],
          {
            encoding: 'utf8',
            timeout: 5000,
            windowsHide: true,
          },
        );
        if (probe.error) {
          throw new Error(
            `tasklist probe failed for PID ${pid}: ${probe.error.message}; stderr=${probe.stderr ?? ''}`,
          );
        }
        if (probe.status !== 0) {
          throw new Error(
            `tasklist probe exited ${probe.status} for PID ${pid}; stderr=${probe.stderr ?? ''}`,
          );
        }
        const listing = probe.stdout ?? '';
        if (!listing.includes(`"${pid}"`)) return true;
        if (Date.now() >= deadline) return false;
        await new Promise((resolveTimer) => setTimeout(resolveTimer, 250));
      }
    };

    it('processGone fails closed when the tasklist probe cannot be started', async () => {
      await expect(
        processGone(1, 1000, join(tmpdir(), 'no-such-tasklist.exe')),
      ).rejects.toThrow(/tasklist probe failed/);
      await expect(processGone(-1)).rejects.toThrow(/positive PID/);
    });

    it('spawnRelay runs the relay with a sterilized environment (NODE_OPTIONS/NODE_PATH have no carrier)', {
      timeout: RELAY_STARTUP_BUDGET_MS + 60000,
    }, async () => {
      expect(existsSync(machinePowershell)).toBe(true);
      const { dir, relayScript } = makeProbeDir(probeRelayScript(2500));
      const probeFile = join(dir, 'relay-env.json');

      // Poison THIS process's environment exactly like a same-user attacker
      // would before our launcher spawns the relay.
      poisoned = process.env.NODE_OPTIONS;
      nodePath = process.env.NODE_PATH;
      const canaryJs = join(dir, 'canary.js').replace(/\\/g, '/');
      writeFileSync(canaryJs, 'process.exit(0);\n');
      process.env.NODE_OPTIONS = `--require=${canaryJs}`;
      process.env.NODE_PATH = 'D:\\attacker\\node_modules';

      let relayPid = -1;
      const result = await spawnRelay({
        powershellExe: machinePowershell,
        taskkillExe: machineTaskkill,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [probeFile],
        relayFile: join(dir, 'relay.json'),
        timeoutMs: RELAY_STARTUP_BUDGET_MS,
        onRelayPid: (pid) => {
          relayPid = pid;
        },
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({ kind: 'RAN' });
      expect(existsSync(probeFile)).toBe(true);
      const observed = JSON.parse(readFileSync(probeFile, 'utf8')) as string[];
      expect(observed).toEqual([]);
      // The 2,500 ms controlled startup delay really delayed readiness.
      expect(result.elapsedMs).toBeGreaterThanOrEqual(2000);
      // Orphan proof: the relay tree is gone once the result is RAN.
      expect(await processGone(relayPid)).toBe(true);
    });

    it('spawnRelay bounds a hung relay: timeout kill, bounded cleanup, no orphan process tree', {
      timeout: 90000,
    }, async () => {
      const { dir, relayScript } = makeProbeDir(probeRelayScript(30000));
      const probeFile = join(dir, 'relay-env.json');
      const relayFile = join(dir, 'relay.json');

      let relayPid = -1;
      let helperPid = -1;
      const result = await spawnRelay({
        powershellExe: machinePowershell,
        taskkillExe: machineTaskkill,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [probeFile],
        relayFile,
        timeoutMs: 3000,
        onRelayPid: (pid) => {
          relayPid = pid;
        },
        onTaskkillPid: (pid) => {
          helperPid = pid;
        },
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({
        kind: 'TIMED_OUT',
        timedOut: true,
        // Bounded cleanup: the launcher settled its promise and proved the
        // tree died — it never hangs behind an unresolvable pending spawn.
        killConfirmed: true,
        // P1-01: the taskkill helper itself has an explicit, bounded
        // disposition — it exited zero and its lifecycle is closed.
        killDisposition: 'EXITED_ZERO',
        killHelperConfirmed: true,
      });
      expect(existsSync(relayFile)).toBe(false);
      expect(existsSync(probeFile)).toBe(false);
      expect(result.taskkillPid).toBe(helperPid);
      expect(result.taskkillPid).toBeGreaterThan(0);
      // The real taskkill worked: no direct-kill fallback was needed.
      expect(result.fallbackKillUsed).toBe(false);
      // Orphan proof: the tree-kill reached the relay AND the taskkill
      // helper itself is gone; nothing lingers (P1-01).
      expect(await processGone(relayPid)).toBe(true);
      expect(await processGone(helperPid)).toBe(true);
    });

    it('spawnRelay bounds a taskkill spawn failure: SPAWN_ERROR disposition, direct fallback, no orphan', {
      timeout: 60000,
    }, async () => {
      const { dir, relayScript } = makeProbeDir(probeRelayScript(30000));
      const relayFile = join(dir, 'relay.json');

      let relayPid = -1;
      let helperPid = -2;
      const result = await spawnRelay({
        powershellExe: machinePowershell,
        taskkillExe: join(dir, 'no-such-taskkill.exe'),
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [join(dir, 'relay-env.json')],
        relayFile,
        timeoutMs: 3000,
        onRelayPid: (pid) => {
          relayPid = pid;
        },
        onTaskkillPid: (pid) => {
          helperPid = pid;
        },
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({
        kind: 'TIMED_OUT',
        timedOut: true,
        // The helper never came into existence; the launcher's direct
        // relay-root kill fallback proved the tree gone anyway.
        killConfirmed: true,
        killDisposition: 'SPAWN_ERROR',
        taskkillPid: -1,
        fallbackKillUsed: true,
        killHelperConfirmed: true,
      });
      expect(existsSync(relayFile)).toBe(false);
      expect(helperPid).toBe(-1);
      // Orphan proof: the fallback reached the relay; no helper exists.
      expect(await processGone(relayPid)).toBe(true);
    });

    it('spawnRelay bounds a failing taskkill (nonzero exit): direct fallback, relay and helper both gone', {
      timeout: 60000,
    }, async () => {
      expect(existsSync(machineRobocopy)).toBe(true);
      const { dir, relayScript } = makeProbeDir(probeRelayScript(30000));
      const relayFile = join(dir, 'relay.json');

      let relayPid = -1;
      let helperPid = -1;
      const result = await spawnRelay({
        powershellExe: machinePowershell,
        // robocopy exits nonzero for the /PID /T /F argv without killing
        // anything — the helper "ran but failed" path.
        taskkillExe: machineRobocopy,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [join(dir, 'relay-env.json')],
        relayFile,
        timeoutMs: 3000,
        onRelayPid: (pid) => {
          relayPid = pid;
        },
        onTaskkillPid: (pid) => {
          helperPid = pid;
        },
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({
        kind: 'TIMED_OUT',
        timedOut: true,
        // The nonzero helper could not be trusted: the direct fallback
        // killed the relay root and the exit was observed.
        killConfirmed: true,
        killDisposition: 'EXITED_NONZERO',
        fallbackKillUsed: true,
        killHelperConfirmed: true,
      });
      expect(result.killExitCode).toBeGreaterThan(0);
      expect(existsSync(relayFile)).toBe(false);
      // Orphan proof: helper pid (robocopy) AND relay pid are both gone.
      expect(await processGone(relayPid)).toBe(true);
      expect(await processGone(helperPid)).toBe(true);
    });

    it('spawnRelay reaps a hung taskkill helper: bounded helper lifecycle, direct fallback, no orphan of either', {
      timeout: 120000,
    }, async () => {
      expect(existsSync(machineCmd)).toBe(true);
      const { dir, relayScript } = makeProbeDir(probeRelayScript(30000));
      const relayFile = join(dir, 'relay.json');

      let relayPid = -1;
      let helperPid = -1;
      const result = await spawnRelay({
        powershellExe: machinePowershell,
        // cmd.exe ignores /PID /T /F and blocks forever on its never-fed
        // stdin pipe — the "helper outlived its own bound" path.
        taskkillExe: machineCmd,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [join(dir, 'relay-env.json')],
        relayFile,
        timeoutMs: 3000,
        onRelayPid: (pid) => {
          relayPid = pid;
        },
        onTaskkillPid: (pid) => {
          helperPid = pid;
        },
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({
        kind: 'TIMED_OUT',
        timedOut: true,
        // The stuck helper hit its own grace bound and was reaped; the
        // direct fallback killed the relay root and both exits were
        // observed — no disposition was left implicit.
        killConfirmed: true,
        killDisposition: 'TIMED_OUT',
        fallbackKillUsed: true,
        killHelperConfirmed: true,
      });
      expect(existsSync(relayFile)).toBe(false);
      expect(result.taskkillPid).toBe(helperPid);
      expect(result.taskkillPid).toBeGreaterThan(0);
      // Orphan proof: BOTH the hung helper (cmd) and the relay are gone —
      // the launcher reaps what it spawns (P1-01).
      expect(await processGone(relayPid)).toBe(true);
      expect(await processGone(helperPid)).toBe(true);
    });

    it('spawnRelay reports a structured SPAWN_ERROR when the relay host cannot be launched', {
      timeout: 30000,
    }, async () => {
      const { dir, relayScript } = makeProbeDir(probeRelayScript());
      const result = await spawnRelay({
        powershellExe: join(dir, 'no-such-powershell.exe'),
        taskkillExe: machineTaskkill,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [join(dir, 'relay-env.json')],
        relayFile: join(dir, 'relay.json'),
        timeoutMs: 10000,
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({
        kind: 'SPAWN_ERROR',
      });
    });

    it('spawnRelay classifies a relay that exits without writing the relay file as NO_RELAY', {
      timeout: RELAY_STARTUP_BUDGET_MS + 60000,
    }, async () => {
      const { dir, relayScript } = makeProbeDir(SILENT_EXIT_RELAY);
      const result = await spawnRelay({
        powershellExe: machinePowershell,
        taskkillExe: machineTaskkill,
        nodeExe: process.execPath,
        relayScript,
        helperBundle: join(dir, 'unused-bundle.mjs'),
        helperArgs: [join(dir, 'relay-env.json')],
        relayFile: join(dir, 'relay.json'),
        timeoutMs: RELAY_STARTUP_BUDGET_MS,
      });
      expect(result, `relay result: ${JSON.stringify(result)}`).toMatchObject({
        kind: 'NO_RELAY',
        timedOut: false,
      });
      expect(existsSync(join(dir, 'relay.json'))).toBe(false);
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
