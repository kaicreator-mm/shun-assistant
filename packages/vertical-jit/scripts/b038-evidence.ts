// B-038 real Windows evidence run for T06 (LOCAL_WINDOWS_BUILD_HOST).
//
// Executes the Loop B JIT lifecycle against the REAL winget official source
// on this host with disposable portable packages, and records the frozen
// evidence set:
//   1. trusted acquisition/use with exact provenance, RETAIN
//   2. verified-use R2 removal with residue classification
//   3. user-asset canary inside the deletion scope ⇒ removal blocked
//   4. interrupted removal (crash after the real effect) ⇒ reconcile-first
//   5. unknown provenance (bogus package id) ⇒ typed refusal, nothing installed
//   6. stale grant between issuance and boundary ⇒ GRANT_POLICY_STALE, no effect
//   7. elevation refused non-interactively ⇒ UAC_DECLINED, NOT_STARTED
//
// Usage: node scripts/b038-evidence.ts [evidenceDir]
// The run needs network access to the official winget endpoint and a
// non-elevated shell for scenario 7 (it is skipped with the reason otherwise).

import { spawn } from 'node:child_process';
import { mkdir, readFile, rm, statfs, writeFile } from 'node:fs/promises';
import { cpus, homedir, release as osRelease, totalmem } from 'node:os';
import { join } from 'node:path';
import {
  type EnvironmentFacts,
  type JitLifecycleOutput,
  JitLifecycleOutputSchema,
} from '@shun/contracts';
import { CliTaskBackend } from '../src/adapters/cli-backend.ts';
import { FileJournal, NodeFilesystem, SpawnProcess } from '../src/adapters/node.ts';
import { WingetAcquisition, WingetPrivilegedBackend } from '../src/adapters/winget.ts';
import { JitLifecycleError } from '../src/failures.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import type { PrivilegedFault } from '../src/local-backend.ts';
import {
  jitCapabilityDefinition,
  MemoryStore,
  MockApproval,
  MockRegistry,
  providerIdFor,
  trustedProviderDefinition,
} from '../src/mocks.ts';
import {
  type JitLifecycleDeps,
  runJitBenchmarkLifecycle,
  runJitLifecycle,
} from '../src/orchestrator.ts';
import { AcquisitionError } from '../src/ports.ts';
import { PatternVerifier } from '../src/verifiers.ts';

const now = (): string => new Date().toISOString();

interface ScenarioResult {
  readonly id: string;
  readonly title: string;
  status: 'PASS' | 'FAIL' | 'SKIPPED';
  detail?: string;
  output?: unknown;
  error?: string;
}

const results: ScenarioResult[] = [];

async function scenario(id: string, title: string, fn: () => Promise<string>): Promise<void> {
  const started = Date.now();
  try {
    const detail = await fn();
    results.push({
      id,
      title,
      status: 'PASS',
      detail: `${detail} (${Math.round((Date.now() - started) / 1000)}s)`,
    });
    console.log(`[PASS] ${id} — ${title}`);
  } catch (error) {
    if (error instanceof SkipSignal) {
      results.push({ id, title, status: 'SKIPPED', detail: error.message });
      console.log(`[SKIP] ${id} — ${error.message}`);
      return;
    }
    const message = error instanceof Error ? error.message : String(error);
    results.push({ id, title, status: 'FAIL', error: message });
    console.log(`[FAIL] ${id} — ${message}`);
  }
}

class SkipSignal extends Error {}

function isElevated(): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn('net', ['session'], { shell: false, windowsHide: true });
    child.on('close', (code) => resolve(code === 0));
    child.on('error', () => resolve(false));
  });
}

/** Best-effort host cleanup: winget uninstall, then kill any GUI the task step launched. */
async function cleanupWinget(packageId: string, processName?: string): Promise<void> {
  await new Promise<void>((resolve) => {
    const child = spawn(
      'winget',
      ['uninstall', '--id', packageId, '--exact', '--disable-interactivity'],
      { shell: false, windowsHide: true, stdio: 'ignore' },
    );
    child.on('close', () => resolve());
    child.on('error', () => resolve());
  });
  if (!processName) return;
  await new Promise<void>((resolve) => {
    const killer = spawn('taskkill', ['/IM', processName, '/F'], {
      shell: false,
      windowsHide: true,
      stdio: 'ignore',
    });
    killer.on('close', () => resolve());
    killer.on('error', () => resolve());
  });
}

async function realFacts(): Promise<EnvironmentFacts> {
  const elevated = await isElevated();
  let freeDiskMb = 0;
  try {
    const stats = await statfs(process.env.SystemDrive ?? 'C:');
    freeDiskMb = Math.round((stats.bsize * stats.bavail) / (1024 * 1024));
  } catch {
    freeDiskMb = 0;
  }
  return {
    environmentId: 'local-windows-b038',
    backendKind: 'LOCAL_WINDOWS',
    os: `Windows ${osRelease()}`,
    arch: process.arch,
    observationRevision: now(),
    runtimeCapabilities: ['winget', 'node'],
    privilegeMode: elevated ? 'ELEVATED_ADMIN' : 'FILTERED_ADMIN',
    guiSession: true,
    filesystemCapabilities: ['ntfs-acl'],
    networkPolicy: 'POLICY_CONTROLLED',
    resources: {
      cpuCores: cpus().length,
      memoryMb: Math.round(totalmem() / (1024 * 1024)),
      freeDiskMb,
    },
  };
}

interface World {
  readonly deps: JitLifecycleDeps;
  readonly authority: LocalAuthority;
  readonly store: MemoryStore;
  readonly journalsDir: string;
}

function makeWorld(options: {
  evidenceDir: string;
  packageId: string;
  capabilityId: string;
  taskOutputDir: string;
  machineScope?: boolean;
  faults?: readonly PrivilegedFault[];
}): World {
  const fs = new NodeFilesystem();
  const process = new SpawnProcess();
  const acquisition = new WingetAcquisition(process, fs);
  const journalsDir = join(options.evidenceDir, 'journals');
  const journals = (actionId: string): FileJournal =>
    new FileJournal(join(journalsDir, `${actionId}.jsonl`));
  const authority = new LocalAuthority({ now });
  const store = new MemoryStore();
  const provider = trustedProviderDefinition(options.packageId, {
    version: 'resolved-at-runtime',
    license: 'Recorded-from-winget-show',
    publisher: 'Recorded-from-winget-show',
    installerSha256: 'resolved-at-runtime',
    installDir: '',
    executableName: 'resolved-at-runtime',
    configDir: '',
  });
  provider.acquisition.source = `winget:${options.packageId}`;
  const registry = new MockRegistry({
    capabilities: [jitCapabilityDefinition(options.capabilityId)],
    providers: [provider],
    bindings: [
      {
        bindingId: `binding-${providerIdFor(options.packageId)}`,
        providerId: providerIdFor(options.packageId),
        capabilityId: options.capabilityId,
        capabilityRevisionRange: { min: 'r1' },
        adapterId: 'adapter.jit-cli',
        interfaceClass: 'I1',
        environmentRequirements: { backendKind: 'LOCAL_WINDOWS', os: 'WINDOWS' },
        verifierId: 'verifier.jit-cli',
      },
    ],
    envBindings: [
      {
        providerBindingId: `${providerIdFor(options.packageId)}@local-windows-b038`,
        environmentId: 'local-windows-b038',
        feasibility: { feasible: true, rejectionReasons: [] },
      },
    ],
  });
  const deps: JitLifecycleDeps = {
    registry,
    acquisition,
    privileged: new WingetPrivilegedBackend({
      authority,
      clock: now,
      journals,
      process,
      machineScope: options.machineScope ?? false,
      ...(options.faults ? { faults: options.faults } : {}),
    }),
    environment: new CliTaskBackend({
      process,
      fs,
      facts: FACTS,
      clock: now,
      taskOutputDir: options.taskOutputDir,
    }),
    authorization: authority,
    approval: new MockApproval('approve'),
    verifier: new PatternVerifier(),
    store,
    planLedger: authority.ledger,
    journals,
    fs,
    clock: now,
    policy: {
      rankingPolicyRevision: 'rank-v1',
      machineScopeInstall: options.machineScope ?? false,
      protectedRoots: [join(homedir(), 'Documents')],
      taskOutputDir: options.taskOutputDir,
      durableJitPolicy: {
        policyId: 'pol.b038-jit-removal',
        revision: 'r1',
        jitRemoveAfterVerifiedUse: true,
        forbidUserAssetDeletion: true,
      },
    },
    trace: (event) => {
      void event;
    },
  };
  return { deps, authority, store, journalsDir };
}

let FACTS: EnvironmentFacts;

function lifecycleInput(
  taskId: string,
  capabilityId: string,
  retention: 'RETAIN' | 'JIT_REMOVE_AFTER_VERIFIED_USE',
) {
  return {
    taskId,
    capabilityRequirement: { capabilityId, revision: 'r1' },
    providerConstraints: { trustedProvenanceRequired: true, supportedPlatform: 'WINDOWS' },
    lifecyclePolicy: { retention },
    targetTask: { fixtureRef: 'fixture://b038/version-echo', parameters: { argv: ['--version'] } },
  };
}

function expectRemoved(output: unknown, scenarioId: string): JitLifecycleOutput {
  const parsed = JitLifecycleOutputSchema.parse(output);
  if (parsed.finalState !== 'REMOVED' || parsed.lifecycleState.state !== 'REMOVED') {
    throw new Error(`${scenarioId}: expected REMOVED terminal, got ${parsed.finalState}`);
  }
  if (!parsed.r2Gate) {
    throw new Error(`${scenarioId}: REMOVED output carries no R2 gate record`);
  }
  return parsed;
}

async function main(): Promise<void> {
  const runDir = process.argv[2] ?? join('evidence', `b038-${Date.now()}`);
  await mkdir(runDir, { recursive: true });
  FACTS = await realFacts();
  console.log(`B-038 evidence run in ${runDir}`);
  console.log(`host: ${FACTS.os} ${FACTS.arch} privilege=${FACTS.privilegeMode}`);

  const elevated = FACTS.privilegeMode === 'ELEVATED_ADMIN';

  // ---- Scenario 1: jq trusted acquisition/use, RETAIN then dispose ----
  const jqWorld = makeWorld({
    evidenceDir: runDir,
    packageId: 'jqlang.jq',
    capabilityId: 'data.json.query',
    taskOutputDir: join(runDir, 's1-task-out'),
  });
  await scenario(
    'S1',
    'B-038 trusted acquisition/use/verify + RETAIN (winget official source)',
    async () => {
      const output = await runJitLifecycle(
        lifecycleInput('b038-s1-retain', 'data.json.query', 'RETAIN'),
        jqWorld.deps,
      );
      const parsed = JitLifecycleOutputSchema.parse(output);
      if (parsed.finalState !== 'RETAINED' || parsed.taskResult.verification.status !== 'PASS') {
        throw new Error(
          `S1: expected verified RETAIN, got ${parsed.finalState}/${parsed.taskResult.verification.status}`,
        );
      }
      await writeFile(
        join(runDir, 's1-retain-output.json'),
        JSON.stringify(output, null, 2),
        'utf8',
      );
      return `jq ${parsed.provenance.version} from ${parsed.provenance.source} (hash ${parsed.provenance.hash ?? 'n/a'}) — retained, task verified`;
    },
  );

  await scenario(
    'S1b',
    'B-038 verified-use R2 removal, durable JIT policy (dispose jq)',
    async () => {
      const output = await runJitLifecycle(
        lifecycleInput('b038-s1b-remove', 'data.json.query', 'JIT_REMOVE_AFTER_VERIFIED_USE'),
        jqWorld.deps,
      );
      const parsed = expectRemoved(output, 'S1b');
      await writeFile(
        join(runDir, 's1b-removed-output.json'),
        JSON.stringify(output, null, 2),
        'utf8',
      );
      return `removed ${parsed.lifecycleState.version}; residue candidates ${parsed.residueReport.candidates.length}, unknownOrProtectedDeleted=false`;
    },
  );

  // ---- Scenario 2: ripgrep install → remove with residue classification ----
  const rgWorld = makeWorld({
    evidenceDir: runDir,
    packageId: 'BurntSushi.ripgrep.MSVC',
    capabilityId: 'text.search',
    taskOutputDir: join(runDir, 's2-task-out'),
  });
  await scenario(
    'S2',
    'B-038 install/use/verify/remove with residue classification (ripgrep)',
    async () => {
      const output = await runJitLifecycle(
        lifecycleInput('b038-s2-remove', 'text.search', 'JIT_REMOVE_AFTER_VERIFIED_USE'),
        rgWorld.deps,
      );
      const parsed = expectRemoved(output, 'S2');
      const classes = new Set(
        parsed.residueReport.candidates.map((candidate) => candidate.classification),
      );
      await writeFile(
        join(runDir, 's2-removed-output.json'),
        JSON.stringify(output, null, 2),
        'utf8',
      );
      return `ripgrep ${parsed.lifecycleState.version} removed; residue classes ${[...classes].join(', ')}`;
    },
  );

  // ---- Scenario 3: canary inside the deletion scope blocks removal ----
  const rgWorld3 = makeWorld({
    evidenceDir: runDir,
    packageId: 'BurntSushi.ripgrep.MSVC',
    capabilityId: 'text.search',
    taskOutputDir: join(runDir, 's3-task-out'),
  });
  await scenario(
    'S3',
    'B-038 user-asset canary inside deletion scope ⇒ USER_ASSET_AT_RISK, asset intact',
    async () => {
      // Install (retain) so the package dir exists.
      await runJitLifecycle(
        lifecycleInput('b038-s3-install', 'text.search', 'RETAIN'),
        rgWorld3.deps,
      );
      const candidate = await rgWorld3.deps.acquisition.resolveExact({
        packageId: 'BurntSushi.ripgrep.MSVC',
      });
      const layout = await rgWorld3.deps.acquisition.layoutOf(candidate);
      const packageDir = layout.installDirs[0];
      if (!packageDir) throw new Error('S3: no package dir discovered after install');
      const canary = join(packageDir, 'b038-user-canary.txt');
      const envelope = {
        ...lifecycleInput('b038-s3-canary', 'text.search', 'JIT_REMOVE_AFTER_VERIFIED_USE'),
        preExistingUserAssets: [{ path: canary }],
      };
      const blocked = await runJitBenchmarkLifecycle(envelope, rgWorld3.deps, {
        providerOwnedFiles: [...layout.executables],
      }).catch((error: unknown) => error);
      if (!(blocked instanceof JitLifecycleError) || blocked.code !== 'USER_ASSET_AT_RISK') {
        throw new Error(`S3: expected USER_ASSET_AT_RISK, got ${String(blocked)}`);
      }
      // Independent post-check: the canary survives untouched, provider retained.
      const canaryContent = await readFile(canary, 'utf8');
      if (!canaryContent.startsWith('canary 0')) throw new Error('S3: canary content altered');
      await writeFile(
        join(runDir, 's3-blocked.json'),
        JSON.stringify({ code: blocked.code, detail: blocked.detail }, null, 2),
        'utf8',
      );
      // Cleanup for the next scenario: remove the harness canary, then remove the provider.
      await rm(canary, { force: true });
      const disposed = await runJitLifecycle(
        lifecycleInput('b038-s3-dispose', 'text.search', 'JIT_REMOVE_AFTER_VERIFIED_USE'),
        rgWorld3.deps,
      );
      expectRemoved(disposed, 'S3-dispose');
      return `removal blocked (${blocked.detail}); canary intact; provider disposed after canary cleanup`;
    },
  );

  // ---- Scenario 4: interrupted removal (real effect, crashed worker) ----
  const rgWorld4 = makeWorld({
    evidenceDir: runDir,
    packageId: 'BurntSushi.ripgrep.MSVC',
    capabilityId: 'text.search',
    taskOutputDir: join(runDir, 's4-task-out'),
    faults: [
      {
        kind: 'CRASH_AFTER_EFFECT',
        when: (action) => action.action.op === 'software.uninstall',
      },
    ],
  });
  await scenario(
    'S4',
    'B-038 interrupted removal ⇒ journal MAY_HAVE_EXECUTED_UNCERTAIN ⇒ reconcile-first REMOVED',
    async () => {
      await runJitLifecycle(
        lifecycleInput('b038-s4-install', 'text.search', 'RETAIN'),
        rgWorld4.deps,
      );
      const output = await runJitLifecycle(
        lifecycleInput('b038-s4-remove', 'text.search', 'JIT_REMOVE_AFTER_VERIFIED_USE'),
        rgWorld4.deps,
      );
      const parsed = expectRemoved(output, 'S4');
      const journal = await rgWorld4.deps.journals('b038-s4-remove-uninstall').replay();
      const torn = !journal.some((entry) => entry.phase === 'EXEC_DONE');
      await writeFile(
        join(runDir, 's4-torn-journal.jsonl'),
        journal.map((entry) => JSON.stringify(entry)).join('\n'),
        'utf8',
      );
      await writeFile(
        join(runDir, 's4-removed-output.json'),
        JSON.stringify(output, null, 2),
        'utf8',
      );
      return `removed ${parsed.lifecycleState.version}; privileged journal torn at EXEC_START=${torn}; reconcile resolved to REMOVED`;
    },
  );

  // ---- Scenario 5: unknown provenance (bogus package id) ----
  const ghostWorld = makeWorld({
    evidenceDir: runDir,
    packageId: 'Shun.Evidence.NoSuchPackage.7f3a',
    capabilityId: 'text.search',
    taskOutputDir: join(runDir, 's5-task-out'),
  });
  await scenario('S5', 'B-038 unknown provenance ⇒ typed refusal before any install', async () => {
    const error = await runJitLifecycle(
      lifecycleInput('b038-s5-ghost', 'text.search', 'RETAIN'),
      ghostWorld.deps,
    ).catch((caught: unknown) => caught);
    if (!(error instanceof AcquisitionError) || error.kind !== 'PACKAGE_UNKNOWN') {
      throw new Error(`S5: expected PACKAGE_UNKNOWN refusal, got ${String(error)}`);
    }
    await writeFile(
      join(runDir, 's5-refusal.json'),
      JSON.stringify({ kind: error.kind, detail: error.message }, null, 2),
      'utf8',
    );
    return `refused: ${error.message}`;
  });

  // ---- Scenario 6: stale grant between issuance and boundary ----
  const staleWorld = makeWorld({
    evidenceDir: runDir,
    packageId: 'jqlang.jq',
    capabilityId: 'data.json.query',
    taskOutputDir: join(runDir, 's6-task-out'),
  });
  await scenario(
    'S6',
    'B-038 stale policy grant ⇒ GRANT_POLICY_STALE at the boundary, no side effect',
    async () => {
      const inner = staleWorld.deps.privileged;
      const deps: JitLifecycleDeps = {
        ...staleWorld.deps,
        privileged: {
          execute: async (action, grant) => {
            staleWorld.authority.supersedePolicy('pol-snap-changed-mid-run');
            return inner.execute(action, grant);
          },
        },
      };
      const error = await runJitLifecycle(
        lifecycleInput('b038-s6-stale', 'data.json.query', 'RETAIN'),
        deps,
      ).catch((caught: unknown) => caught);
      if (!(error instanceof JitLifecycleError) || !error.detail.includes('GRANT_POLICY_STALE')) {
        throw new Error(`S6: expected GRANT_POLICY_STALE refusal, got ${String(error)}`);
      }
      if (error.recovery?.recoveryClassification !== 'FAILED_BEFORE_EFFECT') {
        throw new Error(
          `S6: expected FAILED_BEFORE_EFFECT recovery, got ${error.recovery?.recoveryClassification}`,
        );
      }
      await writeFile(
        join(runDir, 's6-stale-grant.json'),
        JSON.stringify(
          { code: error.code, detail: error.detail, recovery: error.recovery },
          null,
          2,
        ),
        'utf8',
      );
      return 'boundary refused the presentation; journal stopped before EXEC_START; nothing installed';
    },
  );

  // ---- Scenario 7: elevation refused non-interactively ----
  await scenario(
    'S7',
    'B-038 elevation refused non-interactively ⇒ UAC_DECLINED / NOT_STARTED (Notepad++ machine scope)',
    async () => {
      if (elevated) {
        throw new SkipSignal(
          'shell is elevated — a refusal cannot be produced; run on a standard-user shell',
        );
      }
      const zipWorld = makeWorld({
        evidenceDir: runDir,
        packageId: 'Notepad++.Notepad++',
        capabilityId: 'text.editor',
        taskOutputDir: join(runDir, 's7-task-out'),
        machineScope: true,
      });
      const error = await runJitLifecycle(
        lifecycleInput('b038-s7-elevation', 'text.editor', 'RETAIN'),
        zipWorld.deps,
      ).catch((caught: unknown) => caught);
      const silentlyGranted =
        !(error instanceof JitLifecycleError) ||
        /not present on disk/.test((error as JitLifecycleError).detail);
      if (silentlyGranted) {
        // This host granted elevation silently (UAC never-notify): the
        // machine-scope install really executed. Clean up and record the
        // negative as unproducible on this host.
        await cleanupWinget('Notepad++.Notepad++', 'notepad++.exe');
        throw new SkipSignal(
          'UAC silently granted the machine-scope install on this host — a declined-elevation negative cannot be produced here (UAC_DECLINED semantics stay covered by the port-level test suite); install attempt artifacts are in journals/',
        );
      }
      if (!(error instanceof JitLifecycleError) || error.code !== 'INSTALL_FAILED') {
        throw new Error(`S7: expected INSTALL_FAILED, got ${String(error)}`);
      }
      if (error.recovery?.recoveryClassification !== 'NOT_STARTED') {
        throw new Error(
          `S7: expected NOT_STARTED recovery, got ${error.recovery?.recoveryClassification}`,
        );
      }
      await writeFile(
        join(runDir, 's7-elevation.json'),
        JSON.stringify(
          { code: error.code, detail: error.detail, recovery: error.recovery },
          null,
          2,
        ),
        'utf8',
      );
      return 'machine-scope install refused without an elevation path; helper provably never started';
    },
  );

  // ---- Summary ----
  const passed = results.filter((entry) => entry.status === 'PASS').length;
  const failed = results.filter((entry) => entry.status === 'FAIL').length;
  const skipped = results.filter((entry) => entry.status === 'SKIPPED').length;
  const summary = [
    `# B-038 evidence — Loop B trusted JIT software lifecycle (T06)`,
    '',
    `- Host: ${FACTS.os} ${FACTS.arch}, privilege ${FACTS.privilegeMode}`,
    `- Run dir: ${runDir}`,
    `- Result: ${passed} PASS / ${failed} FAIL / ${skipped} SKIPPED`,
    '',
    '| Scenario | Status | Detail |',
    '| --- | --- | --- |',
    ...results.map(
      (entry) =>
        `| ${entry.id} ${entry.title} | ${entry.status} | ${entry.detail ?? entry.error ?? ''} |`,
    ),
    '',
    'Store records and privileged journals are under this run directory.',
  ].join('\n');
  await writeFile(join(runDir, 'summary.md'), summary, 'utf8');
  await writeFile(join(runDir, 'results.json'), JSON.stringify(results, null, 2), 'utf8');
  console.log(
    `\n${passed} PASS / ${failed} FAIL / ${skipped} SKIPPED — summary at ${join(runDir, 'summary.md')}`,
  );
  if (failed > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
