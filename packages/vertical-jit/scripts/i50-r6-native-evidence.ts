// T10 / #50 R6 — real-Windows native handle-safety evidence run
// (LOCAL_WINDOWS_NATIVE_BUILDER_VALIDATOR).
//
// Executes the managed-portable lifecycle against the REAL winget catalog on
// this host through the R6 native primitives (ShunNative.cs via the trusted
// PowerShell transport), with concrete ShunStore durability and every
// negative exercised for real:
//
//   HOST  real host/winget/PowerShell/elevation facts
//   A     official source resolution (winget show → portable (zip) + exact SHA)
//   B     real winget download (spaced/parens artifact + YAML sidecar) →
//         locked-stream native extraction → node.exe discovery → --version
//   C     B-038 archive task with task readPaths bound into the executed plan
//   D     R2 removal gate → native identity-pinned deletion → both roots
//         absent, user fixture canary unchanged
//   E     foreign file in provider root / in download root ⇒ refuse, zero
//         deletion (preflight AND effect-level native refusal)
//   F1    concrete ShunStore restart reconcile (crash after CHECKPOINT → new
//         composition resumes removal without reinstall)
//   F2    corrupt durable CHECKPOINT (SQLite payload tamper) ⇒ retain/refuse
//   F3    stale checkpoint provenance ⇒ retain/refuse
//   F4    checkpoint with absent provider ⇒ REMOVE_FAILED/UNCERTAIN, never an
//         invented removal PASS
//   G     raw external WinGet uninstall stays REFUSED / FAILED_BEFORE_EFFECT
//         with zero winget-uninstall invocations
//   H     the full win32 native adversarial vitest suite re-run at evidence
//         time (junction storms, bombs, races — no skipped row)
//
// Usage: node scripts/i50-r6-native-evidence.ts [evidenceDir]
// Needs network to the official winget CDN and a non-elevated shell.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { lstat, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir, release as osRelease } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ActionPlan, EnvironmentFacts, JitLifecycleOutput } from '@shun/contracts';
import { JitLifecycleOutputSchema } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { CliTaskBackend } from '../src/adapters/cli-backend.ts';
import {
  ManagedPortableAcquisition,
  ManagedPortablePrivilegedBackend,
} from '../src/adapters/managed-portable.ts';
import { PowerShellNativeDeleter, SafePowerShellZipExtractor } from '../src/adapters/native-win.ts';
import { FileJournal, NodeFilesystem, SpawnProcess } from '../src/adapters/node.ts';
import { WingetPrivilegedBackend } from '../src/adapters/winget.ts';
import { JitLifecycleError } from '../src/failures.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import {
  jitCapabilityDefinition,
  MockApproval,
  MockRegistry,
  providerIdFor,
  trustedProviderDefinition,
} from '../src/mocks.ts';
import {
  type JitLifecycleDeps,
  resumeJitRemovalFromCheckpoint,
  runJitLifecycle,
} from '../src/orchestrator.ts';
import { buildActionPlan, uninstallAction } from '../src/plans.ts';
import type { ProcessPort, ProcessResult, ProcessRunSpec } from '../src/ports.ts';
import { PatternVerifier } from '../src/verifiers.ts';

const now = (): string => new Date().toISOString();
const PACKAGE_ID = 'OpenJS.NodeJS.LTS';
const CAPABILITY_ID = 'node.script.run';
const BINDING_ID = `binding-${providerIdFor(PACKAGE_ID)}`;
const POWERSHELL_EXE = join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);
const PACKAGE_DIR = dirname(dirname(fileURLToPath(import.meta.url)));

interface ScenarioResult {
  readonly id: string;
  readonly title: string;
  status: 'PASS' | 'FAIL' | 'SKIPPED';
  detail?: string;
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
    const message = error instanceof Error ? error.message : String(error);
    results.push({ id, title, status: 'FAIL', error: message });
    console.log(`[FAIL] ${id} — ${message}`);
  }
}

function firstLine(stdout: string): string {
  return (
    stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean) ?? ''
  );
}

function resolveWingetPath(): string {
  const probe = spawnSync('where.exe', ['winget'], { encoding: 'utf8' });
  const path = firstLine(probe.stdout ?? '');
  if (!path) throw new Error('winget.exe not resolvable on PATH');
  return path;
}

function isElevated(): boolean {
  return spawnSync('net', ['session'], { encoding: 'utf8' }).status === 0;
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

async function sha256File(path: string): Promise<string> {
  return createHash('sha256')
    .update(await readFile(path))
    .digest('hex');
}

async function refusalOf(promise: Promise<unknown>): Promise<{ code: string; message: string }> {
  try {
    await promise;
    return { code: 'NO_ERROR', message: 'unexpected success' };
  } catch (error) {
    if (error instanceof JitLifecycleError) {
      return { code: error.code, message: error.message };
    }
    return { code: 'UNKNOWN', message: error instanceof Error ? error.message : String(error) };
  }
}

/** Records whether any raw winget uninstall was ever spawned (must stay false). */
class WatchingProcess implements ProcessPort {
  readonly #inner: ProcessPort;
  uninstallInvoked = false;

  constructor(inner: ProcessPort) {
    this.#inner = inner;
  }

  run(spec: ProcessRunSpec): Promise<ProcessResult> {
    if (spec.argv.includes('uninstall')) this.uninstallInvoked = true;
    return this.#inner.run(spec);
  }
}

interface WorldOptions {
  evidenceDir: string;
  scenarioName: string;
  approvalMode?: 'approve' | 'die-after-checkpoint';
  durablePolicy?: boolean;
  /** Same-machine restart composition: reuse the crashed world's root/store. */
  managedRootOverride?: string;
  storeOverride?: ShunStore;
}

interface ManagedWorld {
  readonly deps: JitLifecycleDeps;
  readonly authority: LocalAuthority;
  readonly acquisition: ManagedPortableAcquisition;
  readonly store: ShunStore;
  readonly watchedProcess: WatchingProcess;
  readonly plans: ActionPlan[];
  readonly taskOutputDir: string;
  readonly managedRoot: string;
  readonly traces: { at: string; kind: string; detail?: string }[];
}

function makeManagedWorld(options: WorldOptions): ManagedWorld {
  const watchedProcess = new WatchingProcess(new SpawnProcess());
  const fs = new NodeFilesystem();
  const extractor = new SafePowerShellZipExtractor(watchedProcess, POWERSHELL_EXE, {
    timeoutMs: 10 * 60_000,
  });
  const deleter = new PowerShellNativeDeleter(watchedProcess, POWERSHELL_EXE, {
    timeoutMs: 10 * 60_000,
  });
  const managedRoot =
    options.managedRootOverride ?? join(options.evidenceDir, options.scenarioName, 'shun-managed');
  const acquisition = new ManagedPortableAcquisition(watchedProcess, fs, {
    root: managedRoot,
    wingetExe: resolveWingetPath(),
    executableName: 'node.exe',
    extractor,
    nativeDeleter: deleter,
    timeoutMs: 10 * 60_000,
  });
  const journalsDir = join(options.evidenceDir, options.scenarioName, 'journals');
  const journals = (actionId: string): FileJournal =>
    new FileJournal(join(journalsDir, `${actionId}.jsonl`));
  const authority = new LocalAuthority({ now });
  const storeDir = join(options.evidenceDir, options.scenarioName);
  mkdirSync(storeDir, { recursive: true }); // SQLite creates files, not directories
  mkdirSync(join(storeDir, 'task-out'), { recursive: true });
  const store = options.storeOverride ?? new ShunStore({ file: join(storeDir, 'shun-store.db') });
  const provider = trustedProviderDefinition(PACKAGE_ID, {
    version: 'resolved-at-runtime',
    license: 'Recorded-from-winget-show',
    publisher: 'Recorded-from-winget-show',
    installerSha256: 'resolved-at-runtime',
    installDir: '',
    executableName: 'node.exe',
    configDir: '',
  });
  provider.acquisition.source = `winget:${PACKAGE_ID}`;
  const registry = new MockRegistry({
    capabilities: [jitCapabilityDefinition(CAPABILITY_ID)],
    providers: [provider],
    bindings: [
      {
        bindingId: BINDING_ID,
        providerId: providerIdFor(PACKAGE_ID),
        capabilityId: CAPABILITY_ID,
        capabilityRevisionRange: { min: 'r1' },
        adapterId: 'adapter.jit-cli',
        interfaceClass: 'I1',
        environmentRequirements: { backendKind: 'LOCAL_WINDOWS', os: 'WINDOWS' },
        verifierId: 'verifier.jit-cli',
      },
    ],
    envBindings: [
      {
        providerBindingId: `${providerIdFor(PACKAGE_ID)}@local-windows-r6`,
        environmentId: 'local-windows-r6',
        feasibility: { feasible: true, rejectionReasons: [] },
      },
    ],
  });
  const taskOutputDir = join(options.evidenceDir, options.scenarioName, 'task-out');
  const facts: EnvironmentFacts = {
    environmentId: 'local-windows-r6',
    backendKind: 'LOCAL_WINDOWS',
    os: `Windows ${osRelease()}`,
    arch: process.arch,
    observationRevision: now(),
    runtimeCapabilities: ['winget', 'node', 'powershell-native'],
    privilegeMode: isElevated() ? 'ELEVATED_ADMIN' : 'FILTERED_ADMIN',
    guiSession: true,
    filesystemCapabilities: ['ntfs-acl'],
    networkPolicy: 'POLICY_CONTROLLED',
    resources: { cpuCores: 1, memoryMb: 0, freeDiskMb: 0 },
  };
  const plans: ActionPlan[] = [];
  const traces: { at: string; kind: string; detail?: string }[] = [];
  const deps: JitLifecycleDeps = {
    registry,
    acquisition,
    privileged: new ManagedPortablePrivilegedBackend({
      authority,
      clock: now,
      journals,
      acquisition,
    }),
    environment: new CliTaskBackend({
      process: watchedProcess,
      fs,
      facts,
      clock: now,
      taskOutputDir,
      ledger: authority.ledger,
    }),
    authorization: authority,
    approval:
      options.approvalMode === 'die-after-checkpoint'
        ? {
            requestApproval: async () => {
              throw new Error('simulated process death after durable checkpoint');
            },
          }
        : new MockApproval('approve'),
    verifier: new PatternVerifier(),
    store,
    planLedger: {
      register: async (plan) => {
        plans.push(plan);
        return authority.ledger.register(plan);
      },
      byHash: (hash) => authority.ledger.byHash(hash),
    },
    lifecycleReader: {
      getLifecycleRecord: async (recordId) => {
        const record = await store.getRecord('lifecycle_record', recordId);
        return record
          ? { recordId: record.recordId, payload: record.payload, revision: record.revision }
          : null;
      },
    },
    taskPresentationGate: {
      validate: ({ action, grant, plan }) =>
        authority.validatePresentation(authority.validationInput(grant, plan, action, now())),
    },
    journals,
    fs,
    clock: now,
    policy: {
      rankingPolicyRevision: 'rank-v1',
      machineScopeInstall: false,
      protectedRoots: [join(homedir(), 'Documents'), join(options.evidenceDir, 'user-fixture')],
      taskOutputDir,
      ...(options.durablePolicy
        ? {
            durableJitPolicy: {
              policyId: 'pol.i50-r6-jit-removal',
              revision: 'r1',
              jitRemoveAfterVerifiedUse: true,
              forbidUserAssetDeletion: true as const,
            },
          }
        : {}),
    },
    trace: (event) => traces.push(event),
  };
  return {
    deps,
    authority,
    acquisition,
    store,
    watchedProcess,
    plans,
    taskOutputDir,
    managedRoot,
    traces,
  };
}

function lifecycleInput(
  taskId: string,
  retention: 'RETAIN' | 'JIT_REMOVE_AFTER_VERIFIED_USE',
  runner: string,
  inputPath: string,
  outputPath: string,
) {
  return {
    taskId,
    capabilityRequirement: { capabilityId: CAPABILITY_ID, revision: 'r1' },
    providerConstraints: { trustedProvenanceRequired: true, supportedPlatform: 'WINDOWS' },
    lifecyclePolicy: { retention },
    targetTask: {
      fixtureRef: 'fixture://i50-r6/node-echo',
      parameters: { argv: [runner, inputPath, outputPath], readPaths: [runner, inputPath] },
    },
  };
}

function parseLifecycle(output: unknown): JitLifecycleOutput {
  return JitLifecycleOutputSchema.parse(output);
}

async function managedRootsOf(world: ManagedWorld): Promise<string[]> {
  const candidate = await world.acquisition.resolveExact({ packageId: PACKAGE_ID });
  return (await world.acquisition.predictScope(candidate, false)) as string[];
}

async function main(): Promise<void> {
  if (process.platform !== 'win32') {
    throw new Error('this evidence run requires a real Windows host');
  }
  const evidenceDir = process.argv[2] ?? join(process.cwd(), 'evidence', `i50-r6-${Date.now()}`);
  await mkdir(evidenceDir, { recursive: true });
  console.log(`I50-R6 native evidence run in ${evidenceDir}`);
  const wingetExe = resolveWingetPath();
  const wingetVersion = firstLine(
    spawnSync(wingetExe, ['--version'], { encoding: 'utf8' }).stdout ?? '',
  );
  const psVersion = firstLine(
    spawnSync(
      POWERSHELL_EXE,
      ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'],
      {
        encoding: 'utf8',
      },
    ).stdout ?? '',
  );

  await scenario('HOST', 'real Windows host facts', async () => {
    if (!wingetVersion) throw new Error('winget --version produced nothing');
    if (!psVersion) throw new Error('PowerShell version probe produced nothing');
    return `Windows ${osRelease()} arch=${process.arch} node=${process.version} winget=${wingetVersion} powershell=${psVersion} elevated=${isElevated()}`;
  });

  // user fixture (canary) — outside every managed root
  const fixtureDir = join(evidenceDir, 'user-fixture');
  await mkdir(fixtureDir, { recursive: true });
  const runnerPath = join(fixtureDir, 'echo-fixture.js');
  const inputPath = join(fixtureDir, 'task-input.txt');
  const fixtureMarker = `i50-r6-canary-${Date.now()}`;
  await writeFile(
    runnerPath,
    [
      "const fs = require('node:fs');",
      'const [, , inputPath, outputPath] = process.argv;',
      "const text = fs.readFileSync(inputPath, 'utf8');",
      "fs.writeFileSync(outputPath, 'fixture=' + text.trim() + ' node=' + process.version + '\\n');",
      "console.log(process.version + ' fixture=' + text.trim());",
      '',
    ].join('\n'),
    'utf8',
  );
  await writeFile(inputPath, fixtureMarker, 'utf8');
  const runnerHash = await sha256File(runnerPath);
  const inputHash = await sha256File(inputPath);

  // ---- W1: acquisition-level chain (resolve → download → extract → discover) ----
  const w1 = makeManagedWorld({ evidenceDir, scenarioName: 'w1-acquire' });
  let resolvedVersion = '';
  await scenario(
    'A',
    'official winget source resolves the OpenJS portable (zip) provider',
    async () => {
      const sources = await w1.acquisition.officialSources();
      if (!sources.some((source) => source.url.startsWith('https://cdn.winget.microsoft.com'))) {
        throw new Error(`official winget CDN source missing: ${JSON.stringify(sources)}`);
      }
      const candidate = await w1.acquisition.resolveExact({ packageId: PACKAGE_ID });
      if (!candidate.official) throw new Error('candidate not flagged official');
      if (candidate.installerType !== 'portable (zip)' && candidate.installerType !== 'zip') {
        throw new Error(`installer type not portable(zip): ${candidate.installerType}`);
      }
      if (!candidate.installerUrl?.startsWith('https://nodejs.org/')) {
        throw new Error(`unexpected installer URL: ${candidate.installerUrl}`);
      }
      if (!/^[0-9a-f]{64}$/.test(candidate.installerSha256 ?? '')) {
        throw new Error('no exact catalog SHA256');
      }
      resolvedVersion = candidate.version;
      await writeFile(
        join(evidenceDir, 'a-resolve.json'),
        JSON.stringify(candidate, null, 2),
        'utf8',
      );
      return `${PACKAGE_ID} ${candidate.version} type=${candidate.installerType} sha=${candidate.installerSha256}`;
    },
  );

  await scenario(
    'B',
    'real winget download (spaced artifact + YAML sidecar) → native locked extraction → node.exe discovery',
    async () => {
      const candidate = await w1.acquisition.resolveExact({ packageId: PACKAGE_ID });
      const installOutcome = await w1.acquisition.install(PACKAGE_ID, candidate.version);
      if (!installOutcome.ok) throw new Error(`managed install refused: ${installOutcome.note}`);
      const layout = await w1.acquisition.layoutOf(candidate);
      const executable = layout.executables[0];
      if (!executable) throw new Error('no discovered executable');
      const probe = await new SpawnProcess().run({
        argv: [executable, '--version'],
        timeoutMs: 60_000,
      });
      if (probe.exitCode !== 0 || !probe.stdout.includes(candidate.version)) {
        throw new Error(
          `node --version failed: exit=${probe.exitCode} stdout=${probe.stdout.trim()}`,
        );
      }
      const downloadEntries =
        layout.ownedPaths?.filter((path) => path.startsWith(layout.cacheDirs[0] ?? '\\')) ?? [];
      const sidecar = downloadEntries.find((path) => path.toLowerCase().endsWith('.yaml'));
      const artifact = downloadEntries.find((path) => path.toLowerCase().endsWith('.zip'));
      if (!sidecar || !artifact) {
        throw new Error(`artifact/sidecar missing: ${JSON.stringify(downloadEntries)}`);
      }
      if (!/( |\()/.test(artifact))
        throw new Error(`artifact filename lacks space/paren shape: ${artifact}`);
      return `node=${probe.stdout.trim()}; artifact=${artifact.split('\\').pop()}; yaml sidecar present`;
    },
  );

  // ---- W1b: full lifecycle (install → task/readPaths → verify → R2 removal) ----
  const w1b = makeManagedWorld({ evidenceDir, scenarioName: 'w1b-lifecycle' });
  let lifecycleResult: JitLifecycleOutput | undefined;
  await scenario(
    'C',
    'B-038 archive task executes with task readPaths bound into the executed ActionPlan',
    async () => {
      const outputPath = join(w1b.taskOutputDir, 'out.txt');
      const output = await runJitLifecycle(
        lifecycleInput(
          'i50-r6-full',
          'JIT_REMOVE_AFTER_VERIFIED_USE',
          runnerPath,
          inputPath,
          outputPath,
        ),
        w1b.deps,
      );
      lifecycleResult = parseLifecycle(output);
      if (lifecycleResult.taskResult.verification.status !== 'PASS') {
        throw new Error(`verification: ${lifecycleResult.taskResult.verification.status}`);
      }
      const taskAction = w1b.plans
        .flatMap((plan) => plan.actions)
        .find((action) => action.op === 'process.argv');
      if (!taskAction) throw new Error('no process.argv action in registered plans');
      const readScope = taskAction.filesystemScope?.read ?? [];
      for (const expected of [runnerPath, inputPath]) {
        if (!readScope.some((scopePath) => resolve(scopePath) === resolve(expected))) {
          throw new Error(`readPath not bound: ${expected}; scope=${JSON.stringify(readScope)}`);
        }
      }
      const semantic = await readFile(outputPath, 'utf8');
      if (!semantic.includes(`fixture=${fixtureMarker}`)) {
        throw new Error(`semantic output missing fixture marker: ${semantic.trim()}`);
      }
      if (!semantic.includes(`node=v${resolvedVersion}`)) {
        throw new Error(`semantic output missing managed node version: ${semantic.trim()}`);
      }
      await writeFile(
        join(evidenceDir, 'c-lifecycle-output.json'),
        JSON.stringify(output, null, 2),
        'utf8',
      );
      return `readPaths bound (runner+input); semantic output verified`;
    },
  );

  await scenario(
    'D',
    'R2 gate removes provider via native identity-pinned deletion; roots absent; canary unchanged',
    async () => {
      if (lifecycleResult?.finalState !== 'REMOVED') {
        throw new Error(`expected REMOVED terminal, got ${lifecycleResult?.finalState}`);
      }
      for (const root of await managedRootsOf(w1b)) {
        if (await exists(root)) throw new Error(`managed root still present: ${root}`);
      }
      if ((await sha256File(runnerPath)) !== runnerHash)
        throw new Error('user fixture runner mutated');
      if ((await sha256File(inputPath)) !== inputHash)
        throw new Error('user fixture input mutated');
      return `roots absent; canary hashes unchanged; approval=${lifecycleResult.r2Gate?.approvedBy ?? 'approval'}`;
    },
  );

  // ---- W2: foreign-file negatives on a retained provider ----
  const w2 = makeManagedWorld({ evidenceDir, scenarioName: 'w2-foreign' });
  await scenario(
    'E',
    'foreign file in provider root AND in download root refuse removal with zero deletion',
    async () => {
      const retainOutput = await runJitLifecycle(
        lifecycleInput(
          'i50-r6-foreign',
          'RETAIN',
          runnerPath,
          inputPath,
          join(w2.taskOutputDir, 'out.txt'),
        ),
        w2.deps,
      );
      if (parseLifecycle(retainOutput).finalState !== 'RETAINED') {
        throw new Error('precondition: expected RETAINED lifecycle');
      }
      const candidate = await w2.acquisition.resolveExact({ packageId: PACKAGE_ID });
      const layout = await w2.acquisition.layoutOf(candidate);
      const manifest = layout.ownedPaths;
      if (!manifest) throw new Error('no owned manifest');
      const action = uninstallAction({
        actionId: 'i50-r6-foreign-remove',
        bindingId: BINDING_ID,
        packageId: PACKAGE_ID,
        version: candidate.version,
        deleteRoots: [...layout.installDirs, ...layout.cacheDirs],
        deletionManifest: manifest,
        deletionIdentities: layout.ownedObjectIdentities,
        elevated: false,
        timeoutMs: 10 * 60_000,
      });
      const cases = [
        { label: 'provider-root', path: join(layout.installDirs[0] ?? '', 'attacker-dropped.txt') },
        { label: 'download-root', path: join(layout.cacheDirs[0] ?? '', 'attacker-dropped.txt') },
      ];
      for (const foreignCase of cases) {
        await writeFile(foreignCase.path, 'foreign content', 'utf8');
        const preflight = await w2.acquisition.removalPreflight(action);
        if (!preflight || preflight.ok || !preflight.noEffect) {
          throw new Error(`${foreignCase.label}: preflight did not refuse with noEffect`);
        }
        const effect = await w2.acquisition.remove(action);
        if (effect.ok) throw new Error(`${foreignCase.label}: effect removal did not refuse`);
        if (!effect.noEffect)
          throw new Error(`${foreignCase.label}: refusal not noEffect (partial deletion?)`);
        if (!(await exists(foreignCase.path)))
          throw new Error(`${foreignCase.label}: foreign file deleted`);
        for (const owned of manifest) {
          if (resolve(owned) === resolve(foreignCase.path)) continue;
          if (!(await exists(owned)))
            throw new Error(`${foreignCase.label}: owned path deleted: ${owned}`);
        }
        await rm(foreignCase.path, { force: true });
      }
      return 'both foreign placements refused with zero deletion';
    },
  );

  // ---- F1/F4: crash after CHECKPOINT on one store, resume from another ----
  const RESTART_TASK = 'i50-r6-restart';
  const restartInput = (world: ManagedWorld) =>
    lifecycleInput(
      RESTART_TASK,
      'JIT_REMOVE_AFTER_VERIFIED_USE',
      runnerPath,
      inputPath,
      join(world.taskOutputDir, 'out.txt'),
    );
  const w3 = makeManagedWorld({
    evidenceDir,
    scenarioName: 'w3-crash',
    approvalMode: 'die-after-checkpoint',
  });
  const checkpointId = `jit:${RESTART_TASK}:lifecycle:checkpoint`;

  await scenario('F1a', 'crash after durable CHECKPOINT retains provider on disk', async () => {
    const refusal = await refusalOf(runJitLifecycle(restartInput(w3), w3.deps));
    if (!refusal.message.includes('simulated process death')) {
      throw new Error(`expected simulated death, got: ${refusal.message}`);
    }
    const record = await w3.store.getRecord('lifecycle_record', checkpointId);
    if (record?.payload.state !== 'CHECKPOINT') {
      throw new Error('durable CHECKPOINT record missing after crash');
    }
    const durableIdentities = record.payload.providerOwnedObjectIdentities;
    if (!Array.isArray(durableIdentities) || durableIdentities.length === 0) {
      throw new Error('durable CHECKPOINT omitted install-time file identities');
    }
    const layout = record.payload.layout as { installDirs: string[] };
    const providerRoot = layout.installDirs[0];
    if (!providerRoot || !(await exists(providerRoot))) {
      throw new Error('provider root vanished after crash');
    }
    return 'CHECKPOINT durable in concrete ShunStore; provider retained';
  });

  await scenario(
    'F1b',
    'fresh composition resumes removal from concrete ShunStore without reinstall',
    async () => {
      // a real restart on the same machine: fresh process composition over
      // the SAME managed root and the SAME authoritative SQLite store
      const resumed = makeManagedWorld({
        evidenceDir,
        scenarioName: 'w3-resumed',
        durablePolicy: true,
        managedRootOverride: w3.managedRoot,
        storeOverride: w3.store,
      });
      const deps = resumed.deps;
      const output = parseLifecycle(
        await resumeJitRemovalFromCheckpoint(restartInput(resumed), deps),
      );
      if (output.finalState !== 'REMOVED') throw new Error(`resume ended ${output.finalState}`);
      if (output.r2Gate?.approvedBy !== 'DURABLE_POLICY') {
        throw new Error(`approval source: ${output.r2Gate?.approvedBy}`);
      }
      if (!resumed.traces.some((event) => event.kind === 'RESTART_CHECKPOINT_REHYDRATED')) {
        throw new Error('rehydration trace missing');
      }
      if (resumed.traces.some((event) => event.kind === 'INSTALL_EXECUTED')) {
        throw new Error('resume reinstalled the provider');
      }
      for (const root of await managedRootsOf(resumed)) {
        if (await exists(root))
          throw new Error(`root still present after resumed removal: ${root}`);
      }
      return 'REMOVED via DURABLE_POLICY; no reinstall; roots absent';
    },
  );

  await scenario(
    'F4',
    'resume against absent provider refuses REMOVE_FAILED/UNCERTAIN (no invented PASS)',
    async () => {
      // the crashed world's own composition still holds the CHECKPOINT, but the
      // provider was removed by F1b — resuming must refuse honestly
      const refusal = await refusalOf(resumeJitRemovalFromCheckpoint(restartInput(w3), w3.deps));
      if (
        !/REMOVE_FAILED|UNCERTAIN|manual reconciliation|POLICY_BLOCKED/i.test(
          `${refusal.code} ${refusal.message}`,
        )
      ) {
        throw new Error(`unexpected resume outcome: ${refusal.code} ${refusal.message}`);
      }
      return `refused (${refusal.code}); provider state not invented`;
    },
  );

  // ---- F2: corrupt checkpoint through the store's own fault-injection seam ----
  const corruptScenario = 'w4-corrupt';
  const CORRUPT_TASK = 'i50-r6-corrupt';
  const w4 = makeManagedWorld({
    evidenceDir,
    scenarioName: corruptScenario,
    approvalMode: 'die-after-checkpoint',
  });
  await scenario(
    'F2',
    'corrupt durable CHECKPOINT (SQLite payload tamper) retains provider and refuses',
    async () => {
      const refusal = await refusalOf(
        runJitLifecycle(
          lifecycleInput(
            CORRUPT_TASK,
            'JIT_REMOVE_AFTER_VERIFIED_USE',
            runnerPath,
            inputPath,
            join(w4.taskOutputDir, 'out.txt'),
          ),
          w4.deps,
        ),
      );
      if (!refusal.message.includes('simulated process death')) {
        throw new Error(`crash precondition failed: ${refusal.message}`);
      }
      const record = await w4.store.getRecord(
        'lifecycle_record',
        `jit:${CORRUPT_TASK}:lifecycle:checkpoint`,
      );
      if (!record) throw new Error('checkpoint missing before tamper');
      const layout = record.payload.layout as { installDirs: string[] };
      const providerRoot = layout.installDirs[0];
      if (!providerRoot) throw new Error('checkpoint layout lacks provider root');
      w4.store.database.exec(
        'UPDATE records SET payload = \'{"taskId":"i50-r6-corrupt","state":"CHECK\' WHERE record_kind = \'lifecycle_record\'',
      );
      const resumeRefusal = await refusalOf(
        resumeJitRemovalFromCheckpoint(
          lifecycleInput(
            CORRUPT_TASK,
            'JIT_REMOVE_AFTER_VERIFIED_USE',
            runnerPath,
            inputPath,
            join(w4.taskOutputDir, 'out.txt'),
          ),
          w4.deps,
        ),
      );
      if (
        !/POLICY_BLOCKED|malformed|Unterminated|JSON/i.test(
          `${resumeRefusal.code} ${resumeRefusal.message}`,
        )
      ) {
        throw new Error(
          `corrupt checkpoint not refused: ${resumeRefusal.code} ${resumeRefusal.message}`,
        );
      }
      if (!(await exists(providerRoot)))
        throw new Error('provider deleted despite corrupt checkpoint');
      return 'POLICY_BLOCKED (malformed); provider retained';
    },
  );

  // ---- F3: stale provenance (simulated catalog drift through the reader) ----
  const STALE_TASK = 'i50-r6-stale';
  const w5 = makeManagedWorld({
    evidenceDir,
    scenarioName: 'w5-stale',
    approvalMode: 'die-after-checkpoint',
  });
  await scenario('F3', 'stale checkpoint provenance retains provider and refuses', async () => {
    const refusal = await refusalOf(
      runJitLifecycle(
        lifecycleInput(
          STALE_TASK,
          'JIT_REMOVE_AFTER_VERIFIED_USE',
          runnerPath,
          inputPath,
          join(w5.taskOutputDir, 'out.txt'),
        ),
        w5.deps,
      ),
    );
    if (!refusal.message.includes('simulated process death')) {
      throw new Error(`crash precondition failed: ${refusal.message}`);
    }
    const record = await w5.store.getRecord(
      'lifecycle_record',
      `jit:${STALE_TASK}:lifecycle:checkpoint`,
    );
    if (!record) throw new Error('checkpoint missing');
    const layout = record.payload.layout as { installDirs: string[] };
    const providerRoot = layout.installDirs[0];
    if (!providerRoot) throw new Error('checkpoint layout lacks provider root');
    const staleDeps: JitLifecycleDeps = {
      ...w5.deps,
      lifecycleReader: {
        getLifecycleRecord: async (recordId) => {
          const stored = await w5.store.getRecord('lifecycle_record', recordId);
          if (!stored) return null;
          const payload = stored.payload as { provenance?: Record<string, unknown> };
          return {
            recordId: stored.recordId,
            revision: stored.revision,
            payload: {
              ...stored.payload,
              provenance: {
                ...payload.provenance,
                source: 'winget:https://stale.example.invalid/old-build.zip',
              },
            },
          };
        },
      },
    };
    const resumeRefusal = await refusalOf(
      resumeJitRemovalFromCheckpoint(
        lifecycleInput(
          STALE_TASK,
          'JIT_REMOVE_AFTER_VERIFIED_USE',
          runnerPath,
          inputPath,
          join(w5.taskOutputDir, 'out.txt'),
        ),
        staleDeps,
      ),
    );
    if (
      !/PROVENANCE_UNKNOWN|POLICY_BLOCKED/i.test(`${resumeRefusal.code} ${resumeRefusal.message}`)
    ) {
      throw new Error(
        `stale checkpoint not refused: ${resumeRefusal.code} ${resumeRefusal.message}`,
      );
    }
    if (!(await exists(providerRoot))) throw new Error('provider deleted despite stale checkpoint');
    return `${resumeRefusal.code}; provider retained`;
  });

  // ---- G: raw external winget uninstall stays refused ----
  await scenario(
    'G',
    'raw external WinGet uninstall refuses FAILED_BEFORE_EFFECT with zero uninstall invocations',
    async () => {
      const world = makeManagedWorld({ evidenceDir, scenarioName: 'g-external' });
      const candidate = await world.acquisition.resolveExact({ packageId: PACKAGE_ID });
      const anyRoot = join(evidenceDir, 'g-external', 'pretend-root');
      const action = uninstallAction({
        actionId: 'i50-r6-external-uninstall',
        bindingId: BINDING_ID,
        packageId: PACKAGE_ID,
        version: candidate.version,
        deleteRoots: [anyRoot],
        deletionManifest: [join(anyRoot, 'app.exe')],
        elevated: false,
        timeoutMs: 60_000,
      });
      const plan = buildActionPlan({
        taskId: 'i50-r6-external',
        capabilityId: CAPABILITY_ID,
        bindingId: BINDING_ID,
        rankingPolicyRevision: 'rank-v1',
        policySnapshotRevision: 'pol-snap-r1',
        action,
        verificationPlan: { verifierId: 'v', verifierRevision: 'r1', checks: [{ checkId: 'c1' }] },
        recoveryPlan: {
          classificationStrategy: 'JOURNAL_AND_POST_STATE',
          reconcileBeforeRetry: true,
          retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
        },
      });
      await world.authority.ledger.register(plan);
      const grant = await world.authority.issue({
        taskId: plan.taskId,
        planHash: plan.planHash,
        policySnapshotRevision: plan.policySnapshotRevision,
        actionScope: {
          actionIds: [action.actionId],
          privilegeLevel: 'USER',
          filesystem: { read: [anyRoot], write: [anyRoot] },
        },
        authorizationKind: 'AUTOMATIC',
      });
      const backend = new WingetPrivilegedBackend({
        authority: world.authority,
        clock: now,
        journals: (actionId) =>
          new FileJournal(join(evidenceDir, 'g-external', 'journals', `${actionId}.jsonl`)),
        process: world.watchedProcess,
        fs: new NodeFilesystem(),
        machineScope: false,
      });
      const receipt = await backend.execute(
        {
          taskId: plan.taskId,
          actionId: action.actionId,
          planHash: plan.planHash,
          policySnapshotRevision: plan.policySnapshotRevision,
          authorizationKind: 'AUTOMATIC',
          authorizationRef: grant.grantId,
          expiresAt: grant.expiresAt,
          action,
        },
        grant,
      );
      if (receipt.terminal !== 'REFUSED') throw new Error(`terminal: ${receipt.terminal}`);
      if (receipt.sideEffectEvidence.recoveryClassification !== 'FAILED_BEFORE_EFFECT') {
        throw new Error(`classification: ${receipt.sideEffectEvidence.recoveryClassification}`);
      }
      const entries = await new FileJournal(
        join(evidenceDir, 'g-external', 'journals', `${action.actionId}.jsonl`),
      ).replay();
      const phases = entries.map((entry) => entry.phase);
      if (phases.includes('EXEC_START')) throw new Error('journal reached EXEC_START');
      if (world.watchedProcess.uninstallInvoked)
        throw new Error('a raw winget uninstall was spawned');
      if ((await sha256File(runnerPath)) !== runnerHash) throw new Error('canary mutated');
      return `REFUSED / FAILED_BEFORE_EFFECT; journal ${phases.join('→')}; zero uninstall spawns`;
    },
  );

  // ---- H: native adversarial suite re-run at evidence time ----
  await scenario(
    'H',
    'full win32 native adversarial suite re-run (junction storms, bombs, races)',
    async () => {
      const suite = spawn(
        process.execPath,
        [
          join(PACKAGE_DIR, 'node_modules', 'vitest', 'vitest.mjs'),
          'run',
          'test/native-safety.win.test.ts',
          '--reporter=basic',
        ],
        { cwd: PACKAGE_DIR, shell: false },
      );
      let out = '';
      suite.stdout.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
      suite.stderr.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
      const code = await new Promise<number>((resolveCode) => suite.on('close', resolveCode));
      await writeFile(join(evidenceDir, 'h-native-suite.log'), out, 'utf8');
      if (code !== 0 || !out.includes('20 passed')) {
        throw new Error(`native adversarial suite failed (exit ${code}) — see h-native-suite.log`);
      }
      return 'native-safety.win.test.ts: 20 passed (h-native-suite.log)';
    },
  );

  const report = {
    claim: 'SHUN_I50_PR51_BEB259F_WIN_NATIVE_HANDLE_SAFETY_R6',
    host: {
      os: `Windows ${osRelease()}`,
      arch: process.arch,
      node: process.version,
      winget: wingetVersion,
      powershell: psVersion,
      elevated: isElevated(),
    },
    package: PACKAGE_ID,
    resolvedVersion,
    results,
    allPassed: results.every((result) => result.status === 'PASS'),
    finishedAt: now(),
  };
  await writeFile(join(evidenceDir, 'report.json'), JSON.stringify(report, null, 2), 'utf8');
  console.log('');
  for (const result of results) {
    console.log(`${result.status}  ${result.id}  ${result.detail ?? result.error ?? ''}`);
  }
  console.log(`\nALL_PASS=${report.allPassed}`);
  process.exitCode = report.allPassed ? 0 : 1;
}

await main();
