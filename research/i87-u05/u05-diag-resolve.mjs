// Diagnose which resolveBinding step fails: replicates the backend sequence
// with the same repo source (the staging bundle is built from it).
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { availableParallelism, release, totalmem } from 'node:os';
import * as path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../../packages/contracts/src/index.ts';
import { resolveGoal, ShunRegistry } from '../../packages/resolver/src/index.ts';
import { assertSignedHostFactsCurrent } from '../../apps/control-api/src/real-storage/registry-host-facts.ts';
import { verifyRegistryIssuance } from '../../apps/control-api/src/real-storage/registry-issuance.ts';
import { createStorageRegistrySnapshot } from '../../apps/control-api/src/real-storage/registry-snapshot.ts';
import { verifyPinnedRegistryPublicKey } from '../../apps/control-api/src/real-storage/registry-key-pin.ts';
import { readJson } from './u05-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKTREE = path.resolve(HERE, '..', '..');
const sandbox = process.argv[2];
const execFileAsync = promisify(execFile);
const CAPABILITY = 'system.storage.diagnose_bounded_action';
const BINDING = 'binding/shun-storage-local-windows';

const step = (name, fn) =>
  Promise.resolve()
    .then(fn)
    .then(
      (v) => {
        console.log(`[OK] ${name}`, v === undefined ? '' : JSON.stringify(v).slice(0, 300));
        return v;
      },
      (e) => {
        console.log(`[THROW] ${name}: ${e.message}`);
        throw e;
      },
    );

const env = await readJson(path.join(sandbox, 'env.json'));
const workspace = env.SHUN_REAL_STORAGE_ROOT;
const clock = () => new Date().toISOString();

const rawJson = await fs.readFile(env.SHUN_REGISTRY_CURRENTNESS_FILE, 'utf8');
const keyPem = await fs.readFile(env.SHUN_REGISTRY_PUBLIC_KEY_FILE, 'utf8');

await step('pin', () => verifyPinnedRegistryPublicKey(keyPem, env.SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256));
const signed = await step('verify-issuance', () =>
  verifyRegistryIssuance(JSON.parse(rawJson), keyPem, workspace, clock()),
);

const stats = await fs.statfs(workspace);
const arch = process.arch === 'x64' ? 'X64' : process.arch === 'arm64' ? 'ARM64' : null;
const { stdout } = await execFileAsync('C:\\Windows\\System32\\whoami.exe', ['/groups', '/fo', 'csv', '/nh'], {
  windowsHide: true,
  encoding: 'utf8',
  timeout: 15_000,
});
const privilegeMode = /S-1-16-12288/i.test(stdout)
  ? 'ELEVATED_ADMIN'
  : /S-1-5-32-544/i.test(stdout)
    ? 'FILTERED_ADMIN'
    : 'STANDARD_USER';
const observed = {
  environmentId: 'shun-real-storage-' + process.arch,
  backendKind: 'LOCAL_WINDOWS',
  os: `WINDOWS-${release()}`,
  arch,
  observationRevision: 'host-' + clock(),
  runtimeCapabilities: ['windows-storage-metadata'],
  privilegeMode,
  guiSession: true,
  filesystemCapabilities: ['read', 'write'],
  networkPolicy: 'OFFLINE',
  resources: {
    cpuCores: Math.max(1, availableParallelism()),
    memoryMb: Math.max(1, Math.floor(totalmem() / (1024 * 1024))),
    freeDiskMb: Math.max(0, Math.floor(Number(stats.bavail * stats.bsize) / (1024 * 1024))),
  },
};
console.log('observed:', JSON.stringify(observed));
console.log('issued.resources:', JSON.stringify(signed.snapshot.environment.resources));
await step('host-facts-current', () => assertSignedHostFactsCurrent(signed.snapshot.environment, observed));
// the backend rebuilds from the SIGNED environment (not the observation)
const snapshot = createStorageRegistrySnapshot(signed.snapshot.environment);
await step('fact-classes-match', () => {
  if (canonicalJson(snapshot) !== canonicalJson(signed.snapshot)) {
    throw new Error('REAL_STORAGE_REGISTRY_SIGNED_FACT_CLASSES_MISMATCH');
  }
});
await step('registry+resolve', async () => {
  const registry = await ShunRegistry.fromAttestedSnapshot(snapshot, {
    currentnessAuthority: {
      currentRevision: async () => (await import('node:fs')).readFileSync(env.SHUN_REGISTRY_CURRENTNESS_FILE, 'utf8') && signed.currentRevision,
    },
    additionalObjectiveMatchers: {
      [CAPABILITY]: [/bounded cache cleanup/i, /system\.storage\.diagnose_bounded_action/i],
    },
  });
  const result = resolveGoal({
    request: {
      taskId: 'u05-diag',
      goal: CAPABILITY + ': bounded cache cleanup of stale browser cache files',
      objects: [{ kind: 'DIRECTORY', ref: workspace }],
      constraints: { other: { offline: true, boundedCleanup: true } },
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    },
    registry,
    objectExists: () => true,
  });
  const summary = {
    stage: result.stage,
    binding: result.record.selectedBindingId,
    gates: result.record.hardGateDispositions.map((r) => `${r.gateId}:${r.outcome}`),
    disclosure: result.record.privacyDisclosurePlan.externalDisclosure,
  };
  if (
    result.stage !== 'RESOLUTION' ||
    result.record.selectedBindingId !== BINDING ||
    result.record.hardGateDispositions.some((row) => row.outcome !== 'PASS') ||
    result.record.privacyDisclosurePlan.externalDisclosure !== 'FORBIDDEN'
  ) {
    throw new Error('REAL_STORAGE_RESOLVER_HARD_GATES_FAILED ' + JSON.stringify(summary));
  }
  return summary;
});
console.log('ALL-RESOLVE-STEPS-PASS');
