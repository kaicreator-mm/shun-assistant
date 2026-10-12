// T10 B-037: shared Resolver -> real sharp vertical -> T09 observation adapter.
// Test-owned integration surface only; never imports T09 private/gold.
import { execFile } from 'node:child_process';
import { availableParallelism, totalmem } from 'node:os';
import { promisify } from 'node:util';
import { basename, extname, isAbsolute, join, relative, resolve } from 'node:path';
import { mkdir, readFile, realpath, statfs, writeFile } from 'node:fs/promises';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { ShunRegistry, resolveGoal, snapshotFactsRevision } from '../../packages/resolver/src/index.ts';
import {
  makeSharpImageProvider,
  runImageBatchProcess,
  sharpBindingView,
} from '../../packages/vertical-image/src/index.ts';

const execFileAsync = promisify(execFile);
export const REPORT_CASE = 'B-037';
export const OUTPUT_RELATIVE = 'candidate/B-037';

export function buildObservationPayload({ outputs, selectedBindingId, hardGateEvidence }) {
  return {
    outputs,
    provider_selection: {
      selected_binding_id: selectedBindingId,
      hard_gates_evidence: [...hardGateEvidence],
    },
    real_host_validation: 'NOT_RUN',
    fixture_oracle_status: 'NOT_RUN',
  };
}

function scoped(root, target) {
  const rel = relative(root, target);
  return rel.length > 0 && rel.split(/[\\/]/)[0] !== '..' && !isAbsolute(rel);
}

async function detectPrivilegeMode() {
  const whoami = String.raw`C:\Windows\System32\whoami.exe`;
  const { stdout } = await execFileAsync(whoami, ['/groups', '/fo', 'csv', '/nh'], {
    windowsHide: true,
    encoding: 'utf8',
    timeout: 15_000,
  });
  if (/S-1-16-12288/i.test(stdout)) return 'ELEVATED_ADMIN';
  if (/S-1-5-32-544/i.test(stdout)) return 'FILTERED_ADMIN';
  return 'STANDARD_USER';
}

function formatOf(path) {
  const ext = extname(path).toLowerCase();
  if (ext === '.jpg' || ext === '.jpeg') return 'JPG';
  if (ext === '.png') return 'PNG';
  throw new Error(`B037_UNSUPPORTED_PUBLIC_OBJECT: ${path}`);
}

async function hostFacts(root) {
  if (process.platform !== 'win32') throw new Error('B037_REAL_WINDOWS_REQUIRED');
  const disk = await statfs(root);
  const freeDiskMb = Math.floor(Number(disk.bavail * disk.bsize) / (1024 * 1024));
  const arch = process.arch === 'arm64' ? 'ARM64' : process.arch === 'x64' ? 'X64' : null;
  if (!arch) throw new Error(`B037_ARCH_UNSUPPORTED: ${process.arch}`);
  return {
    environmentId: `t10-b037-local-windows-${process.arch}`,
    backendKind: 'LOCAL_WINDOWS',
    os: `WINDOWS-${process.getSystemVersion?.() ?? 'unknown'}`,
    arch,
    observationRevision: `t10-b037-host-${Date.now()}`,
    runtimeCapabilities: ['sharp-libvips'],
    privilegeMode: await detectPrivilegeMode(),
    guiSession: true,
    filesystemCapabilities: ['read', 'write'],
    networkPolicy: 'OFFLINE',
    resources: {
      cpuCores: Math.max(1, availableParallelism()),
      memoryMb: Math.max(1, Math.floor(totalmem() / (1024 * 1024))),
      freeDiskMb: Math.max(0, freeDiskMb),
    },
  };
}

export async function resolveSharpForB037(facts) {
  const sharp = sharpBindingView();
  const capability = {
    capabilityId: 'image.batch_process',
    revision: 'r1',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    sideEffectClass: 'R1',
    allowedInterfaceClasses: ['I0'],
    verificationContract: {
      verifierId: sharp.verifierId,
      verifierRevision: 'c001-v0.1',
      checks: [{ checkId: 'image-semantic-oracle', required: true }],
    },
    requiredPolicyFacts: [],
  };
  const provider = {
    providerId: sharp.providerId,
    revision: sharp.providerVersion,
    acquisition: {
      mechanism: 'PREINSTALLED',
      source: 'workspace dependency: sharp/libvips',
      official: true,
      version: sharp.providerVersion,
    },
    provenanceFacts: {
      trustState: 'TRUSTED',
      formatSupport: ['JPG', 'PNG'],
    },
    licenseFacts: { license: 'Apache-2.0' },
    supportedPlatforms: [{ os: 'WINDOWS', arch: facts.arch }],
    lifecycle: { supportedOperations: ['CONFIGURE'] },
    interfaces: [{
      interfaceId: 'sharp-i0',
      interfaceClass: 'I0',
      invocation: '@shun/vertical-image makeSharpImageProvider.resizeTo',
    }],
  };
  const binding = {
    bindingId: sharp.bindingId,
    providerId: sharp.providerId,
    capabilityId: capability.capabilityId,
    capabilityRevisionRange: { min: capability.revision, max: capability.revision },
    adapterId: sharp.adapterId,
    interfaceClass: sharp.interfaceClass,
    environmentRequirements: {
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      networkAccess: 'FORBIDDEN',
    },
    verifierId: sharp.verifierId,
  };
  const snapshot = {
    capabilities: [capability],
    providers: [provider],
    bindings: [binding],
    environment: facts,
  };
  const registry = await ShunRegistry.fromAttestedSnapshot(snapshot, {
    currentnessAuthority: { currentRevision: async () => snapshotFactsRevision(snapshot) },
  });
  const request = {
    taskId: 't10-b037',
    goal: 'image.batch_process: resize images, preserve capture date',
    objects: [{ kind: 'DIRECTORY', ref: 'T09_PUBLIC_B037_OBJECT_SET' }],
    constraints: { other: { offline: true } },
    policyContext: {
      privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    },
  };
  const result = resolveGoal({ request, registry, objectExists: () => true });
  if (result.stage !== 'RESOLUTION' || !result.record.selectedBindingId) {
    throw new Error('B037_SHARED_RESOLUTION_FAILED');
  }
  return result.record;
}

async function loadPublic(root) {
  const raw = JSON.parse(await readFile(join(root, 'public/capability-inputs.json'), 'utf8'));
  const entry = raw?.[REPORT_CASE];
  if (
    entry?.capability_id !== 'image.batch_process' ||
    entry?.constraints?.local_only !== true ||
    entry?.constraints?.output_separate !== true ||
    entry?.constraints?.max_long_edge_px !== 1600 ||
    !Array.isArray(entry?.objects) ||
    entry.objects.length !== 200
  ) {
    throw new Error('B037_PUBLIC_INPUT_MISMATCH');
  }
  return entry;
}

export async function runB037({ fixtureRoot, observationFile }) {
  const root = await realpath(resolve(fixtureRoot));
  const observation = resolve(observationFile);
  if (scoped(root, observation)) throw new Error('B037_OBSERVATION_MUST_BE_OUTSIDE_FIXTURE_ROOT');
  const publicEntry = await loadPublic(root);
  const facts = await hostFacts(root);
  const resolution = await resolveSharpForB037(facts);
  const hardGateEvidence = resolution.hardGateDispositions.map(
    (row) => `${row.gate}:${row.bindingId}:${row.outcome}:${row.reason}`,
  );
  if (
    resolution.privacyDisclosurePlan.externalDisclosure !== 'FORBIDDEN' ||
    hardGateEvidence.length === 0 ||
    hardGateEvidence.some((row) => !row.includes(':PASS:'))
  ) {
    throw new Error('B037_RESOLVER_HARD_GATE_FAILED');
  }

  const outputDir = resolve(root, OUTPUT_RELATIVE);
  if (!scoped(root, outputDir)) throw new Error('B037_OUTPUT_SCOPE_REFUSED');
  const inputFiles = [];
  for (const rel of publicEntry.objects) {
    if (typeof rel !== 'string') throw new Error('B037_PUBLIC_OBJECT_INVALID');
    const absolute = resolve(root, rel);
    if (!scoped(root, absolute)) throw new Error('B037_INPUT_SCOPE_REFUSED');
    const actual = await realpath(absolute);
    if (!scoped(root, actual)) throw new Error('B037_INPUT_REALPATH_ESCAPE');
    inputFiles.push({ path: actual, format: formatOf(actual) });
  }
  await mkdir(outputDir, { recursive: true });

  const result = await runImageBatchProcess(
    {
      taskId: 't10-b037',
      inputFiles,
      operation: { kind: 'RESIZE', maxLongEdgePx: 1600 },
      metadataPolicy: { preserveCaptureDate: true },
      outputDirectory: outputDir,
      qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1', ssimThreshold: 0.95 },
      networkUsage: 'LOCAL_ONLY',
    },
    {
      facts,
      providers: [makeSharpImageProvider()],
      preferredBindingId: resolution.selectedBindingId,
    },
  );
  if (!result.ok) throw new Error(`B037_VERTICAL_FAILED: ${result.failure.code}`);
  if (
    result.output.selectedBindingId !== resolution.selectedBindingId ||
    result.output.verification.status !== 'PASS'
  ) {
    throw new Error('B037_VERTICAL_BINDING_OR_VERIFICATION_MISMATCH');
  }

  const outputs = {};
  for (const record of result.output.records) {
    if (record.status !== 'WRITTEN' || !record.outputPath) {
      throw new Error(`B037_RECORD_NOT_WRITTEN: ${record.inputPath}`);
    }
    const rel = relative(root, resolve(record.outputPath)).replaceAll('\\', '/');
    if (!rel.startsWith(`${OUTPUT_RELATIVE}/`)) throw new Error('B037_OUTPUT_ESCAPED_CANDIDATE_ROOT');
    outputs[basename(record.inputPath)] = rel;
  }
  if (Object.keys(outputs).length !== 200) throw new Error('B037_OUTPUT_COUNT_MISMATCH');

  const observationPayload = buildObservationPayload({
    outputs,
    selectedBindingId: resolution.selectedBindingId,
    hardGateEvidence,
  });
  await writeFile(observation, `${JSON.stringify(observationPayload, null, 2)}\n`, { flag: 'wx' });
  return { observation, selectedBindingId: resolution.selectedBindingId };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = new Map();
  for (let index = 2; index + 1 < process.argv.length; index += 2) {
    args.set(process.argv[index], process.argv[index + 1]);
  }
  const fixtureRoot = args.get('--root');
  const observationFile = args.get('--observation');
  if (!fixtureRoot || !observationFile || args.size !== 2) {
    console.error('Usage: node tests/integration/b037-run.mjs --root <verified T09 root> --observation <external new JSON>');
    process.exitCode = 2;
  } else {
    try {
      console.log(JSON.stringify(await runB037({ fixtureRoot, observationFile })));
    } catch (error) {
      console.error(error instanceof Error ? error.message : 'B037_ADAPTER_FAILED');
      process.exitCode = 1;
    }
  }
}
