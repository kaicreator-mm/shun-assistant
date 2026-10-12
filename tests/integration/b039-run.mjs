// T10 B-039: shared Resolver -> real ActionController -> real storage vertical -> T09 observation.
// Candidate-side code reads only T09 public inputs and the visible workspace; hidden oracle data is never consumed.
import { execFile } from 'node:child_process';
import { access, mkdir, readFile, readdir, realpath, statfs, writeFile } from 'node:fs/promises';
import { availableParallelism, totalmem } from 'node:os';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import {
  ActionController,
  AuthorizationAuthority,
} from '../../packages/authorization/src/index.ts';
import {
  ShunRegistry,
  resolveGoal,
  snapshotFactsRevision,
} from '../../packages/resolver/src/index.ts';
import {
  DISPOSABLE_SEGMENT_MARKERS,
  runStorageDiagnose,
} from '../../packages/vertical-storage/src/index.ts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '../../packages/store/src/index.ts';

const execFileAsync = promisify(execFile);
export const REPORT_CASE = 'B-039';
export const CANDIDATE_ROOT = 'candidate/B-039';
const POLICY_REVISION = 't10-storage-policy-v1';
const ISSUANCE_SECRET = 't10-b039-controller-issuance';
const INTEGRITY_SECRET = 't10-b039-controller-integrity';

function scoped(root, target) {
  const rel = relative(root, target);
  return rel.length > 0 && rel.split(/[\\/]/)[0] !== '..' && !isAbsolute(rel);
}

function fixtureRelative(root, target) {
  const rel = relative(root, target);
  if (!rel || rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) {
    throw new Error('B039_PATH_OUTSIDE_FIXTURE');
  }
  return rel.replaceAll('\\', '/');
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

async function hostFacts(root) {
  if (process.platform !== 'win32') throw new Error('B039_REAL_WINDOWS_REQUIRED');
  const disk = await statfs(root);
  const arch = process.arch === 'arm64' ? 'ARM64' : process.arch === 'x64' ? 'X64' : null;
  if (!arch) throw new Error(`B039_ARCH_UNSUPPORTED: ${process.arch}`);
  return {
    environmentId: `t10-b039-local-windows-${process.arch}`,
    backendKind: 'LOCAL_WINDOWS',
    os: `WINDOWS-${process.getSystemVersion?.() ?? 'unknown'}`,
    arch,
    observationRevision: `t10-b039-host-${Date.now()}`,
    runtimeCapabilities: ['windows-storage-metadata'],
    privilegeMode: await detectPrivilegeMode(),
    guiSession: true,
    filesystemCapabilities: ['read', 'write'],
    networkPolicy: 'OFFLINE',
    resources: {
      cpuCores: Math.max(1, availableParallelism()),
      memoryMb: Math.max(1, Math.floor(totalmem() / (1024 * 1024))),
      freeDiskMb: Math.max(0, Math.floor(Number(disk.bavail * disk.bsize) / (1024 * 1024))),
    },
  };
}

export async function resolveStorageForB039(facts, goal = 'identify growth and preview a bounded cache cleanup') {
  const capability = {
    capabilityId: 'system.storage.diagnose_bounded_action',
    revision: 'r1',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    sideEffectClass: 'R0',
    allowedInterfaceClasses: ['I0'],
    verificationContract: {
      verifierId: 'verifier.storage-c003',
      verifierRevision: 'r1',
      checks: [
        { checkId: 'protected-assets-unchanged', required: true },
        { checkId: 'reclaimed-bytes-verified', required: true },
      ],
    },
    requiredPolicyFacts: [],
  };
  const provider = {
    providerId: 'storage.cleaner.local-windows',
    revision: '0.1.0',
    acquisition: {
      mechanism: 'PREINSTALLED',
      source: '@shun/vertical-storage',
      official: true,
      version: '0.1.0',
    },
    provenanceFacts: { trustState: 'TRUSTED' },
    licenseFacts: { license: 'INTERNAL' },
    supportedPlatforms: [{ os: 'WINDOWS', arch: facts.arch }],
    lifecycle: { supportedOperations: ['CONFIGURE'] },
    interfaces: [{
      interfaceId: 'storage-local-i0',
      interfaceClass: 'I0',
      invocation: '@shun/vertical-storage runStorageDiagnose',
    }],
  };
  const binding = {
    bindingId: 'binding/shun-storage-local-windows',
    providerId: provider.providerId,
    capabilityId: capability.capabilityId,
    capabilityRevisionRange: { min: capability.revision, max: capability.revision },
    adapterId: 'adapter.storage.local-windows',
    interfaceClass: 'I0',
    environmentRequirements: {
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      networkAccess: 'FORBIDDEN',
    },
    verifierId: capability.verificationContract.verifierId,
  };
  const snapshot = {
    capabilities: [capability],
    providers: [provider],
    bindings: [binding],
    environment: facts,
  };
  const registry = await ShunRegistry.fromAttestedSnapshot(snapshot, {
    currentnessAuthority: { currentRevision: async () => snapshotFactsRevision(snapshot) },
    additionalObjectiveMatchers: {
      'system.storage.diagnose_bounded_action': [/\bsystem\.storage\.diagnose_bounded_action\b/i, /bounded cache cleanup/i],
    },
  });
  const result = resolveGoal({
    request: {
      taskId: 't10-b039',
      goal: `system.storage.diagnose_bounded_action: ${goal}`,
      objects: [{ kind: 'DIRECTORY', ref: 'T09_PUBLIC_B039_WORKSPACE' }],
      constraints: { other: { offline: true, boundedCleanup: true } },
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    },
    registry,
    objectExists: () => true,
  });
  if (result.stage !== 'RESOLUTION' || !result.record.selectedBindingId) {
    throw new Error('B039_SHARED_RESOLUTION_FAILED');
  }
  return result.record;
}

export async function makeDurableControllerWorld(approved, databaseFile) {
  // The T10 candidate uses the concrete durable SQLite adapter, not Map/Set
  // policy or grants. The fixture approval remains test-owned (not a UI claim).
  const store = new ShunStore({ file: databaseFile });
  let state;
  try {
    state = new ShunStoreAuthorizationAdapter(store);
    // Never overwrite an existing authority/policy/issued grant on a second
    // invocation: doing so could resurrect a revoked identity after restart.
    // Even a half-initialized database is NOT a virgin authority.
    const priorAuthority = await state.loadAuthorityRecord();
    const priorPolicy = await state.loadCurrentPolicy();
    if (priorAuthority !== null || priorPolicy !== null || await state.hasAnyGrant()) {
      throw new Error('B039_DURABLE_STATE_RESEED_REFUSED');
    }
    const authorityInserted = await state.compareAndSaveAuthorityRecord({
      authorityId: 'shun.t10.storage',
      authorityRevision: 'auth-b039-1',
      policyInitialized: true,
      priorAuthorityRevisions: [],
      updatedAt: new Date().toISOString(),
    }, null);
    if (!authorityInserted) throw new Error('B039_DURABLE_AUTHORITY_INIT_RACE');
    const policyInserted = await state.compareAndSavePolicySnapshot({
      policySnapshotRevision: POLICY_REVISION,
      status: 'ACTIVE',
      authorityId: 'shun.t10.storage',
      authorityRevision: 'auth-b039-1',
      revokedGrantIds: [],
      priorRevisions: [],
      rules: [],
      riskGuards: [],
      updatedAt: new Date().toISOString(),
    }, null);
    if (!policyInserted) throw new Error('B039_DURABLE_POLICY_INIT_RACE');
  } catch (error) {
    await store.close();
    throw error;
  }
  const clock = () => new Date().toISOString();
  const authority = new AuthorizationAuthority({
    state, grants: state, integritySecret: INTEGRITY_SECRET,
    issuanceSecret: ISSUANCE_SECRET, clock,
  });
  const approvals = {
    requests: [],
    async requestApproval(request) {
      approvals.requests.push(structuredClone(request));
      return {
        approvalId: 't10-b039-explicit-approval',
        taskId: request.taskId, planHash: request.planHash,
        approved, approvedBy: 'USER_APPROVAL',
      };
    },
  };
  const controller = new ActionController({
    authority, policyState: state, approvals,
    issuanceSecret: ISSUANCE_SECRET, clock,
  });
  return { controller, approvals, authority, state, store, clock };
}

async function loadPublic(root) {
  const raw = JSON.parse(await readFile(join(root, 'public/capability-inputs.json'), 'utf8'));
  const entry = raw?.[REPORT_CASE];
  if (
    entry?.capability_id !== 'system.storage.diagnose_bounded_action' ||
    typeof entry?.workspace !== 'string' ||
    typeof entry?.goal !== 'string'
  ) {
    throw new Error('B039_PUBLIC_INPUT_MISMATCH');
  }
  return entry;
}

async function directChildDirectories(workspace) {
  const entries = await readdir(workspace, { withFileTypes: true });
  const dirs = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const candidate = await realpath(join(workspace, entry.name));
    dirs.push(candidate);
  }
  return dirs;
}

function basenameIsDisposable(dir) {
  const name = basename(dir).toLowerCase();
  return DISPOSABLE_SEGMENT_MARKERS.includes(name);
}

async function listFiles(root, dir, out = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) await listFiles(root, p, out);
    else if (entry.isFile()) out.push(fixtureRelative(root, p));
  }
  return out;
}

async function freeBytes(path) {
  const fs = await statfs(path);
  return Number(fs.bavail * fs.bsize);
}

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export function deriveEvidenceEvents(result) {
  const observationRef = result.output.attribution.evidenceRefs.find((ref) =>
    ref.includes('observation-'),
  );
  if (!observationRef) throw new Error('B039_OBSERVATION_EVIDENCE_MISSING');
  if (!result.output.attribution.growthSourcePath) {
    throw new Error('B039_ATTRIBUTION_EVIDENCE_MISSING');
  }
  if (!result.proposal || result.proposal.targets.length === 0) {
    throw new Error('B039_CLASSIFICATION_OR_PLAN_MISSING');
  }
  if (!result.preview || result.preview.trim().length === 0) {
    throw new Error('B039_PREVIEW_MISSING');
  }
  const expectedGate = ['PLAN', 'PREVIEW', 'CHECKPOINT', 'APPROVAL', 'EXECUTE', 'VERIFY'];
  const actualGate = result.output.cleanupPlan?.r2Gate.phases ?? [];
  if (actualGate.join('>') !== expectedGate.join('>')) {
    throw new Error('B039_R2_GATE_SEQUENCE_MISMATCH');
  }
  if (
    result.receipts.length === 0 ||
    result.receipts.some((receipt) => receipt.terminal !== 'SUCCEEDED')
  ) {
    throw new Error('B039_EXECUTION_RECEIPT_NOT_SUCCEEDED');
  }
  if (
    result.output.protectedAssetVerification.length === 0 ||
    result.output.protectedAssetVerification.some((entry) => entry.unchanged !== true) ||
    !result.output.reclaimed
  ) {
    throw new Error('B039_SEMANTIC_VERIFICATION_EVIDENCE_MISSING');
  }
  return [
    { phase: 'observe', evidence_ref: observationRef },
    { phase: 'attribute', evidence_ref: result.output.attribution.evidenceRefs[0] },
    { phase: 'classify', target_count: result.proposal.targets.length },
    { phase: 'plan', plan_hash: result.proposal.plan.planHash },
    { phase: 'preview', preview_present: true },
    {
      phase: 'approval_or_durable_policy',
      approved_by: result.output.cleanupPlan.r2Gate.approvedBy,
    },
    { phase: 'execute', receipt_count: result.receipts.length },
    { phase: 'verify', protected_assets_unchanged: true },
  ];
}

export function refineGrowthFile(root, result) {
  const attributed = resolve(result.output.attribution.growthSourcePath);
  const target = result.proposal?.checkpoint.targets.find(
    (candidate) => resolve(candidate.path).toLowerCase() === attributed.toLowerCase(),
  );
  if (!target || target.files.length === 0) throw new Error('B039_GROWTH_FILE_EVIDENCE_MISSING');
  const sorted = [...target.files].sort((a, b) => b.sizeBytes - a.sizeBytes);
  if (sorted.length > 1 && sorted[0].sizeBytes === sorted[1].sizeBytes) {
    throw new Error('B039_GROWTH_FILE_AMBIGUOUS');
  }
  return fixtureRelative(root, sorted[0].path);
}

export async function runB039({ fixtureRoot, observationFile, approve = false }) {
  if (process.platform !== 'win32') throw new Error('B039_REAL_WINDOWS_REQUIRED');
  if (approve !== true) throw new Error('B039_EXPLICIT_APPROVAL_REQUIRED');
  const root = await realpath(resolve(fixtureRoot));
  const observation = resolve(observationFile);
  if (scoped(root, observation)) throw new Error('B039_OBSERVATION_MUST_BE_OUTSIDE_FIXTURE_ROOT');

  const publicEntry = await loadPublic(root);
  const workspace = await realpath(resolve(root, publicEntry.workspace));
  if (!scoped(root, workspace)) throw new Error('B039_WORKSPACE_SCOPE_REFUSED');
  const facts = await hostFacts(workspace);
  const resolution = await resolveStorageForB039(facts, publicEntry.goal);
  if (
    resolution.selectedBindingId !== 'binding/shun-storage-local-windows' ||
    resolution.privacyDisclosurePlan.externalDisclosure !== 'FORBIDDEN' ||
    resolution.hardGateDispositions.some((row) => row.outcome !== 'PASS')
  ) {
    throw new Error('B039_RESOLVER_HARD_GATE_FAILED');
  }

  const children = await directChildDirectories(workspace);
  const protectedDirs = children.filter((dir) => !basenameIsDisposable(dir));
  if (protectedDirs.length === 0) throw new Error('B039_NO_CONSERVATIVE_PROTECTED_SCOPE');
  const protectedFiles = [];
  for (const dir of protectedDirs) await listFiles(root, dir, protectedFiles);

  const candidateEvidence = resolve(root, CANDIDATE_ROOT, 'evidence');
  if (!scoped(root, candidateEvidence)) throw new Error('B039_EVIDENCE_SCOPE_REFUSED');
  await mkdir(candidateEvidence, { recursive: true });
  const world = await makeDurableControllerWorld(true, join(candidateEvidence, 'authorization.sqlite'));
  try {
  const before = await freeBytes(workspace);
  const result = await runStorageDiagnose(
    {
      controller: world.controller,
      scope: { roots: [workspace] },
      evidenceDir: candidateEvidence,
      policySnapshotRevision: POLICY_REVISION,
      rankingPolicyRevision: resolution.resolverRevision ?? 't10-resolver',
      environmentId: facts.environmentId,
      providerId: 'storage.cleaner.local-windows',
      providerVersion: '0.1.0',
      clock: world.clock,
    },
    {
      taskId: 't10-b039',
      targetVolume: workspace.slice(0, 2).toUpperCase(),
      protectedAssets: protectedDirs.map((path) => ({ path })),
      cleanupPolicy: { eligibleCategories: ['CACHE'] },
    },
  );
  if (!(await world.state.hasAnyGrant())) {
    throw new Error('B039_DURABLE_AUTHORIZATION_GRANT_MISSING');
  }
  const after = await freeBytes(workspace);
  if (!result.output.cleanupPlan || !result.output.reclaimed || !result.proposal) {
    throw new Error('B039_CLEANUP_DID_NOT_EXECUTE');
  }

  const classified = {};
  const checkpointFiles = result.proposal.checkpoint.targets.flatMap((target) => target.files);
  for (const file of checkpointFiles) {
    classified[fixtureRelative(root, file.path)] = 'disposable_cache';
  }
  for (const rel of protectedFiles) classified[rel] = 'protected';

  const deletedPaths = [];
  for (const file of checkpointFiles) {
    if (!(await pathExists(file.path))) deletedPaths.push(fixtureRelative(root, file.path));
  }
  if (deletedPaths.length === 0) throw new Error('B039_NO_VERIFIABLE_DELETION');

  const observedGrowthSource = refineGrowthFile(root, result);
  const approvalKind =
    result.output.cleanupPlan.r2Gate.approvedBy === 'DURABLE_POLICY'
      ? 'pre_existing_durable_policy'
      : 'explicit_approval';
  const journalRef = result.output.executionEvidence?.sideEffectEvidence.journalRef;
  if (!journalRef) throw new Error('B039_MEASUREMENT_EVIDENCE_MISSING');

  const payload = {
    observed_growth_source: observedGrowthSource,
    events: deriveEvidenceEvents(result),
    classifications: classified,
    deleted_paths: deletedPaths,
    approval: { kind: approvalKind, scope: 'classified_disposable_cache_only' },
    measured_reclaimed_bytes: result.output.reclaimed.grossBytes,
    free_bytes_before: before,
    free_bytes_after: after,
    measurement_evidence_ref: journalRef,
    cache_recreated_bytes: result.output.reclaimed.postActionStateBytes,
    provider_selection: {
      selected_binding_id: resolution.selectedBindingId,
      hard_gates: resolution.hardGateDispositions,
    },
    authority_integration: {
      action_controller: true,
      per_effect_currentness: true,
      durable_state: 'REAL_SHUNSTORE_SQLITE_AUTHORIZATION_ADAPTER',
    },
    real_host_validation: 'NOT_RUN',
    fixture_oracle_status: 'NOT_RUN',
  };
  await writeFile(observation, `${JSON.stringify(payload, null, 2)}\n`, { flag: 'wx' });
  return { observation, observedGrowthSource, deletedPaths };
  } finally {
    await world.store.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = new Map();
  let approve = false;
  for (let index = 2; index < process.argv.length; index += 1) {
    const token = process.argv[index];
    if (token === '--approve') {
      approve = true;
      continue;
    }
    const value = process.argv[index + 1];
    if (!value) break;
    args.set(token, value);
    index += 1;
  }
  const fixtureRoot = args.get('--root');
  const observationFile = args.get('--observation');
  if (!fixtureRoot || !observationFile || args.size !== 2) {
    console.error('Usage: node tests/integration/b039-run.mjs --root <verified+injected T09 root> --observation <external new JSON> --approve');
    process.exitCode = 2;
  } else {
    try {
      console.log(JSON.stringify(await runB039({ fixtureRoot, observationFile, approve })));
    } catch (error) {
      console.error(error instanceof Error ? error.message : 'B039_ADAPTER_FAILED');
      process.exitCode = 1;
    }
  }
}
