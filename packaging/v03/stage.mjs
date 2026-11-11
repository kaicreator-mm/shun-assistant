// v0.3 portable stage builder (#407, ADS #1359 G1). Reuses the audited v0.2
// T09 mechanisms byte-identically: the signed-manifest verifier
// (scripts/package-v02/manifest.mjs) and the per-user lifecycle
// (packaging/windows-portable/lifecycle.mjs) are copied into the stage, not
// reimplemented. What is NEW here is the v0.3 closure: the real DomainHarness
// BUILD envelope assembled by the operator script, the installed public SDK
// consumer (runtime imports resolve from it), the pinned native broker/host
// binaries, the actual R04 desktop UI, a bundled Node24, and the per-user
// first-run provisioner + launcher generated below.
//
// Output is an UNSIGNED stage directory. Operator signing, distribution and
// Standard User Home/Pro qualification are separate mandatory gates; this
// script grants no authority by itself.
//
//   node packaging/v03/stage.mjs <absolute-empty-stage-dir>   (Windows x64, Node >= 24)
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
const native = join(repo, 'apps/control-api/native');
const RUNTIME_NODE_MAJOR = 24;
const BUILD_ID = 'shun-v0.3.0-portable-g1';
const TENANT_ID = 'tenant:shun-v03-portable';
const DEPLOYED_APP_ID = 'deployment:shun-v0.3.0-portable';
// The shipped operator Guided Case observation is long-lived relative to the
// 5-minute staged-step clamp; per-step validity is still enforced by the
// Host service at runtime.
export const CASE_VALIDITY_MS = 365n * 24n * 60n * 60n * 1000n;

export const STAGE_LAUNCH_ENV_KEYS = [
  'SHUN_CONTROL_MODE',
  'SHUN_CONTROL_UI_DIR',
  'SHUN_REAL_STORAGE_ROOT',
  'SHUN_REAL_STORAGE_PROTECTED',
  'SHUN_REAL_STORAGE_DATABASE',
  'SHUN_REGISTRY_CURRENTNESS_FILE',
  'SHUN_REGISTRY_PUBLIC_KEY_FILE',
  'SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256',
  'SHUN_REAL_STORAGE_EVIDENCE_DIR',
  'SHUN_CONTROLLER_ISSUANCE_SECRET',
  'SHUN_GRANT_INTEGRITY_SECRET',
  'SHUN_V03_GUIDED_DATABASE',
  'SHUN_V03_FOLDER_SELECTION_DATABASE',
  'SHUN_V03_GUIDED_CASE_FILE',
  'SHUN_V03_GUIDED_CASE_SHA256',
  'SHUN_V03_BUILD_FILE',
  'SHUN_V03_BUILD_SHA256',
  'SHUN_V03_SDK_CONSUMER_DIR',
  'SHUN_V03_KERNEL_DOC_DATABASE',
  'SHUN_V03_DEPLOYMENT_ROOT',
  'SHUN_V03_TENANT_ID',
  'SHUN_V03_DEPLOYED_APP_ID',
  'SHUN_V03_CLOUD_JOURNAL',
  'SHUN_V03_APPROVAL_LEDGER',
];

function fail(reason) {
  throw new Error(`SHUN_V03_STAGE_REFUSED:${reason}`);
}

function requireFile(path) {
  if (!existsSync(path)) fail(`REQUIRED_SOURCE_MISSING:${path}`);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail('REQUIRED_SOURCE_NOT_REGULAR');
  return path;
}

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function sha256Text(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function pinnedDigest(name, artifactsPath = join(native, 'artifacts.ts')) {
  const text = readFileSync(artifactsPath, 'utf8');
  const match = text.match(new RegExp(`export const ${name}\\s*=\\s*['"]([0-9a-f]{64})['"]`));
  if (!match) fail('NATIVE_PIN_UNAVAILABLE');
  return match[1];
}

/** Enforce the existing native folder-picker pin BEFORE any byte enters a signed stage. */
export function verifyFolderPickerSource(addonPath, artifactsPath) {
  const addon = requireFile(addonPath);
  if (sha256File(addon) !== pinnedDigest('FOLDER_PICKER_ADDON_SHA256', artifactsPath)) {
    fail('FOLDER_PICKER_PIN_MISMATCH');
  }
  return addon;
}

/**
 * Deterministic standard-module source, exactly the audited R02-E startup
 * composition: the pinned public SDK bundle plus the pinned router with its
 * export statements stripped into an IIFE re-export.
 */
export function standardBundleSource(sdkText, routerText) {
  const routerBody = routerText.replace(/^export /gm, '');
  return `${sdkText}
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

/**
 * Operator-pinned Guided Case bytes (host observation + selected semantic).
 * G3: the delivered case models the FIRST-RUN user state — the observation
 * carries NO selectedRootRef and scope is UNKNOWN, so the R04 journey opens
 * on shun.guided.select-root and the shipped desktop UI's native pick button
 * and the /api/v03/guided/select-root route are actually reachable for the
 * end user. A preselected build-time root made chooseTemplate skip straight
 * to inspect-scope and left the folder-select journey dead code in the
 * delivered bundle.
 */
export function mintGuidedCaseBytes({ buildId, nowMs, validityMs = CASE_VALIDITY_MS }) {
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/.test(buildId ?? '')) fail('CASE_BUILD_ID_INVALID');
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) fail('CASE_NOW_INVALID');
  const caseId = `task-${buildId}`;
  const semantic = {
    observation: {
      schema: 'shun.guided.host-observation.v1',
      taskId: caseId,
      journeyId: `journey-${buildId}`,
      sourceRef: `host:obs:${buildId}`,
      revision: buildId,
      caseRef: { snapshotId: `snap-${buildId}`, digest: 'e'.repeat(64) },
      observedAtUnixMs: nowMs - 1_000,
      validUntilUnixMs: nowMs + Number(validityMs),
      evidenceRefs: [`host:scope:${buildId}`],
    },
    semanticSelection: {
      status: 'SELECTED',
      semantic: {
        schema: 'shun.goal-semantic.v1',
        taskId: caseId,
        goalContract: { taskId: caseId, objective: 'summarize selected folder' },
        capabilityId: 'system.storage.diagnose_bounded_action',
        capabilityRevision: 'r1',
        provenance: { resolverRevision: 'resolver-v03' },
      },
    },
    scope: { status: 'UNKNOWN' },
  };
  return JSON.stringify(semantic, null, 2) + '\n';
}

/** The trusted BUILD spec handed to the real assembler (#407: no reimplementation). */
export function buildSpec({ kernelSource, standardSource, businessSource, capabilitySource, shaOf }) {
  const sha = shaOf ?? sha256Text;
  return {
    appId: 'shun-v03-goal',
    audience: 'operator-local',
    buildId: BUILD_ID,
    targetProfile: 'node24-esm/1',
    routes: [
      {
        intentId: 'goal-interpret',
        operationId: 'interpretGoal',
        capabilityId: 'llm',
        handlerId: 'interpretGoal',
      },
    ],
    hardBudget: { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 },
    modules: [
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: '__KERNEL_FILE__',
        sourceSha256: sha(kernelSource),
        module: {
          packageId: 'v08-kernel-mechanism@1.0.0',
          role: 'kernel-primary',
          abiVersion: 'v08-kernel-abi/1',
          endpoint: 'occurrence-runtime',
          dependencies: [],
          provides: ['kernel:occurrence-runtime/1'],
          requires: [],
        },
      },
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: '__STANDARD_FILE__',
        sourceSha256: sha(standardSource),
        module: {
          packageId: 'standard-sdk@v08.1.0.0',
          role: 'standard-primary',
          abiVersion: 'v08-standard-sdk-abi/1',
          endpoint: 'rule-interpreter',
          dependencies: [],
          provides: ['standard:interpret/1', 'standard:route/1'],
          requires: [],
        },
      },
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: '__BUSINESS_FILE__',
        sourceSha256: sha(businessSource),
        module: {
          packageId: 'shun.business.goal@v0.3.0',
          role: 'business',
          abiVersion: 'v08-business-abi/1',
          endpoint: 'business-policy',
          dependencies: [],
          provides: ['intent:goal-interpret'],
          requires: [],
        },
      },
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: '__CAPABILITY_FILE__',
        sourceSha256: sha(capabilitySource),
        module: {
          packageId: 'shun.capability.llm-openai-compatible@v0.3.0',
          role: 'capability',
          abiVersion: 'v08-capability-abi/1',
          endpoint: 'capability-endpoint',
          dependencies: [],
          externalImports: { node: [], npm: ['domain-harness-openai-host'], native: [] },
          provides: ['capability:llm/1'],
          requires: [],
          capabilityId: 'llm',
          externalEffect: true,
          handlers: [{ operationId: 'interpretGoal', handler: 'interpretGoal' }],
        },
      },
    ],
  };
}

/**
 * Re-verify the four public SDK tarballs against the committed SHA256SUMS
 * receipts even when the repo consumer is already installed, so the stage
 * never copies unpinned bytes.
 */
function verifySdkTarballReceipts(fixturesDir, names) {
  const receipts = new Map();
  for (const line of readFileSync(join(fixturesDir, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    if (match) receipts.set(match[2].trim(), match[1]);
  }
  for (const name of names) {
    const expected = receipts.get(name);
    if (!expected) fail(`SDK_RECEIPT_MISSING:${name}`);
    const actual = sha256File(join(fixturesDir, name));
    if (actual !== expected) fail(`SDK_TARBALL_TAMPERED:${name}`);
  }
}

/** Copy the receipt-verified installed public SDK packages into the stage. */
function copySdkPackages(repoConsumer, stageConsumer) {
  const sdkRoot = join(repoConsumer, 'node_modules', '@kaicreator');
  if (!existsSync(sdkRoot)) fail('SDK_CONSUMER_NOT_INSTALLED');
  mkdirSync(join(stageConsumer, 'node_modules'), { recursive: true });
  const copied = [];
  for (const name of readdirSync(sdkRoot)) {
    const src = join(sdkRoot, name);
    if (!lstatSync(src).isDirectory()) fail('SDK_PACKAGE_NOT_DIRECTORY');
    cpSync(src, join(stageConsumer, 'node_modules', '@kaicreator', name), {
      recursive: true,
      dereference: false,
    });
    copied.push({ name: `@kaicreator/${name}`, sha256: packageTreeDigest(join(stageConsumer, 'node_modules', '@kaicreator', name)) });
  }
  if (copied.length < 4) fail('SDK_CONSUMER_INCOMPLETE');
  return copied;
}

function packageTreeDigest(root) {
  const files = [];
  (function visit(dir, prefix = '') {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : 1,
    )) {
      if (entry.isSymbolicLink()) fail('SDK_PACKAGE_SYMLINK_REFUSED');
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) visit(join(dir, entry.name), rel);
      else if (entry.isFile()) files.push(rel);
      else fail('SDK_PACKAGE_ENTRY_REFUSED');
    }
  })(root);
  return createHash('sha256')
    .update(files.map((rel) => `${rel}:${sha256File(join(root, rel))}`).join('\n'))
    .digest('hex');
}

/** esbuild resolution reuses the reviewed workspace dependency (no new bundler). */
function esbuildApi() {
  const buildRequire = createRequire(join(repo, 'packages/executor-windows/package.json'));
  return buildRequire('esbuild');
}

const CREATE_REQUIRE_BANNER = {
  js: "import { createRequire as __shunCreateRequire } from 'node:module'; const require = __shunCreateRequire(import.meta.url);",
};

async function bundleMainApp(stageRoot) {
  const { build } = esbuildApi();
  const appRoot = join(stageRoot, 'app/native');
  mkdirSync(appRoot, { recursive: true });
  const appBundle = join(appRoot, 'control.mjs');
  await build({
    entryPoints: [join(repo, 'apps/control-api/src/main.ts')],
    outfile: appBundle,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    packages: 'bundle',
    logLevel: 'warning',
    banner: CREATE_REQUIRE_BANNER,
  });
  return appBundle;
}

async function bundleCliTools(stageRoot) {
  const { build } = esbuildApi();
  // The bundled CLI scripts must sit EXACTLY three directories below the
  // Core root: bootstrap-guided-localappdata derives its forbidden workspace
  // scope as resolve(<script dir>, '../../..') — in the repo that is the
  // repository root, in the bundle it must be the replaceable Core itself so
  // the per-user guided database under ShunAssistant/state stays OUTSIDE the
  // refused scope. Any other depth silently re-scopes the rule.
  const tools = join(stageRoot, 'app/native/tools');
  mkdirSync(tools, { recursive: true });
  // The #404 per-user Guided trust bootstrap and the trusted registry issuer
  // are bundled from the reviewed source with their CLI entry guards intact.
  await build({
    entryPoints: [
      join(repo, 'apps/control-api/scripts/bootstrap-guided-localappdata.ts'),
      join(repo, 'apps/control-api/scripts/issue-registry-currentness.ts'),
    ],
    outdir: tools,
    entryNames: '[name]',
    outExtension: { '.js': '.mjs' },
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    packages: 'bundle',
    logLevel: 'warning',
    banner: CREATE_REQUIRE_BANNER,
  });
  return {
    bootstrap: join(tools, 'bootstrap-guided-localappdata.mjs'),
    issuer: join(tools, 'issue-registry-currentness.mjs'),
  };
}

/**
 * Bundle the four trusted Host bindings with code splitting: the provider
 * binding statically imports the windows binding's module, and the runtime
 * contract requires BOTH the composing process and the sealed capability to
 * observe the SAME installed-binding module instance — a shared chunk keeps
 * that single instance instead of two inlined copies.
 */
async function bundleHostBindings(stageRoot) {
  const { build } = esbuildApi();
  const bindingsRoot = join(stageRoot, 'sdk-consumer/node_modules/.shun-bindings');
  const result = await build({
    entryPoints: {
      'openai-host': join(repo, 'packages/domain-host/src/cloud/openai-host.ts'),
      'windows-effect-host': join(repo, 'packages/domain-host/src/windows/effect-host-binding.ts'),
      'provider-host': join(repo, 'packages/domain-host/src/provider/provider-host-binding.ts'),
      'meta-host': join(repo, 'packages/domain-host/src/meta/meta-host-binding.ts'),
    },
    outdir: bindingsRoot,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    splitting: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    packages: 'bundle',
    logLevel: 'warning',
    banner: CREATE_REQUIRE_BANNER,
    metafile: true,
  });
  return { bindingsRoot, outputs: Object.keys(result.metafile.outputs) };
}

/**
 * The four consumer binding packages. Manifest shape matches the audited
 * runtime checks exactly (name + main './index.mjs' + regular file); each
 * index re-exports the bundled entry above so composing process and sealed
 * capability share one module instance.
 */
function writeBindingPackages(stageConsumer) {
  const packages = [
    {
      name: 'domain-harness-openai-host',
      index: `// v0.3 portable trusted binding: re-exports the REAL T04 Shun cloud host
// static entry and its trusted install seam from the reviewed bundled bytes.
// This file carries no authority of its own; credentials/transport/journal
// remain owned by the trusted composition.
export { generate, installTrustedCloudHostBinding, createTrustedCloudHostBinding } from '../.shun-bindings/openai-host.mjs';
`,
    },
    {
      name: 'shun-windows-effect-host',
      index: `// v0.3 portable trusted Windows effect Host binding (real authority chain).
// Re-exports the REAL trusted install seam so the composing process and the
// capability import the same module instance.
export { installTrustedWindowsEffectBinding, windowsExecute, trustedWindowsEffectBindingStatus } from '../.shun-bindings/windows-effect-host.mjs';
`,
    },
    {
      name: 'shun-provider-host',
      index: `// v0.3 portable trusted CuratedProvider Host binding (real first-use chain).
// Re-exports the REAL trusted install seam AND the Host-only two-step
// prepare/confirm surfaces: preview and one-time requestRef authority stay
// in the Host; the K→C callback consumes only {requestRef}.
export {
  installTrustedProviderBinding,
  providerFirstUse,
  prepareProviderFirstUse,
  confirmProviderFirstUse,
  readProviderFirstUseRequest,
  closeTrustedProviderBinding,
  trustedProviderBindingStatus,
} from '../.shun-bindings/provider-host.mjs';
`,
    },
    {
      name: 'shun-meta-host',
      index: `// v0.3 portable trusted Meta Shadow Host binding (real durable store).
// installTrustedMetaBinding is wrapped so the EXACT same HostMetaShadowStore
// instance the feedback binding is installed over also backs the read-only
// querySharedExperiences surface. The store itself remains the authority:
// fail-closed validation, currentness and revocation live inside it. A query
// mints no consent, no Shadow candidate and no authority.
import {
  installTrustedMetaBinding as installRealTrustedMetaBinding,
  submitMetaFeedback,
  trustedMetaBindingStatus,
} from '../.shun-bindings/meta-host.mjs';
let installedStore;
export function installTrustedMetaBinding(config) {
  if (!config || typeof config.store !== 'object' || config.store === null ||
      typeof config.store.querySharedExperiences !== 'function') {
    throw new Error('META_HOST_STORE_REQUIRED');
  }
  installedStore = config.store;
  return installRealTrustedMetaBinding(config);
}
export function querySharedExperiences(input) {
  if (installedStore === undefined) throw new Error('META_HOST_NOT_INSTALLED');
  return installedStore.querySharedExperiences(input);
}
export { submitMetaFeedback, trustedMetaBindingStatus };
`,
    },
  ];
  for (const { name, index } of packages) {
    const dir = join(stageConsumer, 'node_modules', name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name, version: '0.3.0', private: true, type: 'module', main: './index.mjs' }, null, 2) + '\n',
    );
    writeFileSync(join(dir, 'index.mjs'), index);
  }
  return packages.map((p) => p.name);
}

function assembleTrustedBuild(stageRoot, sources) {
  const operatorDir = join(stageRoot, 'operator/sources');
  mkdirSync(operatorDir, { recursive: true });
  const files = {
    kernel: join(operatorDir, 'kernel-mechanism-v1.mjs'),
    standard: join(operatorDir, 'standard-bundle.mjs'),
    business: join(operatorDir, 'business-goal.mjs'),
    capability: join(operatorDir, 'capability-llm.mjs'),
  };
  writeFileSync(files.kernel, sources.kernel);
  writeFileSync(files.standard, sources.standard);
  copyFileSync(sources.businessPath, files.business);
  copyFileSync(sources.capabilityPath, files.capability);
  const spec = buildSpec({
    kernelSource: sources.kernel,
    standardSource: sources.standard,
    businessSource: readFileSync(sources.businessPath, 'utf8'),
    capabilitySource: readFileSync(sources.capabilityPath, 'utf8'),
  });
  const placed = {
    ...spec,
    modules: spec.modules.map((entry) => ({
      ...entry,
      sourceFile:
        entry.sourceFile === '__KERNEL_FILE__'
          ? files.kernel
          : entry.sourceFile === '__STANDARD_FILE__'
            ? files.standard
            : entry.sourceFile === '__BUSINESS_FILE__'
              ? files.business
              : files.capability,
    })),
  };
  const specFile = join(stageRoot, 'operator', 'build-spec.json');
  const buildFile = join(stageRoot, 'operator', 'v03-build.json');
  writeFileSync(specFile, JSON.stringify(placed, null, 2));
  const assembler = spawnSync(
    process.execPath,
    [join(repo, 'scripts/v03-ci/assemble-trusted-build.mjs'), specFile, buildFile],
    { encoding: 'utf8' },
  );
  if (assembler.status !== 0) fail(`BUILD_ASSEMBLER_FAILED:${(assembler.stderr || assembler.stdout || '').slice(0, 400)}`);
  const receipt = JSON.parse(assembler.stdout);
  return { buildFile, buildFileSha256: receipt.sha256 };
}

function writeLauncherScripts(stageRoot) {
  const tools = join(stageRoot, 'tools');
  mkdirSync(tools, { recursive: true });

  // Trusted per-user first-run provisioner. Idempotent and fail-closed:
  // never overwrites existing material, never prints secret bytes. The
  // per-user Guided trust bootstrap itself stays inside the audited
  // bootstrap-guided-localappdata CLI (identity-guarded, consent-gated).
  writeFileSync(
    join(tools, 'shun-provision.mjs'),
    `// Generated by packaging/v03/stage.mjs — v0.3 per-user first-run provisioner.
// One consented run per Windows user creates all per-user material OUTSIDE
// the replaceable Core: Guided per-user trust (audited bootstrap CLI), the
// per-installation storage-registry Ed25519 pair, and the controller grant
// secrets. Re-running is a byte-stable NO-OP; present-but-invalid material
// is refused, never overwritten.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { perUserLayout } from '../packaging/windows-portable/lifecycle.mjs';

const core = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const nodeExe = join(core, 'node.exe');
function refuse(code) {
  console.error('SHUN_PROVISION_REFUSED:' + code);
  process.exit(1);
}
if (process.platform !== 'win32') refuse('WINDOWS_REQUIRED');
if (!process.env.LOCALAPPDATA) refuse('LOCALAPPDATA_REQUIRED');
const layout = perUserLayout(process.env.LOCALAPPDATA);
if (!existsSync(join(core, 'app/native/control.mjs'))) refuse('CORE_NOT_INSTALLED');

const results = [];
const step = (name, outcome) => results.push(name + '=' + outcome);

// 1. Per-user Guided trust (the audited #404 CLI; identity-guarded).
const guidedDb = join(layout.state, 'data', 'guided.sqlite');
mkdirSync(join(layout.state, 'data'), { recursive: true });
const bootstrap = spawnSync(
  nodeExe,
  [join(core, 'app', 'native', 'tools', 'bootstrap-guided-localappdata.mjs'), '--database', guidedDb, '--consent'],
  { encoding: 'utf8', timeout: 120_000 },
);
if (bootstrap.status !== 0) refuse('GUIDED_BOOTSTRAP_FAILED:status=' + String(bootstrap.status) + ':error=' + String(bootstrap.error?.message ?? 'none') + ':out=' + String(bootstrap.stdout ?? '').trim().slice(0, 1200) + ':err=' + String(bootstrap.stderr ?? '').trim().slice(0, 1200));
step('guided', bootstrap.stdout.includes('ALREADY_COMPLETE') ? 'ALREADY_COMPLETE' : 'BOOTSTRAP_CREATED');

// 2. Per-installation storage-registry authority pair (private key NEVER in the Core).
const registrySecretDir = join(layout.state, 'secrets', 'storage-registry');
const privateKeyPath = join(registrySecretDir, 'registry-private.pem');
const publicKeyPath = join(registrySecretDir, 'registry-public.pem');
mkdirSync(registrySecretDir, { recursive: true });
let registrySpki;
if (existsSync(privateKeyPath) && existsSync(publicKeyPath)) {
  const privateKey = readFileSync(privateKeyPath, 'utf8');
  const expectedPublic = readFileSync(publicKeyPath, 'utf8');
  const derived = createPublicKey(createPrivateKey(privateKey));
  if (derived.export({ type: 'spki', format: 'pem' }).toString() !== expectedPublic) refuse('REGISTRY_PAIR_MISMATCH');
  registrySpki = createHash('sha256').update(derived.export({ type: 'spki', format: 'der' })).digest('hex');
  step('registry', 'ALREADY_PRESENT');
} else if (existsSync(privateKeyPath) || existsSync(publicKeyPath)) {
  refuse('REGISTRY_PARTIAL_STATE');
} else {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  writeFileSync(privateKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));
  registrySpki = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  step('registry', 'GENERATED');
}

// 3. Controller grant secrets (random once per installation).
const controllerDir = join(layout.state, 'secrets', 'controller');
mkdirSync(controllerDir, { recursive: true });
for (const name of ['issuance.secret', 'integrity.secret']) {
  const file = join(controllerDir, name);
  if (!existsSync(file)) writeFileSync(file, randomBytes(32).toString('hex') + '\\n');
  else if (!/^[0-9a-f]{64}\\r?\\n?$/.test(readFileSync(file, 'utf8'))) refuse('CONTROLLER_SECRET_INVALID');
}
step('controller-secrets', 'READY');

// 4. Durable state directories (workspace/protected is created empty; the
//    protected dir is user-owned forever and never touched by upgrades).
for (const dir of [
  join(layout.state, 'workspace', 'protected'),
  join(layout.state, 'evidence'),
  join(layout.state, 'registry'),
  join(layout.state, 'data'),
]) mkdirSync(dir, { recursive: true });
step('state-dirs', 'READY');

// 5. Launch configuration (written once; a mismatched pin is refused).
const configFile = join(layout.state, 'config', 'launch.json');
mkdirSync(join(layout.state, 'config'), { recursive: true });
const record = JSON.stringify({ schema: 'shun.portable.launch.v1', registrySpkiSha256: registrySpki }) + '\\n';
if (!existsSync(configFile)) writeFileSync(configFile, record);
else if (readFileSync(configFile, 'utf8') !== record) refuse('LAUNCH_CONFIG_MISMATCH');

console.log('PROVISION_RESULT=' + (results.includes('guided=BOOTSTRAP_CREATED') || results.includes('registry=GENERATED') ? 'CREATED' : 'ALREADY_COMPLETE'));
for (const line of results) console.log(line);
console.log('STATE_ROOT=' + layout.state);
`,
  );

  // Trusted per-launch runner: (re)issues the 120-second workspace-bound
  // registry currentness through the audited issuer, then boots the real
  // v0.3 composition. Cloud egress is forced off: ordinary launches must
  // never become paid calls, and no UAC is needed or requested.
  writeFileSync(
    join(tools, 'shun-launch.mjs'),
    `// Generated by packaging/v03/stage.mjs — v0.3 per-launch trusted runner.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { perUserLayout } from '../packaging/windows-portable/lifecycle.mjs';

const core = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const nodeExe = join(core, 'node.exe');
function refuse(code) {
  console.error('SHUN_LAUNCH_REFUSED:' + code);
  process.exit(1);
}
if (process.platform !== 'win32') refuse('WINDOWS_REQUIRED');
if (!process.env.LOCALAPPDATA) refuse('LOCALAPPDATA_REQUIRED');
const layout = perUserLayout(process.env.LOCALAPPDATA);
const configFile = join(layout.state, 'config', 'launch.json');
const privateKeyPath = join(layout.state, 'secrets', 'storage-registry', 'registry-private.pem');
const publicKeyPath = join(layout.state, 'secrets', 'storage-registry', 'registry-public.pem');
if (!existsSync(configFile) || !existsSync(privateKeyPath) || !existsSync(join(core, 'app/native/control.mjs'))) {
  console.error('SHUN_V03_SETUP_REQUIRED: per-user first-run provisioning is missing for this Windows user.');
  console.error('Run once as this user: %LOCALAPPDATA%\\\\ShunAssistant\\\\core\\\\Shun-FirstRun.cmd');
  refuse('SETUP_REQUIRED');
}
const launch = JSON.parse(readFileSync(configFile, 'utf8'));

// Target privilege mode is a read-only whoami observation (same probe the
// audited issuer support uses); the issuer refuses unusable modes itself.
const whoami = spawnSync(
  join(process.env.SystemRoot ?? 'C:\\\\Windows', 'System32', 'whoami.exe'),
  ['/groups', '/fo', 'csv', '/nh'],
  { encoding: 'utf8', timeout: 15_000 },
);
const privilegeMode = /S-1-16-12288/i.test(whoami.stdout ?? '')
  ? 'ELEVATED_ADMIN'
  : /S-1-5-32-544/i.test(whoami.stdout ?? '')
    ? 'FILTERED_ADMIN'
    : 'STANDARD_USER';

const currentnessFile = join(layout.state, 'registry', 'currentness.json');
const issued = spawnSync(
  nodeExe,
  [join(core, 'app', 'native', 'tools', 'issue-registry-currentness.mjs')],
  {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      ...process.env,
      SHUN_ISSUER_WORKSPACE: join(layout.state, 'workspace'),
      SHUN_REGISTRY_CURRENTNESS_FILE: currentnessFile,
      SHUN_REGISTRY_PUBLIC_KEY_FILE: publicKeyPath,
      SHUN_ISSUER_PRIVATE_KEY_FILE: privateKeyPath,
      SHUN_ISSUER_TARGET_PRIVILEGE_MODE: privilegeMode,
    },
  },
);
if (issued.status !== 0) refuse('REGISTRY_ISSUANCE_FAILED:status=' + String(issued.status) + ':err=' + String(issued.stderr ?? '').trim().slice(0, 1200) + ':out=' + String(issued.stdout ?? '').trim().slice(0, 1200));

const caseFile = join(core, 'operator', 'guided-case.json');
const buildFile = join(core, 'operator', 'v03-build.json');
const buildReceiptFile = join(core, 'operator', 'build-receipt.json');
const receipt = JSON.parse(readFileSync(buildReceiptFile, 'utf8'));
const env = {
  ...process.env,
  SHUN_CONTROL_MODE: 'real-storage',
  SHUN_CONTROL_UI_DIR: join(core, 'control-ui', 'public'),
  SHUN_REAL_STORAGE_ROOT: join(layout.state, 'workspace'),
  SHUN_REAL_STORAGE_PROTECTED: JSON.stringify([join(layout.state, 'workspace', 'protected')]),
  SHUN_REAL_STORAGE_DATABASE: join(layout.state, 'data', 'real.sqlite'),
  SHUN_REGISTRY_CURRENTNESS_FILE: currentnessFile,
  SHUN_REGISTRY_PUBLIC_KEY_FILE: publicKeyPath,
  SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256: launch.registrySpkiSha256,
  SHUN_REAL_STORAGE_EVIDENCE_DIR: join(layout.state, 'evidence'),
  SHUN_CONTROLLER_ISSUANCE_SECRET: readFileSync(join(layout.state, 'secrets', 'controller', 'issuance.secret'), 'utf8').trim(),
  SHUN_GRANT_INTEGRITY_SECRET: readFileSync(join(layout.state, 'secrets', 'controller', 'integrity.secret'), 'utf8').trim(),
  SHUN_V03_GUIDED_DATABASE: join(layout.state, 'data', 'guided.sqlite'),
  SHUN_V03_FOLDER_SELECTION_DATABASE: join(layout.state, 'data', 'folder-selection.sqlite'),
  SHUN_V03_GUIDED_CASE_FILE: caseFile,
  SHUN_V03_GUIDED_CASE_SHA256: receipt.guidedCaseSha256,
  SHUN_V03_BUILD_FILE: buildFile,
  SHUN_V03_BUILD_SHA256: receipt.buildFileSha256,
  SHUN_V03_SDK_CONSUMER_DIR: join(core, 'sdk-consumer'),
  SHUN_V03_KERNEL_DOC_DATABASE: join(layout.state, 'data', 'k-docs.sqlite'),
  SHUN_V03_DEPLOYMENT_ROOT: join(core, 'sdk-consumer'),
  SHUN_V03_TENANT_ID: receipt.tenantId,
  SHUN_V03_DEPLOYED_APP_ID: receipt.deployedAppId,
  SHUN_V03_CLOUD_JOURNAL: join(layout.state, 'data', 'cloud-journal.sqlite'),
  SHUN_V03_APPROVAL_LEDGER: join(layout.state, 'data', 'submit-references.sqlite'),
  SHUN_CLOUD_ENABLED: '0',
};
const child = spawnSync(nodeExe, [join(core, 'app', 'native', 'control.mjs')], {
  env,
  stdio: 'inherit',
});
process.exit(child.status ?? 1);
`,
  );

  // v0.2-parity Core entry (lifecycle requires this exact name) delegating
  // to the v0.3 launcher so a real-storage boot never skips the env closure.
  writeFileSync(
    join(stageRoot, 'shun-core.cmd'),
    '@echo off\r\nsetlocal\r\nset "SHUN_CONTROL_MODE=real-storage"\r\n"%~dp0node.exe" "%~dp0tools\\shun-launch.mjs"\r\nexit /b %ERRORLEVEL%\r\n',
  );

  const userEntries = {
    'Shun-Install.cmd':
      '@echo off\r\nsetlocal\r\nif "%~2"=="" (\r\n  echo Usage: Shun-Install.cmd ^<shun-portable-public.pem^> ^<spki-sha256-pin^>\r\n  echo The public key and pin come from the authenticated distribution page.\r\n  exit /b 2\r\n)\r\n"%~dp0node.exe" "%~dp0packaging\\windows-portable\\lifecycle.mjs" install "%~dp0." "%~1" "%~2"\r\nexit /b %ERRORLEVEL%\r\n',
    'Shun-FirstRun.cmd': '@echo off\r\nsetlocal\r\n"%~dp0node.exe" "%~dp0tools\\shun-provision.mjs"\r\nexit /b %ERRORLEVEL%\r\n',
    'Shun-Run.cmd': '@echo off\r\nsetlocal\r\n"%~dp0node.exe" "%~dp0tools\\shun-launch.mjs"\r\nexit /b %ERRORLEVEL%\r\n',
    'Shun-Uninstall.cmd': '@echo off\r\nsetlocal\r\n"%~dp0node.exe" "%~dp0packaging\\windows-portable\\lifecycle.mjs" uninstall\r\nexit /b %ERRORLEVEL%\r\n',
  };
  for (const [name, body] of Object.entries(userEntries)) {
    writeFileSync(join(stageRoot, name), body);
  }
  return userEntries;
}

async function stage(target) {
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('WINDOWS_X64_REQUIRED');
  if (Number(process.versions.node.split('.')[0]) !== RUNTIME_NODE_MAJOR) {
    fail('NODE24_BUILD_HOST_REQUIRED');
  }
  if (!target || !isAbsolute(target)) fail('EXPLICIT_ABSOLUTE_STAGE_PATH_REQUIRED');
  const stageRoot = resolve(target);
  if (stageRoot === repo || stageRoot === here) fail('STAGE_PATH_INVALID');
  if (existsSync(stageRoot)) {
    if (!lstatSync(stageRoot).isDirectory() || readdirSync(stageRoot).length) {
      fail('STAGE_MUST_BE_AN_EMPTY_DIRECTORY');
    }
  } else {
    mkdirSync(stageRoot, { recursive: true });
  }

  // Native closure: pinned identities only.
  const exe = requireFile(process.execPath);
  const broker = requireFile(join(native, 'broker/shun-consent-broker.exe'));
  const hostAddon = requireFile(join(native, 'host/shun_consent_host.node'));
  const win32Impl = requireFile(
    join(repo, 'packages/recipe-runtime/native/impl/shun_win32_impl.node'),
  );
  const folderPicker = verifyFolderPickerSource(
    join(native, 'folder-picker/shun_folder_picker.node'),
    join(native, 'folder-picker/artifacts.ts'),
  );
  if (sha256File(broker) !== pinnedDigest('CONSENT_BROKER_EXE_SHA256')) fail('BROKER_PIN_MISMATCH');
  if (sha256File(hostAddon) !== pinnedDigest('CONSENT_HOST_ADDON_SHA256')) fail('ADDON_PIN_MISMATCH');

  // The audited consumer installer guarantees the receipt-verified public
  // SDK layout; re-verify receipts here and copy the installed packages.
  const { ensureV03SdkConsumer, consumerDir } = await import(
    '../../tests/integration/v03/r02-a-build/ensure-consumer.mjs'
  );
  await ensureV03SdkConsumer();
  const SDK_TARBALLS = [
    'kaicreator-domain-harness-contracts-0.10.2-rc.0.tgz',
    'kaicreator-domain-harness-microkernel-0.10.2-rc.0.tgz',
    'kaicreator-domain-harness-host-node-0.10.2-rc.0.tgz',
    'kaicreator-domain-harness-build-0.10.2-rc.0.tgz',
  ];
  verifySdkTarballReceipts(
    join(repo, 'tests/integration/v03/t00-scaffold/fixtures'),
    SDK_TARBALLS,
  );

  const appBundle = await bundleMainApp(stageRoot);
  const cliTools = await bundleCliTools(stageRoot);
  const bindings = await bundleHostBindings(stageRoot);
  const stageConsumer = join(stageRoot, 'sdk-consumer');
  const sdkPackages = copySdkPackages(consumerDir, stageConsumer);
  const bindingNames = writeBindingPackages(stageConsumer);

  // Trusted BUILD through the real operator assembler from pinned sources.
  const t11Fixtures = join(repo, 'tests/integration/v03/t11-runtime/fixtures');
  const sources = {
    kernel: readFileSync(join(t11Fixtures, 'kernel-mechanism-v1.mjs'), 'utf8'),
    standard: standardBundleSource(
      readFileSync(join(t11Fixtures, 'standard-sdk-v1.mjs'), 'utf8'),
      readFileSync(join(t11Fixtures, 'workflow-router.mjs'), 'utf8'),
    ),
    businessPath: requireFile(join(repo, 'packages/domain-app/src/activation/modules/business-goal.mjs')),
    capabilityPath: requireFile(join(repo, 'packages/domain-app/src/activation/modules/capability-llm.mjs')),
  };
  const buildReceipt = assembleTrustedBuild(stageRoot, sources);

  // Operator Guided Case (long-lived observation; runtime clamps steps).
  const caseBytes = mintGuidedCaseBytes({ buildId: BUILD_ID, nowMs: Date.now() });
  const caseFile = join(stageRoot, 'operator', 'guided-case.json');
  writeFileSync(caseFile, caseBytes);
  const receiptFile = join(stageRoot, 'operator', 'build-receipt.json');
  writeFileSync(
    receiptFile,
    JSON.stringify(
      {
        schema: 'shun.portable.build-receipt.v1',
        buildId: BUILD_ID,
        buildFileSha256: buildReceipt.buildFileSha256,
        guidedCaseSha256: sha256Text(caseBytes),
        tenantId: TENANT_ID,
        deployedAppId: DEPLOYED_APP_ID,
      },
      null,
      2,
    ) + '\n',
  );

  // Native binaries preserve the bundle-relative require('../native/*')
  // layout the bundled graph resolves against.
  for (const [src, relativePath] of [
    [broker, 'app/native/broker/shun-consent-broker.exe'],
    [hostAddon, 'app/native/host/shun_consent_host.node'],
    [win32Impl, 'app/native/impl/shun_win32_impl.node'],
    [folderPicker, 'app/native/shun_folder_picker.node'],
  ]) {
    const dst = join(stageRoot, relativePath);
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(src, dst);
  }
  copyFileSync(exe, join(stageRoot, 'node.exe'));

  // Audited v0.2 verifier + lifecycle, byte-identical to the reviewed tree.
  for (const [src, relativePath] of [
    [join(repo, 'packaging/windows-portable/lifecycle.mjs'), 'packaging/windows-portable/lifecycle.mjs'],
    [join(repo, 'scripts/package-v02/manifest.mjs'), 'scripts/package-v02/manifest.mjs'],
  ]) {
    const dst = join(stageRoot, relativePath);
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(requireFile(src), dst);
  }

  // Actual R04 desktop UI.
  cpSync(join(repo, 'apps/control-ui/public'), join(stageRoot, 'control-ui/public'), {
    recursive: true,
    errorOnExist: true,
    force: false,
    dereference: false,
  });

  writeLauncherScripts(stageRoot);

  writeFileSync(
    join(stageRoot, 'BUILD-ID.json'),
    JSON.stringify(
      {
        schema: 'shun.portable.build-id.v1',
        buildId: BUILD_ID,
        createdAt: new Date().toISOString(),
        nodeVersion: process.version,
        target: 'windows-x64-node24',
        digests: {
          node: sha256File(join(stageRoot, 'node.exe')),
          controlBundle: sha256File(appBundle),
          consentBroker: sha256File(join(stageRoot, 'app/native/broker/shun-consent-broker.exe')),
          consentHost: sha256File(join(stageRoot, 'app/native/host/shun_consent_host.node')),
          win32Impl: sha256File(join(stageRoot, 'app/native/impl/shun_win32_impl.node')),
          folderPicker: sha256File(join(stageRoot, 'app/native/shun_folder_picker.node')),
          buildFile: buildReceipt.buildFileSha256,
          guidedCase: sha256Text(caseBytes),
        },
        sdkPackages,
        bindingPackages: bindingNames,
      },
      null,
      2,
    ) + '\n',
  );
  writeFileSync(
    join(stageRoot, 'BUILD-NOT-A-RELEASE.txt'),
    'UNSIGNED v0.3.0 Windows portable staging output. Must be operator-signed, distributed through the authenticated channel with the out-of-band SPKI pin, and qualified on genuine Standard User Windows Home and Pro before any release. Do not ship this directory directly.\r\n',
  );
  void cliTools;
  void bindings;
  return {
    kind: 'SHUN_V030_PORTABLE_UNSIGNED_STAGE',
    buildId: BUILD_ID,
    nodeVersion: process.version,
    buildFileSha256: buildReceipt.buildFileSha256,
    guidedCaseSha256: sha256Text(caseBytes),
    digests: {
      node: sha256File(join(stageRoot, 'node.exe')),
      consentBroker: sha256File(join(stageRoot, 'app/native/broker/shun-consent-broker.exe')),
      consentHost: sha256File(join(stageRoot, 'app/native/host/shun_consent_host.node')),
      win32Impl: sha256File(join(stageRoot, 'app/native/impl/shun_win32_impl.node')),
      folderPicker: sha256File(join(stageRoot, 'app/native/shun_folder_picker.node')),
      appBundle: sha256File(appBundle),
    },
    sdkPackages,
    bindingPackages: bindingNames,
    signed: false,
    launchQualified: false,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 1) fail('USAGE_STAGE_PATH_ONLY');
    console.log(JSON.stringify(await stage(args[0]), null, 2));
  } catch (error) {
    const code = String(error?.message ?? '').startsWith('SHUN_V03_STAGE_REFUSED:')
      ? error.message
      : `SHUN_V03_STAGE_REFUSED:BUILD_FAILED:${String(error?.message ?? error).slice(0, 300)}`;
    console.error(code);
    process.exitCode = 1;
  }
}
