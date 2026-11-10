// Deterministic negative unit tests for the v0.3 portable stage builder
// (#407). No network, no full stage build, no real user profile: these pin
// the shape of the generated closure (BUILD spec roles/provenance, Guided
// Case bytes, launch env closure) and prove the sign/verify/assembler
// refusals the acceptance matrix requires. Run on Node >= 24:
//
//   node --test packaging/v03/stage.test.mjs
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';
import { publicKeyFingerprint, signBundle, verifyBundle } from '../../scripts/package-v02/manifest.mjs';
import {
  buildSpec,
  CASE_VALIDITY_MS,
  mintGuidedCaseBytes,
  sha256Text,
  standardBundleSource,
  STAGE_LAUNCH_ENV_KEYS,
} from './stage.mjs';

const fixtures = [];
afterEach(() => {
  for (const path of fixtures.splice(0)) rmSync(path, { recursive: true, force: true });
});
function fixture() {
  const temp = mkdtempSync(join(tmpdir(), 'shun-v03-stage-test-'));
  fixtures.push(temp);
  return temp;
}
function refuses(fn) {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

const KERNEL = 'export function occurrence() { return 1; }\n';
const ROUTER = 'export function routeWorkflowIntent(x) { return x; }\n';
const STANDARD = standardBundleSource('export const sdk = 1;\n', ROUTER);
const BUSINESS = 'export function businessPolicy() { return true; }\n';
const CAPABILITY = 'export function interpretGoal() { return { ok: true }; }\n';

test('standardBundleSource is deterministic and strips router exports into an IIFE re-export', () => {
  assert.equal(STANDARD, standardBundleSource('export const sdk = 1;\n', ROUTER));
  assert.match(STANDARD, /const __dhv10RouterBundle = \(\(\) => \{/);
  assert.match(STANDARD, /export const routeWorkflowIntent = __dhv10RouterBundle\.routeWorkflowIntent;/);
  assert.ok(!/^export function routeWorkflowIntent/m.test(STANDARD));
});

test('buildSpec pins the audited role/provenance invariants of the trusted BUILD', () => {
  const spec = buildSpec({
    kernelSource: KERNEL,
    standardSource: STANDARD,
    businessSource: BUSINESS,
    capabilitySource: CAPABILITY,
  });
  assert.equal(spec.targetProfile, 'node24-esm/1');
  assert.equal(spec.buildId, 'shun-v0.3.0-portable-g1');
  const roles = spec.modules.map((m) => m.module.role);
  assert.deepEqual(roles, ['kernel-primary', 'standard-primary', 'business', 'capability']);
  const provenance = spec.modules.map((m) => m.provenance);
  assert.deepEqual(provenance, [
    'PUBLIC_DOMAIN_PACKAGE_V0103',
    'PUBLIC_DOMAIN_PACKAGE_V0103',
    'SHUN_TRUSTED_DOMAIN_PACKAGE',
    'SHUN_TRUSTED_DOMAIN_PACKAGE',
  ]);
  const expected = {
    __KERNEL_FILE__: KERNEL,
    __STANDARD_FILE__: STANDARD,
    __BUSINESS_FILE__: BUSINESS,
    __CAPABILITY_FILE__: CAPABILITY,
  };
  for (const entry of spec.modules) {
    assert.equal(entry.sourceSha256, sha256Text(expected[entry.sourceFile]));
  }
  const capability = spec.modules[3].module;
  assert.deepEqual(capability.externalImports, { node: [], npm: ['domain-harness-openai-host'], native: [] });
  assert.equal(capability.capabilityId, 'llm');
  assert.equal(capability.externalEffect, true);
  assert.deepEqual(spec.routes, [
    { intentId: 'goal-interpret', operationId: 'interpretGoal', capabilityId: 'llm', handlerId: 'interpretGoal' },
  ]);
  assert.deepEqual(spec.hardBudget, { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 });
});

test('real trusted-build assembler refuses a tampered source pin', () => {
  const temp = fixture();
  const kernelFile = join(temp, 'kernel.mjs');
  const standardFile = join(temp, 'standard.mjs');
  const businessFile = join(temp, 'business.mjs');
  const capabilityFile = join(temp, 'capability.mjs');
  writeFileSync(kernelFile, KERNEL);
  writeFileSync(standardFile, STANDARD);
  writeFileSync(businessFile, BUSINESS);
  writeFileSync(capabilityFile, CAPABILITY);
  const spec = buildSpec({ kernelSource: KERNEL, standardSource: STANDARD, businessSource: BUSINESS, capabilitySource: CAPABILITY });
  const placed = {
    ...spec,
    modules: spec.modules.map((entry, index) => ({
      ...entry,
      sourceFile: [kernelFile, standardFile, businessFile, capabilityFile][index],
      sourceSha256: index === 0 ? 'f'.repeat(64) : entry.sourceSha256,
    })),
  };
  const specFile = join(temp, 'spec.json');
  const outFile = join(temp, 'build.json');
  writeFileSync(specFile, JSON.stringify(placed));
  const assembler = spawnSync(
    process.execPath,
    [join(import.meta.dirname, '../../scripts/v03-ci/assemble-trusted-build.mjs'), specFile, outFile],
    { encoding: 'utf8' },
  );
  assert.notEqual(assembler.status, 0);
  assert.match(assembler.stderr, /PINNED_SOURCE_SHA_MISMATCH/);
  assert.equal(existsSync(outFile), false);
});

test('mintGuidedCaseBytes pins the audited observation shape and validity window', () => {
  const now = 1_700_000_000_000;
  const bytes = mintGuidedCaseBytes({ buildId: 'shun-v0.3.0-portable-g1', nowMs: now });
  const parsed = JSON.parse(bytes);
  assert.equal(parsed.observation.schema, 'shun.guided.host-observation.v1');
  assert.equal(parsed.observation.taskId, 'task-shun-v0.3.0-portable-g1');
  assert.equal(parsed.observation.journeyId, 'journey-shun-v0.3.0-portable-g1');
  assert.equal(parsed.observation.observedAtUnixMs, now - 1_000);
  assert.equal(parsed.observation.validUntilUnixMs, now + Number(CASE_VALIDITY_MS));
  assert.equal(parsed.semanticSelection.status, 'SELECTED');
  assert.equal(parsed.semanticSelection.semantic.capabilityId, 'system.storage.diagnose_bounded_action');
  assert.equal(parsed.scope.status, 'KNOWN');
  // Stable bytes: identical inputs produce the identical signed-payload input.
  assert.equal(bytes, mintGuidedCaseBytes({ buildId: 'shun-v0.3.0-portable-g1', nowMs: now }));
  assert.ok(refuses(() => mintGuidedCaseBytes({ buildId: '../evil', nowMs: now })));
  assert.ok(refuses(() => mintGuidedCaseBytes({ buildId: 'ok-build', nowMs: 0 })));
});

test('STAGE_LAUNCH_ENV_KEYS is exactly the real-storage production closure main.ts requires', () => {
  assert.deepEqual([...STAGE_LAUNCH_ENV_KEYS].sort(), [
    'SHUN_CONTROLLER_ISSUANCE_SECRET',
    'SHUN_CONTROL_MODE',
    'SHUN_CONTROL_UI_DIR',
    'SHUN_GRANT_INTEGRITY_SECRET',
    'SHUN_REAL_STORAGE_DATABASE',
    'SHUN_REAL_STORAGE_EVIDENCE_DIR',
    'SHUN_REAL_STORAGE_PROTECTED',
    'SHUN_REAL_STORAGE_ROOT',
    'SHUN_REGISTRY_CURRENTNESS_FILE',
    'SHUN_REGISTRY_PUBLIC_KEY_FILE',
    'SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256',
    'SHUN_V03_APPROVAL_LEDGER',
    'SHUN_V03_BUILD_FILE',
    'SHUN_V03_BUILD_SHA256',
    'SHUN_V03_CLOUD_JOURNAL',
    'SHUN_V03_DEPLOYED_APP_ID',
    'SHUN_V03_DEPLOYMENT_ROOT',
    'SHUN_V03_GUIDED_CASE_FILE',
    'SHUN_V03_GUIDED_CASE_SHA256',
    'SHUN_V03_GUIDED_DATABASE',
    'SHUN_V03_KERNEL_DOC_DATABASE',
    'SHUN_V03_SDK_CONSUMER_DIR',
    'SHUN_V03_TENANT_ID',
  ]);
});

test('v0.3-shaped bundle: verifier refuses tamper, extra file, wrong pin, wrong key and junctions', () => {
  const temp = fixture();
  const root = join(temp, 'bundle');
  mkdirSync(join(root, 'operator'), { recursive: true });
  writeFileSync(join(root, 'node.exe'), 'fake-node-bytes');
  writeFileSync(join(root, 'app-placeholder.txt'), 'closure-placeholder');
  writeFileSync(join(root, 'operator', 'v03-build.json'), '{}\n');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyFile = join(temp, 'public.pem');
  const privateKeyFile = join(temp, 'private.pem');
  writeFileSync(publicKeyFile, publicKey.export({ type: 'spki', format: 'pem' }));
  writeFileSync(privateKeyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const pin = publicKeyFingerprint(publicKey);
  signBundle(root, privateKeyFile);
  assert.equal(verifyBundle(root, publicKeyFile, pin).entries, 3);

  const tampered = join(temp, 'tampered');
  cpSyncDir(root, tampered);
  writeFileSync(join(tampered, 'operator', 'v03-build.json'), '{"x":1}\n');
  assert.ok(refuses(() => verifyBundle(tampered, publicKeyFile, pin)), 'tampered file must refuse');

  const extra = join(temp, 'extra');
  cpSyncDir(root, extra);
  writeFileSync(join(extra, 'smuggled.txt'), 'x');
  assert.ok(refuses(() => verifyBundle(extra, publicKeyFile, pin)), 'extra file must refuse');

  assert.ok(refuses(() => verifyBundle(root, publicKeyFile, 'b'.repeat(64))), 'wrong pin must refuse');
  const other = generateKeyPairSync('ed25519');
  const otherPublic = join(temp, 'other-public.pem');
  writeFileSync(otherPublic, other.publicKey.export({ type: 'spki', format: 'pem' }));
  assert.ok(refuses(() => verifyBundle(root, otherPublic, pin)), 'wrong key must refuse');

  const junctionRoot = join(temp, 'junction');
  cpSyncDir(root, junctionRoot);
  try {
    symlinkSync(junctionRoot, join(junctionRoot, 'operator', 'junction-probe'), 'junction');
    assert.ok(refuses(() => verifyBundle(junctionRoot, publicKeyFile, pin)), 'junction must refuse');
  } catch (error) {
    assert.match(String(error?.code ?? ''), /EPERM|EACCES|ENOTSUP/);
  }
});

/** Minimal recursive directory copy for the negative bundles. */
function cpSyncDir(src, dst) {
  cpSync(src, dst, { recursive: true, dereference: false, force: false, errorOnExist: true });
}
