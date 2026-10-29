// T00 scoped scaffold test — run explicitly via
//   node --test "tests/integration/v03/t00-scaffold/*.test.mjs"
// (Node 24 on Windows treats a bare directory argument as a module entry, so the
// directory-scanning form of this command does not resolve; the glob form is the
// equivalent precise invocation. Not discovered by the top-level integration runner —
// run-tests.mjs scans only its own directory; CI wiring belongs to integration owner T11.)
//
// Oracles (Execution Pack TEST_MATRIX):
//  - source-identity/public-sdk-pack: SHA256 receipts match the committed fixture tarballs.
//  - isolated-consumer: offline `npm install` of the four local file: tarballs succeeds
//    (offline success proves no registry/npm-published-0.10.3 resolution), installed manifests
//    carry no lifecycle hooks, and the real public roots + microkernel host-seam import cleanly.
//  - package-boundary-negative: private SDK packages and unsupported deep imports are rejected.
//  - artifact-integrity-negative: tampered tarball bytes refuse against the recorded SHA256.
//  - no-install-effects: the three Shun manifests are zero-dep/no-scripts; no public entrypoints;
//    sibling lane paths remain unclaimed; no second-sender (`llm/openai`) references in Shun sources.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const fixturesDir = join(here, 'fixtures');

const SDK_TARBALLS = [
  'kaicreator-domain-harness-contracts-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-microkernel-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-host-node-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-build-0.10.2-rc.0.tgz',
];
const SDK_SCOPE_DIRS = [
  'domain-harness-contracts',
  'domain-harness-microkernel',
  'domain-harness-host-node',
  'domain-harness-build',
];
const PRIVATE_SDK_PACKAGES = ['domain-harness', 'domain-harness-node', 'domain-harness-compiler', 'domain-harness-expo'];
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepack', 'prepare', 'postpack'];

function sha256File(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

function readReceipts() {
  const text = readFileSync(join(fixturesDir, 'SHA256SUMS.txt'), 'utf8');
  const receipts = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    if (match) receipts.set(match[2].trim(), match[1]);
  }
  return receipts;
}

// npm on Windows is npm.cmd; spawning .cmd requires shell mode on modern Node.
const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const NPM_INSTALL_ARGS = 'install --offline --legacy-peer-deps --no-audit --no-fund';

let sharedConsumerDir = null;
let cleanConsumerDir = null;

// The clean consumer is created once and shared by several tests; its cleanup
// must run once after the whole file, not after the first consuming test.
after(() => {
  if (cleanConsumerDir) {
    try {
      rmSync(cleanConsumerDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup of the temporary consumer
    }
  }
});

function installOfflineConsumer() {
  if (sharedConsumerDir) return sharedConsumerDir;
  const consumer = mkdtempSync(join(tmpdir(), 't00-clean-consumer-'));
  cleanConsumerDir = consumer;
  writeFileSync(
    join(consumer, 'package.json'),
    JSON.stringify({ name: 't00-clean-consumer', version: '0.0.0', private: true }, null, 2),
  );
  const tarPaths = SDK_TARBALLS.map((name) => join(fixturesDir, name));
  const command = `${npmBin} ${NPM_INSTALL_ARGS} ${tarPaths.map((p) => `"${p}"`).join(' ')}`;
  const result = spawnSync(command, { cwd: consumer, encoding: 'utf8', shell: true });
  assert.equal(result.status, 0, `offline tarball install failed: ${result.stderr?.slice(-2000)}`);
  sharedConsumerDir = consumer;
  return consumer;
}

test('source-identity/public-sdk-pack: fixture tarballs match recorded SHA256 receipts', () => {
  const receipts = readReceipts();
  for (const name of SDK_TARBALLS) {
    const expected = receipts.get(name);
    assert.ok(expected, `missing SHA256 receipt for ${name}`);
    assert.equal(sha256File(join(fixturesDir, name)), expected, `tarball ${name} does not match its recorded receipt`);
  }
  assert.equal(receipts.size, SDK_TARBALLS.length, 'receipt file must record exactly the four packed tarballs');
  const identity = readFileSync(join(fixturesDir, 'SOURCE-IDENTITY.txt'), 'utf8');
  assert.match(identity, /sdk_tag_commit=061376f4a023070f215f9feffad5c24d96d503cb/);
  assert.match(identity, /sdk_tree=099cdc831aef63befd62aaede7e7a853d1be468f/);
  assert.match(identity, /npm_v0\.10\.3_published=NO/);
});

test('no-install-effects: installed SDK manifests carry no lifecycle hooks and exact source versions', () => {
  const consumer = installOfflineConsumer();
  for (const dir of SDK_SCOPE_DIRS) {
    const manifest = JSON.parse(readFileSync(join(consumer, 'node_modules', '@kaicreator', dir, 'package.json'), 'utf8'));
    assert.equal(manifest.version, '0.10.2-rc.0', `${dir} must resolve to the source-tag version, not an npm 0.10.3`);
    for (const hook of LIFECYCLE_HOOKS) {
      assert.equal(manifest.scripts?.[hook], undefined, `${dir} must not run a ${hook} hook`);
    }
  }
});

test('isolated-consumer: real public imports resolve from the pinned local tarballs', () => {
  const consumer = installOfflineConsumer();
  // Install set must be exactly the four pinned tarballs (no transitive registry extras).
  const scopeDir = join(consumer, 'node_modules', '@kaicreator');
  assert.deepEqual(readdirSync(scopeDir).sort(), [...SDK_SCOPE_DIRS].sort());
  // The optional better-sqlite3 peer must NOT have been pulled into the Shun consumer.
  assert.equal(existsSync(join(consumer, 'node_modules', 'better-sqlite3')), false);

  const probe = `
    const contracts = await import('@kaicreator/domain-harness-contracts');
    if (contracts.LLM_GENERATE_CONTRACT_V1 !== 'dh.llm.generate/1') throw new Error('contracts identity mismatch');
    const microkernel = await import('@kaicreator/domain-harness-microkernel');
    if (Object.keys(microkernel).length === 0) throw new Error('microkernel root export empty');
    const hostSeam = await import('@kaicreator/domain-harness-microkernel/host-seam');
    if (typeof hostSeam.activateV10App !== 'function') throw new Error('host-seam activateV10App missing');
    const hostNode = await import('@kaicreator/domain-harness-host-node');
    if (Object.keys(hostNode).length === 0) throw new Error('host-node root export empty');
    const build = await import('@kaicreator/domain-harness-build');
    if (Object.keys(build).length === 0) throw new Error('build root export empty');
    console.log(JSON.stringify({
      contractV1: contracts.LLM_GENERATE_CONTRACT_V1,
      microkernelRootExports: Object.keys(microkernel).length,
      hostSeamActivate: typeof hostSeam.activateV10App,
      hostNodeRootExports: Object.keys(hostNode).length,
      buildRootExports: Object.keys(build).length,
    }));
  `;
  writeFileSync(join(consumer, 'probe.mjs'), probe);
  const run = spawnSync(`"${process.execPath}" probe.mjs`, { cwd: consumer, encoding: 'utf8', shell: true });
  assert.equal(run.status, 0, `public import probe failed: ${run.stderr?.slice(-2000)}`);
  const observed = JSON.parse(run.stdout);
  assert.equal(observed.contractV1, 'dh.llm.generate/1');
  assert.equal(observed.hostSeamActivate, 'function');
  assert.ok(observed.microkernelRootExports > 0);
  assert.ok(observed.hostNodeRootExports > 0);
  assert.ok(observed.buildRootExports > 0);
});

test('package-boundary-negative: private SDK packages and unsupported deep imports are rejected', () => {
  const consumer = installOfflineConsumer();
  // Probe specifiers through a file (never an inline -e script: cmd.exe quoting is unreliable).
  const probeScript = `
    const specifiers = process.argv.slice(2);
    const observed = {};
    for (const specifier of specifiers) {
      try {
        await import(specifier);
        observed[specifier] = 'UNEXPECTED_RESOLVE';
      } catch (error) {
        observed[specifier] = error.code || String(error.message).slice(0, 120);
      }
    }
    console.log(JSON.stringify(observed));
  `;
  writeFileSync(join(consumer, 'negative-probe.mjs'), probeScript);
  const specifiers = [
    ...PRIVATE_SDK_PACKAGES.map((name) => `@kaicreator/${name}`),
    '@kaicreator/domain-harness-contracts/internal/identity.js',
    '@kaicreator/domain-harness-build/internal/deep.js',
  ];
  const run = spawnSync(
    `"${process.execPath}" negative-probe.mjs ${specifiers.join(' ')}`,
    { cwd: consumer, encoding: 'utf8', shell: true },
  );
  assert.equal(run.status, 0, `negative probe crashed: ${run.stderr?.slice(-1000)}`);
  const observed = JSON.parse(run.stdout);
  for (const name of PRIVATE_SDK_PACKAGES) {
    assert.match(observed[`@kaicreator/${name}`], /ERR_MODULE_NOT_FOUND/, `private package ${name} must not resolve`);
  }
  assert.match(
    observed['@kaicreator/domain-harness-contracts/internal/identity.js'],
    /ERR_PACKAGE_PATH_NOT_EXPORTED/,
    'contracts deep import must be refused by the exports map',
  );
  assert.match(
    observed['@kaicreator/domain-harness-build/internal/deep.js'],
    /ERR_PACKAGE_PATH_NOT_EXPORTED/,
    'build deep import must be refused by the exports map',
  );
});

test('artifact-integrity-negative: tampered tarball bytes refuse against the recorded receipt', (t) => {
  const tamperedDir = mkdtempSync(join(tmpdir(), 't00-tampered-'));
  t.after(() => {
    try {
      rmSync(tamperedDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  });
  const receipts = readReceipts();
  const original = join(fixturesDir, SDK_TARBALLS[0]);
  const tampered = join(tamperedDir, SDK_TARBALLS[0]);
  // Flip one byte in the compressed payload: the receipt layer must refuse the digest,
  // and the package layer must fail to install the corrupted archive offline.
  const bytes = readFileSync(original);
  bytes[Math.floor(bytes.length / 2)] ^= 0xff;
  writeFileSync(tampered, bytes);
  assert.notEqual(sha256File(tampered), receipts.get(SDK_TARBALLS[0]), 'tampered tarball must change the digest');
  writeFileSync(
    join(tamperedDir, 'package.json'),
    JSON.stringify({ name: 't00-tampered-consumer', version: '0.0.0', private: true }, null, 2),
  );
  const run = spawnSync(`${npmBin} ${NPM_INSTALL_ARGS} "${tampered}"`, {
    cwd: tamperedDir,
    encoding: 'utf8',
    shell: true,
  });
  assert.notEqual(run.status, 0, 'install from a tampered artifact must fail (receipt + archive integrity refuse)');
});

test('no-install-effects: Shun scaffold shape — zero-dep manifests, no entrypoints, no second-sender references', () => {
  const threePackages = ['domain-computer', 'domain-host', 'domain-app'];
  for (const name of threePackages) {
    const manifest = JSON.parse(readFileSync(join(repoRoot, 'packages', name, 'package.json'), 'utf8'));
    assert.equal(manifest.private, true);
    assert.equal(manifest.dependencies, undefined, `${name} must have zero dependencies`);
    assert.equal(manifest.devDependencies, undefined, `${name} must have zero devDependencies`);
    assert.equal(manifest.scripts, undefined, `${name} must declare no scripts`);
    assert.equal(manifest.exports, undefined, `${name} public exports are reserved to T11`);
    const tsconfig = JSON.parse(readFileSync(join(repoRoot, 'packages', name, 'tsconfig.json'), 'utf8'));
    assert.equal(tsconfig.extends, '../../tsconfig.base.json');
    // The shared strict base the three configs extend (typecheck behavior is exercised
    // end-to-end by the domain-computer program; host/app are zero-input by design).
    const base = JSON.parse(readFileSync(join(repoRoot, 'tsconfig.base.json'), 'utf8'));
    assert.equal(base.compilerOptions.strict, true);
    assert.equal(base.compilerOptions.noEmit, true);
  }
  // No package-level public entrypoints at T00.
  assert.equal(existsSync(join(repoRoot, 'packages', 'domain-computer', 'src', 'index.ts')), false);
  // Sibling lane directories remain unclaimed by T00.
  assert.equal(existsSync(join(repoRoot, 'packages', 'domain-host', 'src')), false);
  assert.equal(existsSync(join(repoRoot, 'packages', 'domain-app', 'src')), false);
  const computerSrc = readdirSync(join(repoRoot, 'packages', 'domain-computer', 'src'));
  assert.deepEqual(computerSrc, ['contracts'], 'T00 owns only src/contracts inside domain-computer');
  // Shun-owned sources must not reference the forbidden second-sender subpath or its native
  // driver. Scan scope: contracts TS + the three manifests/tsconfigs. (This test file and the
  // fixture provenance note necessarily name the forbidden subpath to assert its absence.)
  const forbidden = [/llm\/openai/, /better-sqlite3/, /\bsk-/];
  const shunOwnedSources = [
    join(repoRoot, 'packages', 'domain-computer', 'src', 'contracts', 'llm-generate-v1.ts'),
    join(repoRoot, 'packages', 'domain-computer', 'src', 'contracts', 'index.ts'),
    ...threePackages.flatMap((name) => [
      join(repoRoot, 'packages', name, 'package.json'),
      join(repoRoot, 'packages', name, 'tsconfig.json'),
    ]),
  ];
  for (const file of shunOwnedSources) {
    const content = readFileSync(file, 'utf8');
    for (const pattern of forbidden) {
      assert.doesNotMatch(content, pattern, `${file} must not reference ${pattern}`);
    }
  }
});
