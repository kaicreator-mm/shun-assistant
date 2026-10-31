/**
 * R02-A: ensure a REAL installed public DomainHarness v0.10.3 SDK consumer
 * layout at <repo>/node_modules/.v03-sdk-consumer.
 *
 * The four t00 fixture tarballs are the SHA256-pinned `npm pack` outputs of
 * the exact public SDK Git tag (v0.10.3, commit 061376f4 — see
 * tests/integration/v03/t00-scaffold/fixtures/SOURCE-IDENTITY.txt). They are
 * installed here unmodified, exactly as an offline operator would install
 * them, so production code resolves @kaicreator/domain-harness-* from a real
 * node_modules layout instead of test aliases.
 *
 * The `domain-harness-openai-host` package is the trusted single-import
 * binding for the selected Shun LLM capability: it re-exports the REAL T04
 * static entry (`packages/domain-host/src/cloud/openai-host.ts` → `generate`),
 * exactly the role `shun-windows-effect-host` plays for the T01 Windows
 * adapter in T11. No transport, credential or second sender lives here.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(here, '../../../..');
export const consumerDir = join(repoRoot, 'node_modules/.v03-sdk-consumer');
const fixturesDir = resolve(repoRoot, 'tests/integration/v03/t00-scaffold/fixtures');

const SDK_TARBALLS = [
  'kaicreator-domain-harness-contracts-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-microkernel-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-host-node-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-build-0.10.2-rc.0.tgz',
];

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

/** Tarball bytes must still match the committed SHA256SUMS receipts. */
function verifyTarballReceipts() {
  const receipts = new Map();
  for (const line of readFileSync(join(fixturesDir, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    if (match) receipts.set(match[2].trim(), match[1]);
  }
  for (const name of SDK_TARBALLS) {
    const expected = receipts.get(name);
    if (!expected) throw new Error(`V03_CONSUMER_RECEIPT_MISSING: ${name}`);
    const actual = sha256(readFileSync(join(fixturesDir, name)));
    if (actual !== expected) throw new Error(`V03_CONSUMER_TARBALL_TAMPERED: ${name}`);
  }
}

function installTarballs() {
  mkdirSync(consumerDir, { recursive: true });
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify({ name: 'v03-sdk-consumer', version: '0.0.0', private: true }, null, 2),
  );
  const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const command = `${npmBin} install --offline --legacy-peer-deps --no-audit --no-fund ${SDK_TARBALLS.map(
    (name) => `"${join(fixturesDir, name)}"`,
  ).join(' ')}`;
  const install = spawnSync(command, { cwd: consumerDir, encoding: 'utf8', shell: true });
  if (install.status !== 0) {
    throw new Error(`V03_CONSUMER_INSTALL_FAILED: ${String(install.stderr?.slice(-2000))}`);
  }
}

/** Trusted single-import binding to the REAL T04 static cloud host entry. */
function stageOpenAiHostBinding() {
  const hostDir = join(consumerDir, 'node_modules/domain-harness-openai-host');
  const adapterUrl = pathToFileURL(
    join(repoRoot, 'packages/domain-host/src/cloud/openai-host.ts'),
  ).href;
  const marker = join(hostDir, 'PROVENANCE.txt');
  const expectedMarker = `v03-sdk-consumer openai-host binding v2 (generate+install seam) -> ${adapterUrl}\n`;
  if (existsSync(marker) && readFileSync(marker, 'utf8') === expectedMarker) return;
  mkdirSync(hostDir, { recursive: true });
  writeFileSync(
    join(hostDir, 'package.json'),
    JSON.stringify(
      {
        name: 'domain-harness-openai-host',
        version: '0.3.0',
        private: true,
        type: 'module',
        main: './index.mjs',
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(hostDir, 'index.mjs'),
    `// R02-A trusted binding: re-export the REAL T04 Shun cloud host static
// entry AND its trusted install seam, so the composing process and the
// capability import THE SAME module instance (the module-global installed
// binding stays coherent). Credentials/transport/journal remain owned by
// the trusted T04 composition. This file carries no authority of its own.
export { generate, installTrustedCloudHostBinding, createTrustedCloudHostBinding } from '${adapterUrl}';
`,
  );
  writeFileSync(marker, expectedMarker);
}

export function ensureV03SdkConsumer() {
  const installedMarker = join(
    consumerDir,
    'node_modules/@kaicreator/domain-harness-build/package.json',
  );
  if (existsSync(installedMarker)) {
    stageOpenAiHostBinding();
    return;
  }
  verifyTarballReceipts();
  installTarballs();
  stageOpenAiHostBinding();
}

// Direct execution (operator/test setup): node ensure-consumer.mjs
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  ensureV03SdkConsumer();
  console.log(JSON.stringify({ consumerDir, ready: true }));
}
