// gen-keys-and-catalog.mjs — i86-U04 step 2.
//
// Generates the curator ed25519 keypair (private key stays in _tmp, never
// committed), downloads the real ripgrep artifact over the network, hashes
// everything from real bytes, builds the sharp payload zip from the vetted
// installed @img artifact, signs the catalogs, and writes the committed
// trust root. Every digest in this script is computed — none are hand-written.
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:net';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESEARCH = resolve(HERE, '..');
const WORKTREE = resolve(RESEARCH, '..', '..');
const TMP = 'C:\\xDev\\kAiCreator\\_tmp\\i86-u04';
const JIT = '../../../packages/vertical-jit/src';
const { SpawnProcess } = await import(`${JIT}/adapters/node.ts`);
const { Events } = await import('./lib/events.mjs');
const { downloadTo, sha256File } = await import('./lib/downloader.mjs');
const { signCatalog, spkiFingerprint } = await import('./lib/catalog.mjs');

const events = new Events(join(RESEARCH, 'events.ndjson'), 'gen');
const RIPGREP_URL =
  'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip';
const RIPGREP_NAME = 'ripgrep-14.1.1-x86_64-pc-windows-msvc.zip';
const SHARP_IMG_DIR = join(
  WORKTREE,
  'node_modules',
  '.pnpm',
  '@img+sharp-win32-x64@0.35.5',
  'node_modules',
  '@img',
  'sharp-win32-x64',
);
const SHARP_NAME = 'sharp-win32-x64-0.35.5.zip';
const ORIGIN_FILES = join(TMP, 'origin-files');

async function main() {
  await emit('GEN_START', 'i86-U04 trust root + catalog generation');
  await mkdir(join(TMP, 'keys'), { recursive: true });
  await mkdir(ORIGIN_FILES, { recursive: true });
  await mkdir(join(RESEARCH, 'catalogs'), { recursive: true });

  // ---- 1. curator keypair (idempotent within the pilot) ----
  const privPath = join(TMP, 'keys', 'curator_ed25519.pkcs8.pem');
  const pubPath = join(TMP, 'keys', 'curator_ed25519.spki.pem');
  let privatePem;
  let publicPem;
  try {
    privatePem = await readFile(privPath, 'utf8');
    publicPem = await readFile(pubPath, 'utf8');
    await emit('KEYS_REUSED', privPath);
  } catch {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    await writeFile(privPath, privatePem);
    await writeFile(pubPath, publicPem);
    await emit('KEYS_GENERATED', 'ed25519 keypair generated (private key in _tmp only)');
  }
  const fingerprint = spkiFingerprint(publicPem);
  await emit('TRUST_ROOT_PIN', fingerprint);

  // ---- 2. real network download of the ripgrep artifact (fetch via proxy) ----
  const zipPath = join(ORIGIN_FILES, RIPGREP_NAME);
  const download = await downloadTo(RIPGREP_URL, zipPath, {
    approvedHosts: ['github.com', 'release-assets.githubusercontent.com'],
    maxBytes: 64 * 1024 * 1024,
    timeoutMs: 180_000,
  });
  await emit('RIPGREP_DOWNLOADED', `${download.sizeBytes} bytes via fetch`, {
    hops: download.hops.map((h) => h.host),
    sha256: download.sha256,
  });

  // ---- 3. independent-channel cross-check: curl through the same proxy ----
  const crosscheckPath = join(ORIGIN_FILES, 'ripgrep-crosscheck.zip');
  await rm(crosscheckPath, { force: true });
  const proc = new SpawnProcess();
  const curl = await proc.run({
    argv: [
      'curl',
      '-sS',
      '-x',
      'http://127.0.0.1:10808',
      '-L',
      '--fail',
      '--retry',
      '2',
      '--max-time',
      '240',
      '-o',
      crosscheckPath,
      RIPGREP_URL,
    ],
    timeoutMs: 260_000,
  });
  if (curl.exitCode !== 0) {
    throw new Error(`curl cross-check failed exit=${curl.exitCode}: ${curl.stderr.slice(0, 200)}`);
  }
  const curlSha = await sha256File(crosscheckPath);
  const fetchSha = await sha256File(zipPath);
  if (curlSha !== fetchSha) {
    throw new Error(`cross-check digest divergence: fetch=${fetchSha} curl=${curlSha}`);
  }
  await emit('RIPGREP_CROSSCHECK', 'curl channel digest equals fetch channel digest', { sha256: curlSha });
  await rm(crosscheckPath, { force: true });

  // ---- 4. sharp payload zip built from the vetted installed @img artifact ----
  const sharpZipPath = join(ORIGIN_FILES, SHARP_NAME);
  await rm(sharpZipPath, { force: true });
  const compress = await proc.run({
    argv: [
      POWERSHELL(),
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `Compress-Archive -Path index.cjs,package.json,versions.json,lib -DestinationPath '${sharpZipPath}' -CompressionLevel Optimal`,
    ],
    cwd: SHARP_IMG_DIR,
    timeoutMs: 120_000,
  });
  // SpawnProcess pipes input only when provided; Compress-Archive needs no stdin.
  if (compress.exitCode !== 0) {
    throw new Error(`Compress-Archive failed exit=${compress.exitCode}: ${compress.stderr.slice(0, 300)}`);
  }
  const sharpZipSha = await sha256File(sharpZipPath);
  const sharpZipSize = (await stat(sharpZipPath)).size;
  const sharpNodePath = join(SHARP_IMG_DIR, 'lib', 'sharp-win32-x64-0.35.5.node');
  const sharpNodeSha = await sha256File(sharpNodePath);
  const sharpNodeSize = (await stat(sharpNodePath)).size;
  await emit('SHARP_PAYLOAD_BUILT', `${sharpZipSize} bytes from installed @img/sharp-win32-x64@0.35.5`, {
    zipSha256: sharpZipSha,
    nodeSha256: sharpNodeSha,
    nodeSizeBytes: sharpNodeSize,
  });

  // ---- 5. origin port reservation (recorded; runners re-bind the same port) ----
  const originPort = await new Promise((res, rej) => {
    const probe = createServer();
    probe.once('error', rej);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close(() => res(port));
    });
  });
  await mkdir(join(TMP, 'origin'), { recursive: true });
  await writeFile(
    join(TMP, 'origin', 'endpoint.json'),
    JSON.stringify({ port: originPort, recordedAt: new Date().toISOString() }, null, 2),
  );
  await emit('ORIGIN_PORT', String(originPort));

  // ---- 6. catalog construction (all digests computed above) ----
  const ripgrepArtifact = {
    sizeBytes: download.sizeBytes,
    sha256: fetchSha,
  };
  const ripgrepBase = {
    id: 'cli.ripgrep',
    providerId: 'tool.ripgrep',
    version: '14.1.1',
    kind: 'cli',
    source: {
      url: RIPGREP_URL,
      approvedHosts: ['github.com', 'release-assets.githubusercontent.com'],
    },
    artifact: ripgrepArtifact,
    requirements: { os: 'win32', arch: 'x64', node: null },
    executable: { relativeName: 'rg.exe' },
    license: 'MIT OR Unlicense',
    publisher: 'BurntSushi',
    removal: { strategy: 'identity-pinned-native', scope: 'provider-and-download-roots' },
    verifier: { hash: 'sha256-whole-artifact', extractor: 'native-handle-relative' },
  };
  const ripgrepLocal = {
    ...ripgrepBase,
    source: {
      url: `http://127.0.0.1:${originPort}/${RIPGREP_NAME}`,
      approvedHosts: ['127.0.0.1'],
    },
  };
  const sharpEntry = {
    id: 'addon.sharp-win32-x64',
    providerId: 'tool.sharp-win32-x64',
    version: '0.35.5',
    kind: 'native-addon',
    source: {
      url: `http://127.0.0.1:${originPort}/${SHARP_NAME}`,
      approvedHosts: ['127.0.0.1'],
    },
    artifact: { sizeBytes: sharpZipSize, sha256: sharpZipSha },
    requirements: { os: 'win32', arch: 'x64', node: { napiVersion: 10 } },
    executable: null,
    license: 'Apache-2.0 AND LGPL-3.0-or-later',
    publisher: 'lovell/sharp (prebuilt @img/sharp-win32-x64)',
    removal: { strategy: 'identity-pinned-native', scope: 'provider-and-download-roots' },
    verifier: { hash: 'sha256-whole-artifact', extractor: 'native-handle-relative' },
    contents: {
      node: { relativePath: 'lib/sharp-win32-x64-0.35.5.node', sha256: sharpNodeSha, sizeBytes: sharpNodeSize },
    },
  };

  const mkCatalog = (entries, revision) => ({
    catalogRevision: revision,
    generatedAt: new Date().toISOString(),
    curator: 'research/i86-u04 pilot curator',
    note: 'all artifact digests computed from real bytes by this tooling; trust lives in the pinned key fingerprint, not in this file',
    entries,
  });

  const catalogReal = mkCatalog([ripgrepBase], 'R2');
  const catalogLocal = mkCatalog([ripgrepLocal, sharpEntry], 'R2');
  const catalogStale = mkCatalog([ripgrepBase], 'R1');

  const outDir = join(RESEARCH, 'catalogs');
  const written = {};
  for (const [name, catalog] of [
    ['catalog-real.json', catalogReal],
    ['catalog-local.json', catalogLocal],
    ['catalog-stale-R1.json', catalogStale],
  ]) {
    const signed = signCatalog(catalog, privatePem);
    await writeFile(join(outDir, name), JSON.stringify(signed, null, 2), 'utf8');
    written[name] = signed.signature.value.slice(0, 24);
  }

  // ---- 7. committed trust root ----
  const trustRoot = {
    algorithm: 'ed25519-spki-sha256',
    publicKeyFingerprint: fingerprint,
    publicKeyPem: publicPem,
    activeCatalogRevision: 'R2',
    note: 'trust anchor for the i86-U04 pilot: only this pinned key can authorize acquisition; downloadable content is never trusted because it is listed here',
  };
  await writeFile(join(RESEARCH, 'trust-root.json'), JSON.stringify(trustRoot, null, 2), 'utf8');

  await emit(
    'GEN_DONE',
    JSON.stringify({ catalogs: Object.keys(written), fingerprint, originPort }),
  );
  console.log('GEN OK', JSON.stringify({ fingerprint, originPort, ripgrep: ripgrepArtifact, sharpZipSha }));
}

function POWERSHELL() {
  return 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
}

async function emit(type, detail, extra = {}) {
  await events.emit(type, detail, extra);
}

main().catch(async (error) => {
  await events.emit('GEN_FAILED', String(error && error.stack ? error.stack : error).slice(0, 800));
  console.error('GEN FAILED', error);
  process.exit(1);
});
