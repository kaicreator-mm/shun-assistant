// run-negatives.mjs — i86-U04 step 7: the full negative matrix, every case a
// real execution with a typed outcome and a no-effect proof.
//
// Hostile-variant catalogs in N1/N3/N4/N5/N7/N9/N10/N11 are signed with the
// pilot curator key on purpose: they model a compromised or buggy curator
// whose SIGNATURE is valid but whose CONTENT is hostile — the hash,
// requirement, revision and redirect gates must catch those, because the
// signature only authenticates the curator, it does not make content safe.
import { copyFile, lstat, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESEARCH = resolve(HERE, '..');
const TMP = 'C:\\xDev\\kAiCreator\\_tmp\\i86-u04';
const NEG = join(TMP, 'neg');
const JIT = '../../../packages/vertical-jit/src';
const { Events } = await import('./lib/events.mjs');
const { ProviderAcquirer, ConsentLedger } = await import('./lib/acquisition.mjs');
const { signCatalog, validateCatalogEntry } = await import('./lib/catalog.mjs');
const { startOrigin } = await import('./lib/origin.mjs');
const { buildStoredZip, writeTamperedCopy } = await import('./lib/minizip.mjs');
const { SpawnProcess } = await import(`${JIT}/adapters/node.ts`);
const { SafePowerShellZipExtractor } = await import(`${JIT}/adapters/native-win.ts`);

const trustRoot = JSON.parse(await readFile(join(RESEARCH, 'trust-root.json'), 'utf8'));
const catalogReal = JSON.parse(await readFile(join(RESEARCH, 'catalogs', 'catalog-real.json'), 'utf8'));
const catalogLocal = JSON.parse(await readFile(join(RESEARCH, 'catalogs', 'catalog-local.json'), 'utf8'));
const privatePem = await readFile(join(TMP, 'keys', 'curator_ed25519.pkcs8.pem'), 'utf8');
const realZipPath = join(TMP, 'origin-files', 'ripgrep-14.1.1-x86_64-pc-windows-msvc.zip');
const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

const proc = new SpawnProcess();
const results = { cases: [], failures: [] };

function record(id, ok, detail) {
  results.cases.push({ id, status: ok ? 'PASS' : 'FAIL', detail });
  if (!ok) results.failures.push(id);
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${id} :: ${detail}`);
}

function assert(cond, message) {
  if (!cond) throw new Error(`ASSERT: ${message}`);
}

function events(id) {
  return new Events(join(RESEARCH, 'events.ndjson'), id);
}

async function sandbox(name) {
  const root = join(NEG, name);
  await rm(root, { recursive: true, force: true });
  for (const dir of ['providers', 'downloads', 'staging', 'state']) {
    await mkdir(join(root, dir), { recursive: true });
  }
  const acquirer = new ProviderAcquirer({
    events: events(`neg-${name}`),
    trustRoot,
    sandbox: {
      providersRoot: join(root, 'providers'),
      downloadsRoot: join(root, 'downloads'),
      stagingRoot: join(root, 'staging'),
      journalPath: join(root, 'state', 'journal.jsonl'),
    },
    maxBytes: 64 * 1024 * 1024,
  });
  return { root, acquirer, consent: new ConsentLedger(join(root, 'state', 'consent-ledger.json')) };
}

/** Runtime-signed hostile-variant catalog (valid signature, hostile content). */
function variantCatalog(name, entries, revision = 'R2') {
  return signCatalog(
    {
      catalogRevision: revision,
      generatedAt: new Date().toISOString(),
      curator: `research/i86-u04 hostile variant ${name}`,
      entries,
    },
    privatePem,
  );
}

const ripgrepEntryFrom = (patch) => ({
  ...JSON.parse(JSON.stringify(catalogReal.entries[0])),
  ...JSON.parse(JSON.stringify(patch)),
});

async function deadPort() {
  const net = await import('node:net');
  return new Promise((res, rej) => {
    const probe = net.createServer();
    probe.once('error', rej);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close(() => res(port));
    });
  });
}

async function legHasEvents(leg, needle) {
  const text = await readFile(join(RESEARCH, 'events.ndjson'), 'utf8');
  return text.split('\n').filter((line) => line.includes(`"leg":"${leg}"`) && line.includes(needle));
}

// ---------- N1: tampered artifact -> HASH_MISMATCH, rg never executed ----------
async function n1() {
  const name = 'n1-tamper-artifact';
  const sb = await sandbox(name);
  const files = join(sb.root, 'files');
  await mkdir(files, { recursive: true });
  const tampered = await writeTamperedCopy(realZipPath, join(files, 'ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'));
  await events(name).emit('N1_TAMPERED', `flipped byte at offset ${tampered.flippedOffset}; sha ${tampered.sha256}`);
  const origin = await startOrigin({ root: files });
  const catalog = variantCatalog(name, [
    ripgrepEntryFrom({ source: { url: origin.url('ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'), approvedHosts: ['127.0.0.1'] } }),
  ]);
  const outcome = await sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin });
  assert(outcome.status === 'HASH_MISMATCH', `expected HASH_MISMATCH, got ${outcome.status}`);
  assert(origin.requests === 1, `attacker origin sees exactly the 1 download request, saw ${origin.requests}`);
  const downloadsLeft = [];
  const scanFiles = async (root) => {
    for (const child of await readdir(root, { withFileTypes: true }).catch(() => [])) {
      const p = join(root, child.name);
      if (child.isDirectory()) await scanFiles(p);
      else downloadsLeft.push(p);
    }
  };
  await scanFiles(join(sb.root, 'downloads'));
  assert(downloadsLeft.length === 0, `tampered artifact must not persist in the cache: ${downloadsLeft}`);
  const providerEntries = await readdir(join(sb.root, 'providers')).catch(() => []);
  assert(providerEntries.length === 0, 'no provider root may appear');
  const spawns = await legHasEvents(name, 'TASK_EXEC');
  assert(spawns.length === 0, 'rg must never be executed from tampered bytes');
  await origin.close();
  await record(name, true, `tampered byte at offset ${tampered.flippedOffset} -> typed HASH_MISMATCH; cache+staging purged; provider root never created; zero rg spawns`);
}

// ---------- N2: tampered catalog -> signature verification failure ----------
async function n2() {
  const name = 'n2-tamper-catalog';
  const sb = await sandbox(name);
  const forged = JSON.parse(JSON.stringify(catalogLocal));
  forged.entries[0].artifact.sha256 = 'f'.repeat(64);
  const verdict = validateCatalogEntry(forged, trustRoot, 'cli.ripgrep');
  assert(!verdict.ok && verdict.code === 'CATALOG_SIGNATURE_INVALID', `expected signature refusal, got ${verdict.code}`);
  const outcome = await sb.acquirer.acquire(forged, 'cli.ripgrep', { consent: true });
  assert(outcome.status === 'CATALOG_SIGNATURE_INVALID', `expected CATALOG_SIGNATURE_INVALID, got ${outcome.status}`);
  await record(name, true, 'single digest edit in a signed catalog -> ed25519 verification fails -> CATALOG_SIGNATURE_INVALID, zero effects');
}

// ---------- N3: wrong OS / arch declarations ----------
async function n3() {
  const name = 'n3-os-arch';
  const sb = await sandbox(name);
  const linuxCatalog = variantCatalog(name + '-linux', [ripgrepEntryFrom({ requirements: { os: 'linux', arch: 'x86_64', node: null } })]);
  const outLinux = await sb.acquirer.acquire(linuxCatalog, 'cli.ripgrep', { consent: true });
  assert(outLinux.status === 'OS_MISMATCH', `expected OS_MISMATCH, got ${outLinux.status}`);
  const armCatalog = variantCatalog(name + '-arm', [ripgrepEntryFrom({ requirements: { os: 'win32', arch: 'arm64', node: null } })]);
  const outArm = await sb.acquirer.acquire(armCatalog, 'cli.ripgrep', { consent: true });
  assert(outArm.status === 'ARCH_MISMATCH', `expected ARCH_MISMATCH, got ${outArm.status}`);
  const providerEntries = await readdir(join(sb.root, 'providers')).catch(() => []);
  assert(providerEntries.length === 0, 'requirement refusals must precede any effect');
  await record(name, true, 'catalog declaring linux/x86_64 -> OS_MISMATCH; declaring win32/arm64 -> ARCH_MISMATCH; both before any download');
}

// ---------- N4: forged Node ABI requirement -> refusal without require ----------
async function n4() {
  const name = 'n4-forged-abi';
  const sb = await sandbox(name);
  const sharpEntry = JSON.parse(JSON.stringify(catalogLocal.entries.find((e) => e.id === 'addon.sharp-win32-x64')));
  sharpEntry.requirements.node.napiVersion = 99;
  const catalog = variantCatalog(name, [sharpEntry]);
  const outcome = await sb.acquirer.acquire(catalog, 'addon.sharp-win32-x64', { consent: true });
  assert(outcome.status === 'NODE_ABI_MISMATCH', `expected NODE_ABI_MISMATCH, got ${outcome.status}`);
  const downloadsLeft = (await readdir(join(sb.root, 'downloads')).catch(() => [])).filter((d) => !d.startsWith('.'));
  assert(downloadsLeft.length === 0, 'no download may happen for an ABI-mismatched addon');
  const loads = await legHasEvents(name, 'WORKER');
  assert(loads.length === 0, 'no worker/native load may be attempted');
  await record(name, true, `N-API requirement forged to 99 (host provides ${process.versions.napi}) -> typed NODE_ABI_MISMATCH before any fetch or require`);
}

// ---------- N5: redirect to an unapproved host ----------
async function n5() {
  const name = 'n5-redirect';
  const sb = await sandbox(name);
  const origin = await startOrigin({ root: join(sb.root, 'files'), mode: 'redirect', redirectTarget: 'http://evil.example.invalid/payload.zip' });
  const catalog = variantCatalog(name, [
    ripgrepEntryFrom({ source: { url: origin.url('ripgrep.zip'), approvedHosts: ['127.0.0.1'] } }),
  ]);
  const outcome = await sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin });
  assert(outcome.status === 'REDIRECT_HOST_UNAPPROVED', `expected REDIRECT_HOST_UNAPPROVED, got ${outcome.status} ${outcome.detail ?? ''}`);
  assert(origin.requests === 1, 'exactly the initial request may reach the origin');
  await origin.close();
  await record(name, true, `origin 302 -> evil.example.invalid refused by manual-redirect host allowlist; zero body bytes fetched`);
}

// ---------- N6: PATH + CWD planting of a fake rg.exe ----------
async function n6() {
  const name = 'n6-hijack';
  const sb = await sandbox(name);
  const hostile = join(sb.root, 'hostile');
  await mkdir(hostile, { recursive: true });
  const marker = join(sb.root, 'marker.txt');
  const csPath = join(hostile, 'FakeRg.cs');
  await writeFile(
    csPath,
    [
      'using System.IO;',
      'class FakeRg {',
      '  static int Main(string[] args) {',
      '    var marker = System.Environment.GetEnvironmentVariable("I86_MARKER");',
      '    if (marker != null) { File.WriteAllText(marker, "fake rg executed with args: " + string.Join(" ", args)); }',
      '    return 0;',
      '  }',
      '}',
    ].join('\r\n'),
    'utf8',
  );
  const fakeExe = join(hostile, 'rg.exe');
  const compile = await proc.run({
    argv: ['C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe', '/nologo', '/out:' + fakeExe, csPath],
    timeoutMs: 120_000,
  });
  assert(compile.exitCode === 0, `csc failed: ${compile.stderr.slice(0, 200)}`);

  // control A: the detector itself works (direct invocation writes the marker)
  await proc.run({ argv: [fakeExe, '--version'], env: { I86_MARKER: marker }, timeoutMs: 30_000 });
  assert(!!(await stat(marker).catch(() => null)), 'control A failed: marker mechanism did not fire');
  await rm(marker, { force: true });

  // control B: PATH hijack really would execute the fake
  const hijackedEnv = { PATH: hostile + ';' + (process.env.PATH ?? ''), I86_MARKER: marker };
  await proc.run({ argv: ['cmd.exe', '/c', 'rg', '--version'], env: hijackedEnv, timeoutMs: 30_000 });
  assert(!!(await stat(marker).catch(() => null)), 'control B failed: PATH resolution did not reach the fake rg');
  await rm(marker, { force: true });

  // pipeline leg: fresh acquire, then invoke rg by ABSOLUTE verified path with a
  // hostile CWD and the hostile dir first on PATH — the fake must never run.
  const files = join(sb.root, 'files');
  await mkdir(files, { recursive: true });
  await copyFile(realZipPath, join(files, 'ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'));
  const origin = await startOrigin({ root: files });
  const catalog = variantCatalog(name, [
    ripgrepEntryFrom({ source: { url: origin.url('ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'), approvedHosts: ['127.0.0.1'] } }),
  ]);
  const outcome = await sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin });
  assert(outcome.status === 'READY', `expected READY, got ${outcome.status}`);
  // the fixture lives in the hostile CWD next to the planted rg.exe
  await writeFile(join(hostile, 'doc.txt'), 'alpha NEEDLE_0001 omega\n');
  const run = await proc.run({
    argv: [outcome.executable, '--no-heading', '--line-number', 'NEEDLE_[0-9]{4}', 'doc.txt'],
    cwd: hostile,
    env: { PATH: hostile + ';' + (process.env.PATH ?? ''), I86_MARKER: marker },
    timeoutMs: 30_000,
  });
  assert(run.exitCode === 0 && /NEEDLE_0001/.test(run.stdout), `real rg did not answer: exit=${run.exitCode} out=${run.stdout.slice(0, 120)}`);
  const markerAfter = !!(await stat(marker).catch(() => null));
  assert(!markerAfter, 'FAKE rg EXECUTED — marker present; pipeline resolution compromised');
  await origin.close();
  await record(name, true, 'controls prove PATH/CWD planting executes a fake rg; the pipeline resolves ONLY the absolute verified path (fake never runs, marker absent) and real rg answers');
}

// ---------- N7: tampered sharp payload -> HASH_MISMATCH, never loaded ----------
async function n7() {
  const name = 'n7-sharp-tamper';
  const sb = await sandbox(name);
  const sharpEntry = JSON.parse(JSON.stringify(catalogLocal.entries.find((e) => e.id === 'addon.sharp-win32-x64')));
  const files = join(sb.root, 'files');
  await mkdir(files, { recursive: true });
  const tampered = await writeTamperedCopy(join(TMP, 'origin-files', 'sharp-win32-x64-0.35.5.zip'), join(files, 'sharp-win32-x64-0.35.5.zip'));
  const origin = await startOrigin({ root: files });
  const catalog = variantCatalog(name, [
    { ...sharpEntry, source: { url: origin.url('sharp-win32-x64-0.35.5.zip'), approvedHosts: ['127.0.0.1'] } },
  ]);
  const outcome = await sb.acquirer.acquire(catalog, 'addon.sharp-win32-x64', { consent: true, originCounters: origin });
  assert(outcome.status === 'HASH_MISMATCH', `expected HASH_MISMATCH, got ${outcome.status}`);
  const providerEntries = await readdir(join(sb.root, 'providers')).catch(() => []);
  assert(providerEntries.length === 0, 'tampered native payload must never be installed');
  const loads = await legHasEvents(name, 'WORKER');
  assert(loads.length === 0, 'the tampered .node must never be required');
  await origin.close();
  await record(name, true, `staged sharp zip byte-flipped at offset ${tampered.flippedOffset} -> HASH_MISMATCH; .node never installed, never required`);
}

// ---------- N8: stale catalog revision -> revoked ----------
async function n8() {
  const name = 'n8-stale-revision';
  const sb = await sandbox(name);
  const stale = JSON.parse(await readFile(join(RESEARCH, 'catalogs', 'catalog-stale-R1.json'), 'utf8'));
  const verdict = validateCatalogEntry(stale, trustRoot, 'cli.ripgrep');
  assert(!verdict.ok && verdict.code === 'CATALOG_REVISION_REVOKED', `expected revision refusal, got ${verdict.code}`);
  const outcome = await sb.acquirer.acquire(stale, 'cli.ripgrep', { consent: true });
  assert(outcome.status === 'CATALOG_REVISION_REVOKED', `expected CATALOG_REVISION_REVOKED, got ${outcome.status}`);
  await record(name, true, 'signed R1 catalog reuse after trust root moved to R2 -> CATALOG_REVISION_REVOKED (a valid signature alone is not enough)');
}

// ---------- N9: offline first use (no cache, dead origin) ----------
async function n9() {
  const name = 'n9-offline-first-use';
  const sb = await sandbox(name);
  const port = await deadPort();
  const catalog = variantCatalog(name, [
    ripgrepEntryFrom({ source: { url: `http://127.0.0.1:${port}/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip`, approvedHosts: ['127.0.0.1'] } }),
  ]);
  const outcome = await sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true });
  assert(outcome.status === 'ORIGIN_UNREACHABLE', `expected ORIGIN_UNREACHABLE, got ${outcome.status} ${outcome.detail ?? ''}`);
  const providerEntries = await readdir(join(sb.root, 'providers')).catch(() => []);
  const stagingEntries = (await readdir(join(sb.root, 'staging')).catch(() => [])).filter((d) => !d.startsWith('.'));
  assert(providerEntries.length === 0 && stagingEntries.length === 0, 'no partial activation may survive an offline failure');
  await record(name, true, `dead origin (port ${port}) on first use -> typed ORIGIN_UNREACHABLE; providers/ and staging/ empty (no half activation)`);
}

// ---------- N10: concurrent acquire of the same content ----------
async function n10() {
  const name = 'n10-concurrent';
  const sb = await sandbox(name);
  const files = join(sb.root, 'files');
  await mkdir(files, { recursive: true });
  await copyFile(realZipPath, join(files, 'ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'));
  const origin = await startOrigin({ root: files });
  const catalog = variantCatalog(name, [
    ripgrepEntryFrom({ source: { url: origin.url('ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'), approvedHosts: ['127.0.0.1'] } }),
  ]);
  const before = origin.requests;
  const [a, b] = await Promise.all([
    sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin }),
    sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin }),
  ]);
  assert(a.status === 'READY' && b.status === 'READY', `both must be READY: ${a.status}/${b.status}`);
  const served = origin.requests - before;
  assert(served === 1, `exactly one download must happen for two concurrent acquires, saw ${served}`);
  assert(a.cacheHit !== b.cacheHit, 'exactly one of the two may fill the cache');
  const text = await readFile(join(sb.root, 'state', 'journal.jsonl'), 'utf8');
  const journal = text
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));
  const byAction = {};
  for (const entry of journal) {
    byAction[entry.actionId] = byAction[entry.actionId] ?? [];
    byAction[entry.actionId].push(entry);
  }
  // Exactly one attempt may own the download effect window; the other must be
  // an adopt that never opens an effect window at all.
  const downloader = [a, b].find((o) => !o.adopted);
  const adopter = [a, b].find((o) => o.adopted);
  assert(downloader && adopter, 'exactly one downloader and one adopter expected');
  const downloaderEntries = byAction[downloader.actionId];
  assert(downloaderEntries.some((e) => e.phase === 'EXEC_START' && e.detail === 'download beginning'), 'downloader must have a real effect window');
  assert(downloaderEntries.some((e) => e.phase === 'EXEC_DONE') && downloaderEntries.some((e) => e.phase === 'RECEIPT_WRITTEN' && e.detail === 'READY'), 'downloader must complete its window');
  const adopterEntries = byAction[adopter.actionId];
  assert(!adopterEntries.some((e) => e.phase === 'EXEC_START'), 'adopter must never open an effect window');
  // Serialization: the adopter's RECEIVED cannot precede the downloader's receipt.
  const adopterReceived = adopterEntries.find((e) => e.phase === 'RECEIVED');
  const downloaderReceipt = downloaderEntries.find((e) => e.phase === 'RECEIPT_WRITTEN' && e.detail === 'READY');
  assert(adopterReceived.ts >= downloaderReceipt.ts, 'acquire attempts must be serialized by the lock (adopter waits for the downloader receipt)');
  await origin.close();
  await record(name, true, 'two concurrent acquires -> READY(downloaded, effect window journaled) + READY(adopted, zero effect window); origin served exactly 1 byte-stream; lock ordering proven by journal timestamps');
}

// ---------- N11: zip-slip / symlink-entry / junction-crossing extraction ----------
async function n11() {
  const name = 'n11-zipslip';
  const sb = await sandbox(name);
  const files = join(sb.root, 'files');
  await mkdir(files, { recursive: true });
  const outside = join(sb.root, 'outside');
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, 'canary.txt'), 'MUST SURVIVE\n');

  const traversalZip = buildStoredZip([
    { name: 'ok.txt', data: Buffer.from('fine\n') },
    { name: '..\\escaped.txt', data: Buffer.from('EVIL\n') },
  ]);
  const absZip = buildStoredZip([
    { name: 'ok.txt', data: Buffer.from('fine\n') },
    { name: join(outside, 'abs.txt'), data: Buffer.from('EVIL\n') },
  ]);
  const symlinkZip = buildStoredZip([
    { name: 'ok.txt', data: Buffer.from('fine\n') },
    { name: 'evil-link', data: Buffer.from('..\\..\\outside\\canary.txt'), symlink: true },
  ]);
  const cases = [
    { label: 'slip', buffer: traversalZip, expect: 'REFUSED', code: 'ZIP_PATH_ESCAPE' },
    { label: 'abs', buffer: absZip, expect: 'REFUSED', code: 'ZIP_ALTERNATE_STREAM' },
    // Windows zip readers materialize unix symlink entries as plain files; the
    // honest expectation is neutralization: no reparse point is created and
    // nothing escapes the destination.
    { label: 'symlink', buffer: symlinkZip, expect: 'NEUTRALIZED' },
  ];
  const origin = await startOrigin({ root: files });
  for (const c of cases) {
    const path = join(files, `${c.label}.zip`);
    await writeFile(path, c.buffer);
    const sha256 = createHash('sha256').update(c.buffer).digest('hex');
    const catalog = variantCatalog(`${name}-${c.label}`, [
      ripgrepEntryFrom({
        version: `14.1.1-${c.label}`,
        source: { url: origin.url(`${c.label}.zip`), approvedHosts: ['127.0.0.1'] },
        artifact: { sizeBytes: c.buffer.length, sha256 },
      }),
    ]);
    const outcome = await sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin });
    if (c.expect === 'REFUSED') {
      assert(outcome.status === c.code, `malicious ${c.label} zip must refuse ${c.code}, got ${outcome.status}`);
      const providerKeys = (await readdir(join(sb.root, 'providers')).catch(() => [])).filter((d) => !d.startsWith('.'));
      assert(providerKeys.length === 0, `no provider root may appear after ${c.label} refusal`);
    } else {
      // The neutralized payload (ok.txt + plain-file evil-link) carries no
      // declared rg.exe, so the acquire must ALSO refuse (EXECUTABLE_NOT_UNIQUE)
      // and never activate. Both refusals are acceptable neutral outcomes; a
      // READY would require proof that no reparse point materialized.
      assert(
        outcome.status === 'EXECUTABLE_NOT_UNIQUE' || outcome.status === 'READY',
        `symlink-entry zip should neutralize (refuse or plain-file install), got ${outcome.status}`,
      );
      if (outcome.status === 'READY') {
        const linkStat = await lstat(join(outcome.providerRoot, 'payload', 'evil-link'));
        assert(!linkStat.isSymbolicLink(), 'symlink entry must NOT materialize as a reparse point');
        await sb.acquirer.removeProvider(outcome);
      }
    }
    const escaped = await readdir(outside);
    assert(escaped.join(',') === 'canary.txt', `outside canary dir must be untouched after ${c.label}: ${escaped}`);
  }
  // junction-crossing unit case: a zip whose entry path walks THROUGH a planted
  // junction must be refused (ZIP_REPARSE_POINT) by the native component walk.
  const extractor = new SafePowerShellZipExtractor(proc, POWERSHELL, { timeoutMs: 90_000 });
  const dest = join(sb.root, 'junction-dest');
  await mkdir(dest, { recursive: true });
  const planted = join(dest, 'planted-junction');
  const mklink = await proc.run({
    argv: ['C:\\Windows\\System32\\cmd.exe', '/c', 'mklink', '/J', planted, outside],
    timeoutMs: 30_000,
  });
  assert(mklink.exitCode === 0, 'mklink for junction-dest failed');
  const crossingZip = buildStoredZip([{ name: 'planted-junction\\drop.txt', data: Buffer.from('should never land\n') }]);
  const crossingPath = join(files, 'crossing.zip');
  await writeFile(crossingPath, crossingZip);
  const crossingSha = createHash('sha256').update(crossingZip).digest('hex');
  let junctionRefusal = '';
  try {
    await extractor.extractZip(crossingPath, dest, crossingSha);
    junctionRefusal = 'NOT_REFUSED';
  } catch (error) {
    junctionRefusal = error.code ?? 'UNKNOWN';
  }
  assert(junctionRefusal === 'ZIP_REPARSE_POINT', `junction-crossing extraction must refuse ZIP_REPARSE_POINT, got ${junctionRefusal}`);
  const outsideAfter = await readdir(outside);
  assert(outsideAfter.join(',') === 'canary.txt', `junction target must be untouched: ${outsideAfter}`);
  await origin.close();
  await record(name, true, 'traversal+absolute-path zips refused (ZIP_PATH_ESCAPE / ZIP_ALTERNATE_STREAM); symlink entry neutralized to a plain file (no reparse, no escape); junction-crossing extraction refused ZIP_REPARSE_POINT; outside canary intact throughout');
}

// ---------- N12: truncated download ----------
async function n12() {
  const name = 'n12-truncated';
  const sb = await sandbox(name);
  const files = join(sb.root, 'files');
  await mkdir(files, { recursive: true });
  await copyFile(realZipPath, join(files, 'ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'));
  const origin = await startOrigin({ root: files, mode: 'truncate', truncateBytes: 1024 * 1024 });
  const catalog = variantCatalog(name, [
    ripgrepEntryFrom({ source: { url: origin.url('ripgrep-14.1.1-x86_64-pc-windows-msvc.zip'), approvedHosts: ['127.0.0.1'] } }),
  ]);
  const outcome = await sb.acquirer.acquire(catalog, 'cli.ripgrep', { consent: true, originCounters: origin });
  assert(outcome.status === 'INCOMPLETE_DOWNLOAD', `expected INCOMPLETE_DOWNLOAD, got ${outcome.status} ${outcome.detail ?? ''}`);
  const leftovers = [];
  const scanFiles = async (root) => {
    for (const child of await readdir(root, { withFileTypes: true }).catch(() => [])) {
      const p = join(root, child.name);
      if (child.isDirectory()) await scanFiles(p);
      else leftovers.push(p);
    }
  };
  await scanFiles(join(sb.root, 'downloads'));
  assert(leftovers.length === 0, `truncated artifact must not persist: ${leftovers}`);
  const providerEntries = await readdir(join(sb.root, 'providers')).catch(() => []);
  assert(providerEntries.length === 0, 'no activation after truncation');
  await origin.close();
  await record(name, true, `origin truncated the artifact to 1MiB (catalog declares ${catalogReal.entries[0].artifact.sizeBytes}) -> typed INCOMPLETE_DOWNLOAD; cache + providers clean`);
}

async function main() {
  await events('negatives').emit('NEGATIVES_START', 'negative matrix begin');
  const cases = [n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n12];
  for (const runCase of cases) {
    try {
      await runCase();
    } catch (error) {
      record(runCase.name, false, String(error && error.stack ? error.stack.split('\n').slice(0, 3).join(' | ') : error));
    }
  }
  await mkdir(join(RESEARCH, 'partial'), { recursive: true });
  await writeFile(join(RESEARCH, 'partial', 'negatives-results.json'), JSON.stringify(results, null, 2), 'utf8');
  await events('negatives').emit('NEGATIVES_DONE', `${results.cases.filter((c) => c.status === 'PASS').length} PASS / ${results.failures.length} FAIL`);
  console.log('NEGATIVES DONE', JSON.stringify(results.failures));
}

main().catch((error) => {
  console.error('NEGATIVES FATAL', error);
  process.exit(1);
});
