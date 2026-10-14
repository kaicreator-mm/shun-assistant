// run-pipeline.mjs — i86-U04 steps 3-7.
//
// P1  consent gate (no consent -> typed refusal, zero effects)
// P2  full acquire from the real vendor URL (states through READY)
// P3  independent action authorization + real rg task with an independent oracle
// P4  removal leg: canary fail-closed, junction refusal, resolve, identity-pinned removal
// P5  cache fill through the local origin (1 request)
// P6a cache replay with origin UP (0 requests — count as proof)
// P6b offline replay with origin dead (cache only)
// P7  interrupted-attempt reconciliation (torn journal + half staging file)
import { mkdir, readdir, readFile, rm, stat, writeFile, lstat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESEARCH = resolve(HERE, '..');
const WORKTREE = resolve(RESEARCH, '..', '..');
const TMP = 'C:\\xDev\\kAiCreator\\_tmp\\i86-u04';
const JIT = '../../../packages/vertical-jit/src';
const { Events } = await import('./lib/events.mjs');
const { ProviderAcquirer, ConsentLedger, TaskAuthorization } = await import('./lib/acquisition.mjs');
const { stableKey } = await import('./lib/catalog.mjs');
const { startOrigin } = await import('./lib/origin.mjs');
const { sha256File } = await import('./lib/downloader.mjs');
const { buildFixtureText, expectedMatches, parseRgOutput, oracleVerdict } = await import('./lib/oracle.mjs');
const { SpawnProcess, FileJournal, NodeFilesystem } = await import(`${JIT}/adapters/node.ts`);
const { removeManifestEntries } = await import(`${JIT}/manifest-removal.ts`);

const events = new Events(join(RESEARCH, 'events.ndjson'), 'pipeline');
const SANDBOX = join(TMP, 'sandbox');
const results = { legs: [], failures: [] };

function record(id, ok, detail) {
  results.legs.push({ id, status: ok ? 'PASS' : 'FAIL', detail });
  if (!ok) results.failures.push(id);
  return events.emit(ok ? 'LEG_PASS' : 'LEG_FAIL', `${id} :: ${detail}`);
}

function assert(cond, message) {
  if (!cond) throw new Error(`ASSERT: ${message}`);
}

const trustRoot = JSON.parse(await readFile(join(RESEARCH, 'trust-root.json'), 'utf8'));
const catalogReal = JSON.parse(await readFile(join(RESEARCH, 'catalogs', 'catalog-real.json'), 'utf8'));
const catalogLocal = JSON.parse(await readFile(join(RESEARCH, 'catalogs', 'catalog-local.json'), 'utf8'));
const endpoint = JSON.parse(await readFile(join(TMP, 'origin', 'endpoint.json'), 'utf8'));

for (const dir of ['providers', 'downloads', 'staging', 'state', 'fixtures', 'canary-outside']) {
  await rm(join(SANDBOX, dir), { recursive: true, force: true });
  await mkdir(join(SANDBOX, dir), { recursive: true });
}

const acquirer = new ProviderAcquirer({
  events,
  trustRoot,
  sandbox: {
    providersRoot: join(SANDBOX, 'providers'),
    downloadsRoot: join(SANDBOX, 'downloads'),
    stagingRoot: join(SANDBOX, 'staging'),
    journalPath: join(SANDBOX, 'state', 'journal.jsonl'),
  },
  maxBytes: 64 * 1024 * 1024,
});
const consentLedger = new ConsentLedger(join(SANDBOX, 'state', 'consent-ledger.json'));
const taskAuthz = new TaskAuthorization(join(SANDBOX, 'state', 'task-authz.json'));
const proc = new SpawnProcess();
const entryId = 'cli.ripgrep';

// ---------- P1: consent gate ----------
{
  await events.emit('P1_START', 'absent -> PENDING_CONSENT -> refusal without consent');
  const before = await readdir(join(SANDBOX, 'downloads')).catch(() => []);
  const refused = await acquirer.acquire(catalogReal, entryId, { consentLedger });
  assert(refused.status === 'CONSENT_REQUIRED', `expected CONSENT_REQUIRED, got ${refused.status}`);
  assert(refused.states.includes('PENDING_CONSENT'), 'state machine passed through PENDING_CONSENT');
  const after = await readdir(join(SANDBOX, 'downloads')).catch(() => []);
  assert(before.length === after.length, 'no download directory appeared without consent');
  const journalLines = (await readFile(join(SANDBOX, 'state', 'journal.jsonl'), 'utf8').catch(() => '')).length;
  assert(journalLines === 0, 'no journal activity without consent');
  await record('P1-consent-gate', true, `CONSENT_REQUIRED before any network/fs/journal effect (downloads dir entries: ${after.length})`);
}

// ---------- P2: full acquire over the real network ----------
let outcome;
{
  await events.emit('P2_START', 'real vendor download with explicit consent');
  await consentLedger.grant(entryId, catalogReal.entries[0].artifact.sha256, 'i86-U04 pilot task: fixture search');
  outcome = await acquirer.acquire(catalogReal, entryId, { consentLedger });
  assert(outcome.status === 'READY', `expected READY, got ${outcome.status} ${outcome.detail ?? ''}`);
  assert(outcome.states.join('->').includes('ACQUIRING->HASH_VERIFIED->INSTALLED->READY'), `states: ${outcome.states.join('->')}`);
  assert(outcome.cacheHit === false, 'first acquire must not be a cache hit');
  const ready = await acquirer.verifyReady(outcome);
  assert(ready.inRoot, 'executable resolves inside the provider root');
  const journal = await new FileJournal(join(SANDBOX, 'state', 'journal.jsonl')).replay();
  const phases = journal.filter((e) => e.actionId === outcome.actionId).map((e) => e.phase);
  for (const phase of ['RECEIVED', 'VALIDATED', 'EXEC_START', 'EXEC_DONE', 'RECEIPT_WRITTEN']) {
    assert(phases.includes(phase), `journal missing ${phase}`);
  }
  await record(
    'P2-real-acquire-READY',
    true,
    `states ${outcome.states.join('->')}; rg.exe ${ready.bytes}B sha ${ready.sha256}; journal phases ${phases.join(',')}`,
  );
  results.rgExeSha256 = ready.sha256;
  results.rgExeBytes = ready.bytes;
  results.downloadSha256 = outcome.download.sha256;
  results.downloadBytes = outcome.download.sizeBytes;
  results.downloadHops = outcome.download.hops.map((h) => h.host);
}

// ---------- P3: separate action authorization + independent oracle ----------
{
  await events.emit('P3_START', 'task authorization is separate from download consent');
  // explicit revoke then attempt -> typed refusal, zero spawns
  await taskAuthz.revoke();
  const fixture = buildFixtureText(6, 40);
  const fixtureDir = join(SANDBOX, 'fixtures');
  for (const file of fixture) await writeFile(join(fixtureDir, file.name), file.lines.join('\n') + '\n');
  const unauthorized = await executeSearchTask(outcome, fixtureDir, taskAuthz);
  assert(unauthorized.status === 'TASK_NOT_AUTHORIZED', `expected TASK_NOT_AUTHORIZED, got ${unauthorized.status}`);
  assert(unauthorized.spawned !== true, 'rg must not spawn without authorization');
  await events.emit('P3_UNAUTHORIZED_REFUSED', 'execution refused without a task authorization record');

  await taskAuthz.grant(entryId);
  const run = await executeSearchTask(outcome, fixtureDir, taskAuthz);
  assert(run.status === 'EXECUTED', `expected EXECUTED, got ${run.status}: ${run.detail ?? ''}`);
  const expected = expectedMatches(fixture);
  const actual = parseRgOutput(run.stdout);
  const verdict = oracleVerdict(expected, actual);
  assert(verdict.match, `oracle mismatch: ${JSON.stringify(verdict).slice(0, 300)}`);
  const version = await proc.run({
    argv: [outcome.executable, '--version'],
    timeoutMs: 30_000,
  });
  await record(
    'P3-authorized-task-oracle',
    true,
    `expected ${verdict.expectedCount} == actual ${verdict.actualCount} matched lines (independent line-scan oracle); rg --version: ${version.stdout.trim().split(/\r?\n/)[0]}`,
  );
  results.rgVersion = version.stdout.trim().split(/\r?\n/)[0];
  results.oracleExpected = verdict.expectedCount;

  // task authorization expiry negative
  await taskAuthz.grant(entryId, -1);
  const expired = await executeSearchTask(outcome, fixtureDir, taskAuthz);
  assert(expired.status === 'TASK_AUTHORIZATION_EXPIRED', `expected expiry, got ${expired.status}`);
  await taskAuthz.revoke();
  await record('P3-authz-separation', true, 'download consent never granted run rights: refusal, expiry, and grant are typed and separate');
}

/** Spawn the verified executable by ABSOLUTE path only, after authorization. */
async function executeSearchTask(outcome, fixtureDir, authz) {
  const check = await authz.check(outcome.entry.id);
  if (!check.ok) return { status: check.code, spawned: false };
  const exe = resolve(outcome.executable);
  if (!exe.toLowerCase().startsWith(resolve(outcome.providerRoot).toLowerCase() + '\\')) {
    return { status: 'EXECUTABLE_OUTSIDE_PROVIDER_ROOT', spawned: false };
  }
  if (!outcome.ownedManifest.map((p) => resolve(p)).includes(exe)) {
    return { status: 'EXECUTABLE_NOT_IN_OWNED_MANIFEST', spawned: false };
  }
  // Bare fixture names + cwd: rg echoes exactly the names it was given, which
  // keeps the oracle's line format independent of absolute paths.
  const run = await proc.run({
    argv: [exe, '--no-heading', '--line-number', 'NEEDLE_[0-9]{4}', ...(await readdir(fixtureDir))],
    cwd: fixtureDir,
    timeoutMs: 60_000,
  });
  await events.emit('TASK_EXEC', `rg exit ${run.exitCode}`, { argv0: exe, timedOut: run.timedOut });
  return { status: 'EXECUTED', exitCode: run.exitCode, stdout: run.stdout, stderr: run.stderr, spawned: true, argv0: exe };
}

// ---------- P4: removal leg ----------
{
  await events.emit('P4_START', 'canary + junction + identity-pinned removal');
  const providerRoot = outcome.providerRoot;
  const canaryPath = join(providerRoot, 'user-canary.txt');
  await writeFile(canaryPath, 'USER DATA — must survive\n');

  // (a) effect-time scope exclusivity refuses when unrecorded content exists
  const refusal = await acquirer.removalScopeRefusal(outcome);
  assert(refusal && refusal.includes('user-canary.txt'), `expected canary refusal, got: ${refusal}`);
  const canaryAlive1 = !!(await stat(canaryPath).catch(() => null));
  assert(canaryAlive1, 'canary must survive the refusal');
  const exeAlive1 = !!(await stat(outcome.executable).catch(() => null));
  assert(exeAlive1, 'provider must be retained on refusal (fail closed)');
  await record('P4a-scope-refusal-canary', true, `refusal names the canary; zero deletions; canary + provider intact: ${refusal.slice(0, 140)}`);

  // (b) junction planted inside the provider root -> native refusal, target untouched
  const outsideTarget = join(SANDBOX, 'canary-outside');
  const sentinel = join(outsideTarget, 'sentinel.txt');
  await writeFile(sentinel, 'SENTINEL — outside all provider roots\n');
  const junctionPath = join(providerRoot, 'junction-dir');
  const mklink = await proc.run({
    argv: ['C:\\Windows\\System32\\cmd.exe', '/c', 'mklink', '/J', junctionPath, outsideTarget],
    timeoutMs: 30_000,
  });
  assert(mklink.exitCode === 0, `mklink failed: ${mklink.stderr.slice(0, 120)}`);
  const removalResultJunction = await acquirer.removeProvider(outcome);
  const junctionRefusal = JSON.stringify(removalResultJunction);
  const providerRootRefused = !removalResultJunction[outcome.providerRoot].ok;
  assert(providerRootRefused, `expected provider-root refusal with junction present: ${junctionRefusal.slice(0, 240)}`);
  assert(removalResultJunction[outcome.downloadRoot] === undefined, 'refusal must stop before the cache root (no cascade)');
  const exeAlive2 = !!(await stat(outcome.executable).catch(() => null));
  const sentinelIntact = !!(await stat(sentinel).catch(() => null));
  assert(exeAlive2, 'provider intact after junction refusal');
  assert(sentinelIntact, 'junction target sentinel must be untouched');
  await events.emit('P4B_JUNCTION', junctionRefusal.slice(0, 400));
  await record('P4b-junction-refusal', true, `native removal refuses reparse content; provider retained; junction sentinel untouched`);

  // (c) human resolves the foreign content -> identity-pinned removal completes
  await rm(canaryPath, { force: true });
  await rm(junctionPath, { recursive: true, force: true });
  const removed = await acquirer.removeProvider(outcome);
  const allOk = Object.values(removed).every((r) => r.ok || r.absentRoot);
  assert(allOk, `pinned removal failed: ${JSON.stringify(removed).slice(0, 240)}`);
  const rootGone = !(await stat(providerRoot).catch(() => null));
  const downloadGone = !(await stat(outcome.downloadRoot).catch(() => null));
  const sentinelAlive = !!(await stat(sentinel).catch(() => null));
  assert(rootGone && downloadGone && sentinelAlive, 'roots removed, sentinel must survive');
  await record('P4c-identity-pinned-removal', true, `provider + download roots removed by install-time NT identity; outside sentinel survives`);

  // (d) unit-level manifest-restricted removal (v0.1 removeManifestEntries semantics)
  const unitRoot = join(SANDBOX, 'staging', 'unit-manifest');
  const unitDirA = join(unitRoot, 'a');
  await mkdir(unitDirA, { recursive: true });
  await writeFile(join(unitDirA, 'owned.txt'), 'owned\n');
  await writeFile(join(unitDirA, 'canary.txt'), 'USER\n');
  const fsPort = new NodeFilesystem();
  const spec = {
    manifest: [unitRoot, unitDirA, join(unitDirA, 'owned.txt')],
    scopeRoots: [unitRoot],
  };
  const unit = await removeManifestEntries({ removeEntry: async (p) => { await rm(p, { force: true }); return true; } }, fsPort, spec);
  const canaryUnitAlive = !!(await stat(join(unitDirA, 'canary.txt')).catch(() => null));
  const ownedGone = !(await stat(join(unitDirA, 'owned.txt')).catch(() => null));
  const dirRetained = unit.retained.includes(unitDirA);
  assert(canaryUnitAlive && ownedGone && dirRetained, `unit manifest removal wrong: ${JSON.stringify(unit)}`);
  await rm(unitRoot, { recursive: true, force: true });
  await record('P4d-manifest-restricted-unit', true, 'deepest-first manifest removal removes exactly recorded files; recorded dir holding a canary is RETAINED; canary survives');
}

// ---------- P5: cache fill through the local origin ----------
let origin;
{
  await events.emit('P5_START', 'origin-backed acquire fills the content-addressed cache');
  origin = await startOrigin({ root: join(TMP, 'origin-files'), port: endpoint.port });
  const before = origin.requests;
  outcome = await acquirer.acquire(catalogLocal, entryId, { consent: true, originCounters: origin });
  assert(outcome.status === 'READY', `expected READY, got ${outcome.status} ${outcome.detail ?? ''}`);
  const served = origin.requests - before;
  assert(served === 1, `origin must serve exactly 1 cache-fill download, saw ${served}`);
  assert(outcome.cacheHit === false, 'this acquire fills the cache (previous removal included it)');
  await acquirer.verifyReady(outcome);
  // quick re-task through the same oracle machinery
  await taskAuthz.grant(entryId);
  const fixtureDir = join(SANDBOX, 'fixtures');
  const run = await executeSearchTask(outcome, fixtureDir, taskAuthz);
  assert(run.status === 'EXECUTED');
  const fixture = await readFixtureBack(fixtureDir);
  const verdict = oracleVerdict(expectedMatches(fixture), parseRgOutput(run.stdout));
  assert(verdict.match, 'oracle mismatch on origin-acquired provider');
  await taskAuthz.revoke();
  await record('P5-origin-cache-fill', true, `origin requests=${served}; READY; oracle re-verified on origin-served bytes (${verdict.actualCount} lines)`);
  const removed = await acquirer.removeProvider(outcome, { includeCache: false });
  assert(Object.values(removed).every((r) => r.ok || r.absentRoot), 'provider-only removal failed');
  await record('P5-removal-retain-cache', true, 'provider root removed, replay cache deliberately retained');
}

async function readFixtureBack(dir) {
  const files = [];
  for (const name of await readdir(dir)) {
    const text = await readFile(join(dir, name), 'utf8');
    files.push({ name, lines: text.replace(/\n$/, '').split('\n') });
  }
  return files;
}

// ---------- P6a: cache replay with origin UP (0 requests) ----------
{
  await events.emit('P6A_START', 'cache replay while origin is up — request count must stay 0');
  const before = origin.requests;
  outcome = await acquirer.acquire(catalogLocal, entryId, { consent: true, originCounters: origin });
  assert(outcome.status === 'READY', `expected READY, got ${outcome.status}`);
  assert(outcome.cacheHit === true, 'must hit the content-addressed cache');
  const served = origin.requests - before;
  assert(served === 0, `origin must receive ZERO requests on cache hit, saw ${served}`);
  await acquirer.verifyReady(outcome);
  await record('P6a-cache-replay-zero-download', true, `origin request count delta = ${served}; READY from verified cache (sha re-checked before use)`);
  const removed = await acquirer.removeProvider(outcome, { includeCache: false });
  assert(Object.values(removed).every((r) => r.ok || r.absentRoot), 'provider-only removal failed');
}

// ---------- P6b: offline replay (origin dead, cache present) ----------
{
  await origin.close();
  await events.emit('P6B_START', 'origin closed — offline replay from cache only');
  const probe = await fetch(`http://127.0.0.1:${endpoint.port}/probe`, { signal: AbortSignal.timeout(5000) }).then(
    () => 'up',
    (error) => `down (${String(error.cause?.code ?? error.name)})`,
  );
  assert(probe.startsWith('down'), `origin port must be dead, probe=${probe}`);
  outcome = await acquirer.acquire(catalogLocal, entryId, { consent: true });
  assert(outcome.status === 'READY', `expected READY offline, got ${outcome.status}`);
  assert(outcome.cacheHit === true, 'offline READY must come from cache');
  await acquirer.verifyReady(outcome);
  await record('P6b-offline-replay', true, `origin probe: ${probe}; READY from cache with zero network possibility`);
  const removed = await acquirer.removeProvider(outcome, { includeCache: false });
  assert(Object.values(removed).every((r) => r.ok || r.absentRoot), 'provider-only removal failed');
}

// ---------- P7: interrupted attempt reconciliation ----------
{
  await events.emit('P7_START', 'torn journal + half staging file -> reconcile -> clean READY');
  const key = stableKey(entryId, catalogLocal.entries.find((e) => e.id === entryId).version);
  const tornActionId = `acquire-${key}-torn-attempt`;
  const journal = new FileJournal(join(SANDBOX, 'state', 'journal.jsonl'));
  await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIVED', actionId: tornActionId, attemptId: 'torn' });
  await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'VALIDATED', actionId: tornActionId, attemptId: 'torn' });
  await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'EXEC_START', actionId: tornActionId, attemptId: 'torn', detail: 'download beginning' });
  // half-downloaded staging garbage, exactly what a killed worker leaves behind
  const stagingDir = join(SANDBOX, 'staging', key);
  await mkdir(stagingDir, { recursive: true });
  await writeFile(join(stagingDir, 'artifact-half.zip'), Buffer.alloc(1024 * 512, 0x5a));
  const { classifyFromJournal } = await import(`${JIT}/journal.ts`);
  const allEntries = await journal.replay();
  const classification = classifyFromJournal(allEntries, tornActionId);
  assert(classification === 'MAY_HAVE_EXECUTED_UNCERTAIN', `torn attempt must classify uncertain, got ${classification}`);

  outcome = await acquirer.acquire(catalogLocal, entryId, { consent: true });
  assert(outcome.status === 'READY', `expected clean READY after reconcile, got ${outcome.status}`);
  const stagingGone = !(await stat(stagingDir).catch(() => null));
  assert(stagingGone, 'stale staging garbage must be purged by reconciliation');
  const journalAfter = await journal.replay();
  const readyReceipts = journalAfter.filter((e) => e.phase === 'RECEIPT_WRITTEN' && e.detail === 'READY');
  assert(readyReceipts.length >= 1, 'READY receipt must be journaled');
  const myRecon = journalAfter.filter((e) => e.actionId === outcome.actionId).map((e) => e.phase);
  assert(myRecon.includes('EXEC_START') && myRecon.includes('EXEC_DONE'), 'new attempt completed its own effect window');
  await acquirer.verifyReady(outcome);
  await record('P7-reconcile-interrupt', true, `torn=${classification} -> staging purged -> fresh attempt READY (cache hit); no half-activation at any point`);
  const removed = await acquirer.removeProvider(outcome, { includeCache: true });
  assert(Object.values(removed).every((r) => r.ok || r.absentRoot), 'final full removal failed');
  const rootGone = !(await stat(outcome.providerRoot).catch(() => null));
  assert(rootGone, 'final state: provider fully removed');
  await record('P7-final-cleanup', true, 'final full removal (provider + cache) completed');
}

await mkdir(join(RESEARCH, 'partial'), { recursive: true });
await writeFile(join(RESEARCH, 'partial', 'pipeline-results.json'), JSON.stringify(results, null, 2), 'utf8');
await events.emit('PIPELINE_DONE', `${results.legs.filter((l) => l.status === 'PASS').length} PASS / ${results.failures.length} FAIL`);
console.log('PIPELINE DONE', JSON.stringify(results.failures));
