// acquisition.mjs — minimal trusted provider JIT acquisition state machine.
//
// abs -> PENDING_CONSENT -> CONSENTED -> ACQUIRING -> HASH_VERIFIED ->
// INSTALLED -> READY, with typed refusals at every gate and no partial
// activation: the provider root only ever appears through one atomic rename
// of a fully hash-verified, fully extracted staging payload.
//
// Reuse from v0.1 vertical-jit: SafePowerShellZipExtractor + PowerShellNativeDeleter
// + SpawnProcess + FileJournal + classifyFromJournal + effectTimeScopeRefusal +
// NodeFilesystem + AcquisitionError + stableKey naming + exclusive-root creation
// semantics. This module composes them around a curated signed catalog instead
// of the winget transport.
import { mkdir, readdir, readFile, rename, rm, stat, writeFile, lstat } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const JIT = '../../../../packages/vertical-jit/src';
const { SafePowerShellZipExtractor, PowerShellNativeDeleter } = await import(`${JIT}/adapters/native-win.ts`);
const { SpawnProcess, FileJournal, NodeFilesystem } = await import(`${JIT}/adapters/node.ts`);
const { classifyFromJournal } = await import(`${JIT}/journal.ts`);
const { effectTimeScopeRefusal } = await import(`${JIT}/manifest-removal.ts`);
const { AcquisitionError } = await import(`${JIT}/ports.ts`);
const { validateCatalogEntry, stableKey } = await import('./catalog.mjs');
const { downloadTo, sha256File } = await import('./downloader.mjs');

const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

export class ConsentLedger {
  #path;
  constructor(path) {
    this.#path = path;
  }
  async #load() {
    try {
      return JSON.parse(await readFile(this.#path, 'utf8'));
    } catch {
      return { grants: [] };
    }
  }
  /** Explicit, purpose-bound consent for downloading+installing one artifact. */
  async grant(entryId, artifactSha256, purpose) {
    const data = await this.#load();
    data.grants.push({ entryId, artifactSha256, purpose, grantedAt: new Date().toISOString() });
    await mkdir(dirname(this.#path), { recursive: true });
    await writeFile(this.#path, JSON.stringify(data, null, 2), 'utf8');
  }
  async find(entryId, artifactSha256) {
    const data = await this.#load();
    return data.grants.find((g) => g.entryId === entryId && g.artifactSha256 === artifactSha256) ?? null;
  }
}

/** Separate execution authorization: download consent never implies run rights. */
export class TaskAuthorization {
  #path;
  constructor(path) {
    this.#path = path;
  }
  async grant(entryId, ttlMs = 10 * 60_000) {
    const record = { entryId, action: 'execute', grantedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + ttlMs).toISOString() };
    await mkdir(dirname(this.#path), { recursive: true });
    await writeFile(this.#path, JSON.stringify(record, null, 2), 'utf8');
    return record;
  }
  async check(entryId, now = new Date()) {
    try {
      const record = JSON.parse(await readFile(this.#path, 'utf8'));
      if (record.entryId !== entryId || record.action !== 'execute') return { ok: false, code: 'TASK_NOT_AUTHORIZED' };
      if (Date.parse(record.expiresAt) < now.getTime()) return { ok: false, code: 'TASK_AUTHORIZATION_EXPIRED' };
      return { ok: true, record };
    } catch {
      return { ok: false, code: 'TASK_NOT_AUTHORIZED' };
    }
  }
  async revoke() {
    await rm(this.#path, { force: true });
  }
}

function within(child, root) {
  const r = resolve(root);
  const c = resolve(child);
  return c === r || c.toLowerCase().startsWith(`${r.toLowerCase()}${sep}`);
}

export class ProviderAcquirer {
  /**
   * deps:
   *   events            — Events instance
   *   trustRoot         — parsed trust-root.json
   *   sandbox           — { providersRoot, downloadsRoot, stagingRoot, journalPath, consentPath, taskAuthzPath }
   *   maxBytes          — download size budget
   */
  #events;
  #trustRoot;
  #sandbox;
  #maxBytes;
  #process;
  #extractor;
  #deleter;
  #fs;
  #mutex = new Map();

  constructor(deps) {
    this.#events = deps.events;
    this.#trustRoot = deps.trustRoot;
    this.#sandbox = deps.sandbox;
    this.#maxBytes = deps.maxBytes ?? 256 * 1024 * 1024;
    this.#process = new SpawnProcess();
    this.#extractor = new SafePowerShellZipExtractor(this.#process, POWERSHELL, { timeoutMs: 180_000 });
    this.#deleter = new PowerShellNativeDeleter(this.#process, POWERSHELL, { timeoutMs: 180_000 });
    this.#fs = new NodeFilesystem();
  }

  get deleter() {
    return this.#deleter;
  }

  #journal() {
    return new FileJournal(this.#sandbox.journalPath);
  }

  /**
   * Restart reconciliation BEFORE any new work: journal-only classification of
   * the entry's latest attempt; torn attempts resolve to staging purge
   * (staging is disposable and never activated, so purge can never destroy
   * installed state). Returns {reconciled, classification, actions}.
   */
  async reconcile(entryId, version) {
    const key = stableKey(entryId, version);
    const actions = [];
    const entries = await this.#journal().replay();
    const mine = entries.filter((entry) => String(entry.actionId ?? '').startsWith(`acquire-${key}`));
    let classification = 'NO_ENTRIES';
    if (mine.length > 0) {
      const latest = mine[mine.length - 1].actionId;
      classification = classifyFromJournal(entries, latest);
    }
    // Staging purge is unconditional and safe: activation is rename-based.
    const stagingDir = join(this.#sandbox.stagingRoot, key);
    try {
      await lstat(stagingDir);
      await rm(stagingDir, { recursive: true, force: true });
      actions.push(`purged stale staging ${stagingDir}`);
    } catch {
      /* absent: nothing to purge */
    }
    // Provider root present without a READY receipt is stale by construction:
    // refuse reuse (v0.1 managed-portable exclusive-root semantics).
    const providerRoot = join(this.#sandbox.providersRoot, key);
    const ready = mine.some((entry) => entry.phase === 'RECEIPT_WRITTEN' && entry.detail === 'READY');
    let rootStale = false;
    try {
      await lstat(providerRoot);
      rootStale = !ready;
    } catch {
      /* absent */
    }
    await this.#events.emit('RECONCILE', JSON.stringify({ entryId, classification, actions, rootStale }));
    return { reconciled: actions.length > 0 || classification === 'MAY_HAVE_EXECUTED_UNCERTAIN', classification, actions, rootStale };
  }

  /**
   * Full typed acquisition. Never downloads before consent; never installs
   * anything that did not hash-verify; never leaves a partial provider root.
   */
  async acquire(catalog, entryId, { consent, consentLedger, originCounters } = {}) {
    const states = [];
    const push = (s) => {
      states.push(s);
      return this.#events.emit('STATE', s);
    };
    await push('ABSENT');

    const check = validateCatalogEntry(catalog, this.#trustRoot, entryId);
    if (!check.ok) {
      await this.#events.emit('REFUSED', check.code, { detail: check.detail });
      return { status: check.code, detail: check.detail, states };
    }
    const entry = check.entry;
    const key = stableKey(entry.id, entry.version);
    const providerRoot = join(this.#sandbox.providersRoot, key);
    const downloadRoot = join(this.#sandbox.downloadsRoot, key);
    const stagingDir = join(this.#sandbox.stagingRoot, key);
    const cachePath = join(downloadRoot, `artifact-${entry.artifact.sha256.slice(0, 16)}.zip`);

    await push('PENDING_CONSENT');
    const existingConsent =
      consent === true
        ? { grantedAt: 'passed-inline' }
        : await consentLedger?.find(entryId, entry.artifact.sha256);
    if (!existingConsent) {
      await this.#events.emit('REFUSED', 'CONSENT_REQUIRED', 'no explicit consent for this artifact — no network or fs effect performed');
      return { status: 'CONSENT_REQUIRED', states, entry, key };
    }
    await this.#events.emit('CONSENT', 'explicit consent present', { grantedAt: existingConsent.grantedAt ?? 'inline' });
    await push('CONSENTED');

    // Serialize concurrent acquires of the same content (in-process mutex +
    // exclusive staging lock directory).
    while (this.#mutex.has(key)) {
      await this.#events.emit('LOCK_WAIT', 'another acquire for the same content is in flight');
      await this.#mutex.get(key).catch(() => {});
    }
    let releaseLock;
    const lockPromise = new Promise((res) => (releaseLock = res));
    this.#mutex.set(key, lockPromise);
    try {
      const lockDir = join(this.#sandbox.stagingRoot, `.lock-${key}`);
      let lockHeld = false;
      for (let waited = 0; waited < 120_000; waited += 1000) {
        try {
          await mkdir(lockDir);
          lockHeld = true;
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 1000));
        }
      }
      if (!lockHeld) {
        return { status: 'LOCK_TIMEOUT', states, entry, key };
      }
      try {
        return await this.#acquireLocked(entry, key, {
          providerRoot,
          downloadRoot,
          stagingDir,
          cachePath,
          push,
          states,
          originCounters,
        });
      } finally {
        await rm(lockDir, { recursive: true, force: true }).catch(() => {});
      }
    } finally {
      this.#mutex.delete(key);
      releaseLock();
    }
  }

  async #acquireLocked(entry, key, ctx) {
    const { providerRoot, downloadRoot, stagingDir, cachePath, push, states, originCounters } = ctx;
    const actionId = `acquire-${key}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const journal = this.#journal();

    // Reconcile any torn earlier attempt for this content before new effects.
    const recon = await this.reconcile(entry.id, entry.version);
    if (recon.rootStale) {
      await this.#events.emit('REFUSED', 'STALE_PROVIDER_ROOT', `provider root exists without a READY receipt: ${providerRoot}`);
      return { status: 'STALE_PROVIDER_ROOT', states, entry, key, actionId };
    }

    await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIVED', actionId, detail: entry.id });
    await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'VALIDATED', actionId, detail: `catalog ${entry.id}@${entry.version} sha ${entry.artifact.sha256.slice(0, 12)}` });

    // Idempotent re-acquire: a concurrent twin (or earlier attempt) that already
    // installed this exact content leaves a READY receipt + provider root; the
    // capability is present, so this attempt returns READY-adopted without
    // touching the disk again.
    const allEntries = await journal.replay();
    const readyReceipt = allEntries.find(
      (e) => String(e.actionId ?? '').startsWith(`acquire-${key}`) && e.phase === 'RECEIPT_WRITTEN' && e.detail === 'READY',
    );
    if (readyReceipt) {
      try {
        await lstat(providerRoot);
        await this.#events.emit('ADOPTED', `provider root for ${entry.id}@${entry.version} already READY (${readyReceipt.actionId})`);
        return {
          status: 'READY',
          states: [...states, 'HASH_VERIFIED', 'INSTALLED', 'READY'],
          entry,
          key,
          actionId,
          providerRoot: resolve(providerRoot),
          downloadRoot: resolve(downloadRoot),
          cacheHit: true,
          adopted: true,
          adoptedFrom: readyReceipt.actionId,
        };
      } catch {
        /* root vanished after a READY receipt: fall through to a fresh install */
      }
    }

    // Cache: content-addressed by artifact SHA — the URL is transport, the
    // digest is trust.
    let cacheHit = false;
    try {
      const cachedSha = await sha256File(cachePath);
      if (cachedSha === entry.artifact.sha256) {
        cacheHit = true;
        await this.#events.emit('CACHE_HIT', cachePath, { sha256: cachedSha });
      } else {
        await this.#events.emit('CACHE_CORRUPT', 'cached artifact digest mismatch — will re-download', {
          expected: entry.artifact.sha256,
          actual: cachedSha,
        });
        await rm(cachePath, { force: true });
      }
    } catch {
      /* no cache entry */
    }

    let download = null;
    if (!cacheHit) {
      await push('ACQUIRING');
      await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'EXEC_START', actionId, detail: 'download beginning' });
      try {
        download = await downloadTo(entry.source.url, cachePath, {
          approvedHosts: entry.source.approvedHosts,
          maxBytes: this.#maxBytes,
        });
      } catch (error) {
        await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: `NO_EFFECT:${error.code ?? 'DOWNLOAD_FAILED'}` });
        await this.#events.emit('REFUSED', error.code ?? 'DOWNLOAD_FAILED', String(error.message).slice(0, 300));
        return { status: error.code ?? 'DOWNLOAD_FAILED', detail: error.message, states, entry, key, actionId };
      }
      if (download.sizeBytes !== entry.artifact.sizeBytes) {
        await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: 'NO_EFFECT:INCOMPLETE_DOWNLOAD' });
        await rm(cachePath, { force: true }).catch(() => {});
        await this.#events.emit('REFUSED', 'INCOMPLETE_DOWNLOAD', `received ${download.sizeBytes} bytes, catalog declares ${entry.artifact.sizeBytes}`);
        return { status: 'INCOMPLETE_DOWNLOAD', states, entry, key, actionId, download };
      }
      if (download.sha256 !== entry.artifact.sha256) {
        await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: 'NO_EFFECT:HASH_MISMATCH' });
        await rm(cachePath, { force: true }).catch(() => {});
        await this.#events.emit('REFUSED', 'HASH_MISMATCH', `computed ${download.sha256}, catalog declares ${entry.artifact.sha256} — artifact never executed`);
        return { status: 'HASH_MISMATCH', states, entry, key, actionId, download };
      }
      await this.#events.emit('HASH_VERIFIED_FILE', `${download.sizeBytes} bytes sha ${download.sha256}`, { hops: download.hops.length });
    } else if (originCounters) {
      // Cache hit while an origin is up: prove 0 requests.
      await this.#events.emit('ORIGIN_REQUEST_COUNT', String(originCounters.requests), { expectation: 0 });
    }
    await push('HASH_VERIFIED');

    // Exclusive fresh roots (v0.1 semantics: ENOENT is the only accepted state).
    try {
      await lstat(providerRoot);
      await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: 'NO_EFFECT:PROVIDER_ROOT_EXISTS' });
      return { status: 'PROVIDER_ROOT_EXISTS', states, entry, key, actionId };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const payloadStaging = join(stagingDir, 'payload');
    await mkdir(dirname(providerRoot), { recursive: true });
    await mkdir(downloadRoot, { recursive: true });
    await rm(stagingDir, { recursive: true, force: true });
    await mkdir(payloadStaging, { recursive: true });

    // Extract through the native handle-relative primitive (zip-slip-safe,
    // per-entry SHA identity, size budgets).
    let extracted;
    try {
      extracted = await this.#extractor.extractZip(cachePath, payloadStaging, entry.artifact.sha256);
    } catch (error) {
      await rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      const code = error.code ?? 'EXTRACT_FAILED';
      await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: `NO_EFFECT:${code}` });
      await this.#events.emit('REFUSED', code, String(error.message).slice(0, 300));
      return { status: code, states, entry, key, actionId };
    }
    await this.#events.emit('EXTRACTED', `${extracted.length} exact entries`, { first: extracted[0]?.path });

    // Unique executable discovery (v0.1 managed-portable semantics).
    const exeName = entry.executable?.relativeName;
    let executable = undefined;
    if (exeName) {
      const matches = [];
      const walk = async (dir) => {
        for (const child of await readdir(dir, { withFileTypes: true })) {
          const p = join(dir, child.name);
          if (child.isSymbolicLink()) throw new AcquisitionError('INSTALL_FAILED', `staging contains reparse entry: ${p}`);
          if (child.isDirectory()) await walk(p);
          else if (child.isFile() && child.name.toLowerCase() === exeName.toLowerCase()) matches.push(p);
        }
      };
      await walk(payloadStaging);
      if (matches.length !== 1) {
        await rm(stagingDir, { recursive: true, force: true });
        await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: 'NO_EFFECT:EXECUTABLE_NOT_UNIQUE' });
        return { status: 'EXECUTABLE_NOT_UNIQUE', states, entry, key, actionId };
      }
      executable = matches[0];
    }

    // ATOMIC ACTIVATION: one rename of the fully verified payload into the
    // provider root. Before the rename there is no provider root at all; after
    // it the content is exactly the verified extraction.
    await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'EXEC_START', actionId, detail: 'atomic activation beginning' });
    await rename(payloadStaging, providerRoot);
    await rm(stagingDir, { recursive: true, force: true }).catch(() => {});

    // Post-activation identity snapshot on the FINAL roots (install-time
    // ownership manifest for identity-pinned removal later).
    const ownedPaths = new Set([resolve(providerRoot), resolve(downloadRoot)]);
    for (const e of extracted) {
      const finalPath = resolve(e.path.replace(payloadStaging, providerRoot));
      if (!within(finalPath, providerRoot)) throw new AcquisitionError('INSTALL_FAILED', `extracted entry escaped provider root: ${e.path}`);
      ownedPaths.add(finalPath);
      let parent = dirname(finalPath);
      while (within(parent, providerRoot)) {
        ownedPaths.add(resolve(parent));
        if (resolve(parent) === resolve(providerRoot)) break;
        parent = dirname(parent);
      }
    }
    ownedPaths.add(resolve(cachePath));
    const manifest = [...ownedPaths];
    let identities = [];
    try {
      identities = await this.#deleter.snapshotTreePinned(providerRoot, manifest.filter((p) => within(p, providerRoot)));
      const downloadManifest = [resolve(downloadRoot), resolve(cachePath)];
      const downloadIdentities = await this.#deleter.snapshotTreePinned(downloadRoot, downloadManifest);
      identities = [...identities, ...downloadIdentities];
    } catch (error) {
      await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'EXEC_DONE', actionId, detail: `identity snapshot failed: ${String(error).slice(0, 160)}` });
      await rm(providerRoot, { recursive: true, force: true }).catch(() => {});
      await rm(downloadRoot, { recursive: true, force: true }).catch(() => {});
      return { status: 'IDENTITY_SNAPSHOT_FAILED', detail: String(error.message ?? error).slice(0, 200), states, entry, key, actionId };
    }
    if (identities.length !== manifest.length) {
      await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'EXEC_DONE', actionId, detail: `identity coverage ${identities.length}/${manifest.length}` });
      await rm(providerRoot, { recursive: true, force: true }).catch(() => {});
      await rm(downloadRoot, { recursive: true, force: true }).catch(() => {});
      return { status: 'IDENTITY_COVERAGE_MISMATCH', states, entry, key, actionId };
    }

    await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'EXEC_DONE', actionId, detail: `installed sha ${entry.artifact.sha256.slice(0, 12)} identities ${identities.length}` });
    await journal.append({ seq: 0, ts: new Date().toISOString(), phase: 'RECEIPT_WRITTEN', actionId, detail: 'READY' });
    await push('INSTALLED');
    await push('READY');
    const exeFinal = executable ? resolve(executable.replace(payloadStaging, providerRoot)) : undefined;
    return {
      status: 'READY',
      states,
      entry,
      key,
      actionId,
      providerRoot: resolve(providerRoot),
      downloadRoot: resolve(downloadRoot),
      executable: exeFinal,
      cacheHit,
      download,
      ownedManifest: manifest,
      identities,
      extractedCount: extracted.length,
    };
  }

  /** Verify install-time state still holds: exe inside provider root, hash unchanged. */
  async verifyReady(outcome) {
    const exeStat = await stat(outcome.executable);
    const sha = await sha256File(outcome.executable);
    const inRoot = within(outcome.executable, outcome.providerRoot);
    await this.#events.emit('VERIFY_READY', JSON.stringify({ exe: outcome.executable, bytes: exeStat.size, sha, inRoot }));
    return { bytes: exeStat.size, sha256: sha, inRoot };
  }

  /**
   * Removal preflight using v0.1 effect-time scope exclusivity: every path
   * inside the declared roots must be manifest-recorded or the effect refuses.
   */
  async removalScopeRefusal(outcome, extraTreeDirs = []) {
    const roots = [outcome.providerRoot, outcome.downloadRoot, ...extraTreeDirs];
    const spec = { manifest: outcome.ownedManifest, scopeRoots: roots };
    return effectTimeScopeRefusal(this.#fs, spec);
  }

  /**
   * Identity-pinned native removal of exactly the install-time manifest.
   * Stops at the first root refusal (v0.1 semantics) so a refusal on the
   * provider root never cascades into deleting the cache root.
   */
  async removeProvider(outcome, { includeCache = true } = {}) {
    const roots = includeCache ? [outcome.providerRoot, outcome.downloadRoot] : [outcome.providerRoot];
    const results = {};
    for (const root of roots) {
      const entries = outcome.ownedManifest.filter((p) => within(p, root));
      const identities = new Map(
        outcome.identities.filter((i) => within(i.path, root)).map((i) => [i.path, i]),
      );
      const result = await this.deleter.removeTreePinned(root, entries, identities);
      results[root] = result;
      if (!result.ok && !result.absentRoot) break;
    }
    await this.#events.emit('REMOVAL', JSON.stringify(results));
    return results;
  }
}
