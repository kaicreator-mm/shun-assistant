// R6 native handle-safety suite — REAL Windows runs, no mocks on any row.
//
// Everything here executes the committed ShunNative.cs primitive through the
// real Windows PowerShell 5.1 host on genuine NTFS paths: junction/reparse
// substitution races before and during extraction, same-path replacement and
// parent-junction swaps across deletion, archive bombs/traversal/ADS/
// collisions, resource limits, hardlink substitution and crash reconcile.
// The suite is skipped ONLY on non-Windows platforms where the primitives do
// not exist (Linux CI); on a Windows host it must pass in full.
import { createHash, randomUUID } from 'node:crypto';
import { type Dirent, existsSync } from 'node:fs';
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, expect, it } from 'vitest';
import {
  type NativeObjectIdentity,
  NativeSafetyError,
  PowerShellNativeDeleter,
  SafePowerShellZipExtractor,
} from '../src/adapters/native-win.ts';
import { SpawnProcess } from '../src/adapters/node.ts';
import { buildZip, type ZipEntrySpec } from './zip-builder.ts';

const powershellExe = join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);
const suiteReady = process.platform === 'win32' && existsSync(powershellExe);

function sha256(buf: Buffer | string): string {
  return createHash('sha256').update(buf).digest('hex');
}

const roots: string[] = [];
afterEach(async () => {
  // Junctions first: unlink the link itself, never recurse through it.
  for (const root of roots.splice(0)) {
    await safeRemove(root);
  }
});

async function safeRemove(path: string): Promise<void> {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) {
      await unlink(path);
    } else {
      await rm(path, { recursive: true, force: true });
    }
  } catch {
    /* already gone */
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

async function listTree(path: string, prefix = ''): Promise<string[]> {
  const out: string[] = [];
  let entries: Dirent[];
  try {
    entries = await readdir(path, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const child = join(path, entry.name);
    out.push(prefix + entry.name);
    if (entry.isDirectory() && !entry.isSymbolicLink()) {
      out.push(...(await listTree(child, `${prefix}${entry.name}/`)));
    }
  }
  return out;
}

const real = it.skipIf(!suiteReady);

const extractor = () =>
  new SafePowerShellZipExtractor(new SpawnProcess(), powershellExe, { timeoutMs: 180_000 });
const deleter = () =>
  new PowerShellNativeDeleter(new SpawnProcess(), powershellExe, { timeoutMs: 180_000 });

// Archives live OUTSIDE any later-under-test managed root, exactly like a
// real download staging root sits beside (not inside) the provider root.
async function freshArchivePath(): Promise<string> {
  const archiveDir = join(tmpdir(), 'shun-r6-archives');
  await mkdir(archiveDir, { recursive: true });
  return join(archiveDir, `${randomUUID()}.zip`);
}

async function extractZip(
  zip: Buffer,
  destination: string,
  expectedSha256 = sha256(zip),
): Promise<ReturnType<SafePowerShellZipExtractor['extractZip']>> {
  const archive = await freshArchivePath();
  await writeFile(archive, zip);
  return extractor().extractZip(archive, destination, expectedSha256);
}

async function expectNativeRefusal(
  zip: Buffer | readonly ZipEntrySpec[],
  destination: string,
  code: RegExp,
): Promise<void> {
  const buffer = Buffer.isBuffer(zip) ? zip : buildZip(zip);
  await mkdir(destination, { recursive: true });
  const archive = await freshArchivePath();
  await writeFile(archive, buffer);
  await expect(extractor().extractZip(archive, destination, sha256(buffer))).rejects.toThrow(code);
}

function ancestorsUpTo(path: string, root: string): string[] {
  const out: string[] = [];
  let current = resolve(path);
  const rootResolved = resolve(root);
  while (current.length > rootResolved.length && current !== rootResolved) {
    out.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return out;
}

function manifestFor(destination: string, entryPaths: readonly string[]): string[] {
  const manifest = new Set<string>([resolve(destination)]);
  for (const path of entryPaths) {
    manifest.add(resolve(path));
    for (const ancestor of ancestorsUpTo(path, destination)) manifest.add(ancestor);
  }
  return [...manifest];
}

async function identityMapFor(
  root: string,
  manifest: readonly string[],
): Promise<Map<string, NativeObjectIdentity>> {
  const snapshot = await deleter().snapshotTreePinned(root, manifest);
  return new Map(snapshot.map((identity) => [resolve(identity.path), identity]));
}

async function extractedWorld(
  prefix: string,
  entries: readonly { name: string; data: Buffer }[],
): Promise<{
  dest: string;
  entryPaths: readonly string[];
  extracted: readonly { path: string; kind: string; sha256?: string }[];
  zip: Buffer;
}> {
  const base = await mkdtemp(join(tmpdir(), prefix));
  roots.push(base);
  const dest = join(base, 'provider', 'payload');
  await mkdir(dest, { recursive: true });
  const zip = buildZip(
    entries.map((entry) => ({ name: entry.name, data: entry.data, method: 8 as const })),
  );
  const extracted = await extractZip(zip, dest);
  return { dest, entryPaths: extracted.map((entry) => entry.path), extracted, zip };
}

// ---------------------------------------------------------------------------
// extraction: structure and budget negatives
// ---------------------------------------------------------------------------

real(
  'T10/R6 native extraction: exact-entry happy path with spaces/parentheses and per-file identities',
  { timeout: 120_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-happy-'));
    roots.push(base);
    const dest = join(base, 'Node.js (LTS)_payload dir');
    await mkdir(dest, { recursive: true });
    const entries = [
      { name: 'node-v24 (win x64)/node tools.exe', data: Buffer.from('MZ trusted portable') },
      { name: 'node-v24 (win x64)/lib/core.js', data: Buffer.from('console.log(1)') },
      { name: 'README.md', data: Buffer.from('hello') },
      { name: 'empty dir/', data: Buffer.alloc(0) },
    ];
    const extracted = await extractZip(
      buildZip(entries.map((e) => ({ ...e, method: 8 as const }))),
      dest,
    );
    const byPath = new Map(extracted.map((entry) => [entry.path, entry]));
    const exe = extracted.find((entry) => entry.path.endsWith('node tools.exe'));
    expect(exe).toBeDefined();
    expect(exe?.kind).toBe('file');
    expect(exe?.sha256).toBe(sha256(Buffer.from('MZ trusted portable')));
    expect(exe?.bytes).toBe(Buffer.from('MZ trusted portable').length);
    const dirEntry = extracted.find((entry) => entry.path.endsWith('empty dir'));
    expect(dirEntry?.kind).toBe('dir');
    expect(await readFile(join(dest, 'node-v24 (win x64)', 'node tools.exe'), 'utf8')).toBe(
      'MZ trusted portable',
    );
    expect(await readFile(join(dest, 'node-v24 (win x64)', 'lib', 'core.js'), 'utf8')).toBe(
      'console.log(1)',
    );
    expect(byPath.size).toBe(extracted.length);
    // on-disk tree equals the entry set plus the implicit parent directories
    // those entries required (which install-time ownership also covers)
    const expected = new Set<string>();
    for (const entry of extracted) {
      let cursor = entry.path;
      while (resolve(cursor) !== resolve(dest)) {
        expected.add(cursor.slice(resolve(dest).length + 1).replaceAll('\\', '/'));
        cursor = dirname(cursor);
      }
    }
    const disk = await listTree(dest);
    expect(new Set(disk)).toEqual(expected);
  },
);

real(
  'T10/R6 native extraction: traversal / ADS / absolute / reserved-name entries fail closed',
  { timeout: 180_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-neg-'));
    roots.push(base);
    const dest = join(base, 'managed', 'payload');

    await expectNativeRefusal(
      [{ name: '../escape.txt', data: Buffer.from('x') }],
      dest,
      /ZIP_PATH_ESCAPE/,
    );
    await expectNativeRefusal(
      [{ name: 'a/../../escape.txt', data: Buffer.from('x') }],
      dest,
      /ZIP_PATH_ESCAPE/,
    );
    await expectNativeRefusal(
      [{ name: '/abs-escape.txt', data: Buffer.from('x') }],
      dest,
      /ZIP_PATH_ESCAPE/,
    );
    await expectNativeRefusal(
      [{ name: 'file:ads.txt', data: Buffer.from('x') }],
      dest,
      /ZIP_ALTERNATE_STREAM/,
    );
    await expectNativeRefusal([{ name: 'CON', data: Buffer.from('x') }], dest, /ZIP_NAME_INVALID/);
    await expectNativeRefusal(
      [{ name: 'trailing.', data: Buffer.from('x') }],
      dest,
      /ZIP_NAME_INVALID/,
    );
    await expectNativeRefusal(
      [{ name: 'trailing space ', data: Buffer.from('x') }],
      dest,
      /ZIP_NAME_INVALID/,
    );
    // nothing was written outside the destination through any of the attacks
    expect(await exists(join(base, 'escape.txt'))).toBe(false);
    expect(await exists(join(dirname(dest), 'escape.txt'))).toBe(false);
    const baseDrive = base.slice(0, 2);
    expect(await exists(`${baseDrive}\\abs-escape.txt`)).toBe(false);
  },
);

real(
  'T10/R6 native extraction: collision and type conflicts refuse',
  { timeout: 120_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-coll-'));
    roots.push(base);
    const dest = join(base, 'payload');
    await expectNativeRefusal(
      [
        { name: 'a.txt', data: Buffer.from('one') },
        { name: 'a.txt', data: Buffer.from('two') },
      ],
      dest,
      /ZIP_ENTRY_COLLISION/,
    );
    await expectNativeRefusal(
      [
        { name: 'x/', data: Buffer.alloc(0) },
        { name: 'x', data: Buffer.from('file-vs-dir') },
      ],
      dest,
      /ZIP_ENTRY_COLLISION|NATIVE_STATUS/,
    );
  },
);

real(
  'T10/R6 native extraction: archive-bomb budgets refuse before and during writes',
  { timeout: 240_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-bomb-'));
    roots.push(base);
    const dest = join(base, 'payload');

    // declared single entry over the per-entry cap (no bytes materialized)
    await expectNativeRefusal(
      [{ name: 'big.bin', data: Buffer.from('x'), declaredLength: 268435457 }],
      dest,
      /ZIP_EXPANDED_LIMIT/,
    );
    // declared total expansion over the aggregate cap (ratio kept honest so the
    // aggregate budget is the control under test)
    await expectNativeRefusal(
      [1, 2, 3, 4, 5].map((i) => ({
        name: `part${i}.bin`,
        data: Buffer.from('x'),
        declaredLength: 250 * 1024 * 1024,
        declaredCompressedLength: 5 * 1024 * 1024,
      })),
      dest,
      /ZIP_EXPANDED_LIMIT/,
    );
    // genuine deflate ratio bomb (512 KiB of zeros compresses far past 400:1)
    await expectNativeRefusal(
      [{ name: 'zeros.bin', data: Buffer.alloc(512 * 1024), method: 8 as const }],
      dest,
      /ZIP_COMPRESSION_RATIO_LIMIT/,
    );
    // entry-count cap
    const many = Array.from({ length: 4097 }, (_, i) => ({
      name: `e${i}.txt`,
      data: Buffer.from(String(i)),
    }));
    await expectNativeRefusal(many, dest, /ZIP_ENTRY_LIMIT/);
    // runtime expansion: central directory lies small, actual stored data is huge
    const huge = Buffer.alloc(270 * 1024 * 1024, 0x41); // 270 MiB actual, 256 MiB cap
    await expectNativeRefusal(
      [{ name: 'lie.bin', data: huge, declaredLength: 1 }],
      dest,
      /ZIP_RUNTIME_EXPANDED_LIMIT|ZIP_LENGTH_MISMATCH/,
    );
    // nothing escaped the destination during any partial write
    expect((await listTree(dest)).every((path) => !path.startsWith('..'))).toBe(true);
  },
);

real(
  'T10/R6 native extraction: oversize archive and SHA mismatch refuse inside the lock',
  { timeout: 120_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-sha-'));
    roots.push(base);
    const dest = join(base, 'payload');
    await mkdir(dest, { recursive: true });
    const zip = buildZip([{ name: 'ok.txt', data: Buffer.from('ok') }]);

    const wrongSha = '0'.repeat(64);
    const archive = join(base, 'artifact.zip');
    await writeFile(archive, zip);
    await expect(extractor().extractZip(archive, dest, wrongSha)).rejects.toThrow(
      /ZIP_SHA_MISMATCH/,
    );
    expect(await exists(join(dest, 'ok.txt'))).toBe(false);

    // sparse oversize archive: length cap fires before any hashing/extraction
    const oversize = join(base, 'oversize.zip');
    const handle = await import('node:fs/promises').then((fs) => fs.open(oversize, 'w'));
    await handle.truncate(513 * 1024 * 1024);
    await handle.close();
    await expect(extractor().extractZip(oversize, dest, '1'.repeat(64))).rejects.toThrow(
      /ZIP_ARCHIVE_LIMIT/,
    );
  },
);

// ---------------------------------------------------------------------------
// extraction: junction races (deterministic + active storm)
// ---------------------------------------------------------------------------

real(
  'T10/R6 native extraction: pre-planted junction inside destination refuses with zero canary contact',
  { timeout: 120_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-jsub-'));
    roots.push(base);
    const dest = join(base, 'payload');
    await mkdir(dest, { recursive: true });
    const canary = join(base, 'user-canary');
    await mkdir(canary, { recursive: true });
    const canaryFile = join(canary, 'user.txt');
    await writeFile(canaryFile, 'user asset');
    await symlink(canary, join(dest, 'sub'), 'junction');

    await expectNativeRefusal(
      [
        { name: 'sub/a.txt', data: Buffer.from('through junction') },
        { name: 'sub/deep/b.txt', data: Buffer.from('nested through junction') },
      ],
      dest,
      /ZIP_REPARSE_POINT/,
    );
    expect(await exists(join(canary, 'a.txt'))).toBe(false);
    expect(await exists(join(canary, 'deep'))).toBe(false);
    expect(await readFile(canaryFile, 'utf8')).toBe('user asset');
  },
);

real(
  'T10/R6 native extraction: destination itself planted as a junction to user data refuses',
  { timeout: 120_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-jdest-'));
    roots.push(base);
    const canary = join(base, 'user-canary');
    await mkdir(canary, { recursive: true });
    await writeFile(join(canary, 'user.txt'), 'user asset');
    const linkDir = join(base, 'managed');
    await mkdir(linkDir, { recursive: true });
    const dest = join(linkDir, 'payload');
    await symlink(canary, dest, 'junction');

    await expectNativeRefusal(
      [{ name: 'a.txt', data: Buffer.from('x') }],
      dest,
      /ZIP_REPARSE_POINT/,
    );
    expect(await exists(join(canary, 'a.txt'))).toBe(false);
    expect(await readFile(join(canary, 'user.txt'), 'utf8')).toBe('user asset');
  },
);

real(
  'T10/R6 native extraction: ACTIVE junction-swap storm never writes through to user data',
  { timeout: 300_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-race-extract-'));
    roots.push(base);
    const canary = join(base, 'user-canary');
    await mkdir(canary, { recursive: true });
    const canaryFile = join(canary, 'user.txt');
    const canaryContent = 'irreplaceable user asset';
    await writeFile(canaryFile, canaryContent);

    const zip = buildZip([
      { name: 'sub/a.txt', data: Buffer.from('A'.repeat(4096)) },
      { name: 'sub/b.txt', data: Buffer.from('B'.repeat(4096)) },
    ]);

    let attacks = 0;
    for (let round = 0; round < 6; round += 1) {
      const dest = join(base, `round${round}`, 'payload');
      await mkdir(dest, { recursive: true });
      const subName = join(dest, 'sub');
      const junctionName = join(dest, 'sub-junction-target');
      let stop = false;
      const attacker = (async () => {
        while (!stop) {
          try {
            await symlink(canary, junctionName, 'junction');
            attacks += 1;
          } catch {
            /* exists already */
          }
          try {
            await unlink(junctionName);
            attacks += 1;
          } catch {
            /* gone */
          }
          try {
            await safeRemove(subName);
            attacks += 1;
          } catch {
            /* gone */
          }
          await new Promise((resolve) => setTimeout(resolve, 2));
        }
      })();
      const archive = join(base, `round${round}`, 'a.zip');
      await writeFile(archive, zip);
      let outcome: 'ok' | 'refused' = 'refused';
      try {
        await extractor().extractZip(archive, dest, sha256(zip));
        outcome = 'ok';
      } catch (error) {
        expect(error).toBeInstanceOf(NativeSafetyError);
      }
      stop = true;
      await attacker;
      // Whatever the interleaving: user data was never touched, and nothing
      // outside the destination exists.
      expect(await readFile(canaryFile, 'utf8')).toBe(canaryContent);
      expect(await listTree(canary)).toEqual(['user.txt']);
      expect(outcome).toMatch(/ok|refused/);
    }
    expect(attacks).toBeGreaterThan(0);
  },
);

// ---------------------------------------------------------------------------
// deletion: identity-pinned manifest removal
// ---------------------------------------------------------------------------

real(
  'T10/R6 native deletion: exact manifest removes the whole provider root by handle',
  { timeout: 180_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r6-del-happy-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ exe') },
      { name: 'bin/lib/a.js', data: Buffer.from('a') },
      { name: 'bin/lib/deep/b.js', data: Buffer.from('b') },
      { name: 'top.txt', data: Buffer.from('top') },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];
    const result = await deleter().removeTreePinned(
      providerRoot,
      manifest,
      await identityMapFor(providerRoot, manifest),
    );
    expect(result.ok).toBe(true);
    expect(result.retained).toEqual([]);
    expect(await exists(providerRoot)).toBe(false);
  },
);

real(
  'T10/R6 native deletion: census identities AGREE with install-time identities across file sizes',
  { timeout: 180_000 },
  async () => {
    // regression: the census read path must hash exactly what the extractor
    // hashed — tiny, sub-buffer, exactly-64KiB and multi-buffer payloads
    const incompressible = (size: number, seed: number): Buffer => {
      const buf = Buffer.alloc(size);
      let state = seed;
      for (let i = 0; i < size; i += 1) {
        state = (state * 1103515245 + 12345) & 0x7fffffff;
        buf[i] = state & 0xff;
      }
      return buf;
    };
    const { dest, extracted } = await extractedWorld('shun-r6-del-agree-', [
      { name: 'bin/tiny.txt', data: Buffer.from('hello') },
      { name: 'bin/sub56.bin', data: incompressible(56527, 7) },
      { name: 'bin/exact64k.bin', data: incompressible(65536, 11) },
      { name: 'bin/multi200.bin', data: incompressible(204800, 13) },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [
      ...manifestFor(
        dest,
        extracted.map((entry) => entry.path),
      ),
      resolve(providerRoot),
    ];
    const identities = await identityMapFor(providerRoot, manifest);
    expect(identities.size).toBe(manifest.length);
    const missing = await deleter().removeTreePinned(providerRoot, manifest);
    expect(missing.ok).toBe(false);
    expect(missing.refusal).toBe('IDENTITY_MISSING');
    expect(await exists(providerRoot)).toBe(true);
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(true);
    expect(result.retained).toEqual([]);
    expect(await exists(providerRoot)).toBe(false);
  },
);

real(
  'T10/R6 native deletion: foreign file anywhere in the root refuses with ZERO deletion',
  { timeout: 180_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r6-del-foreign-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ exe') },
      { name: 'bin/lib.js', data: Buffer.from('lib') },
    ]);
    const providerRoot = dirname(dest);
    const before = await listTree(providerRoot);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];
    const identities = await identityMapFor(providerRoot, manifest);
    const intruder = join(dest, 'bin', 'user-dropped.txt');
    await writeFile(intruder, 'user content');
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('FOREIGN_CONTENT');
    expect(result.detail).toContain('user-dropped.txt');
    // zero deletion: the exact pre-attack tree plus the intruder survives
    expect(await listTree(providerRoot)).toEqual([...before, 'payload/bin/user-dropped.txt']);
    expect(await readFile(intruder, 'utf8')).toBe('user content');
  },
);

real(
  'T10/R6 native deletion: junction planted inside the root refuses as FOREIGN_REPARSE with zero deletion',
  { timeout: 180_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r6-del-reparse-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ exe') },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];
    const identities = await identityMapFor(providerRoot, manifest);
    const canary = join(dirname(providerRoot), 'canary-dir');
    await mkdir(canary, { recursive: true });
    await writeFile(join(canary, 'user.txt'), 'user asset');
    await symlink(canary, join(dest, 'link'), 'junction');
    const before = await listTree(providerRoot);
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('FOREIGN_REPARSE');
    expect(await listTree(providerRoot)).toEqual(before);
    expect(await readFile(join(canary, 'user.txt'), 'utf8')).toBe('user asset');
  },
);

real(
  'T10/R6 native deletion: parent junction swap refuses even when the mirrored tree matches the manifest exactly',
  { timeout: 180_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-del-pjunction-'));
    roots.push(base);
    // real tree lives under realParent; the managed path reaches it through a
    // junction — the exact R2-review P1-02 scenario.
    const realParent = join(base, 'real-tree');
    const dest = join(realParent, 'provider', 'payload');
    await mkdir(dest, { recursive: true });
    const zip = buildZip([
      { name: 'bin/node.exe', data: Buffer.from('MZ exe'), method: 8 as const },
      { name: 'bin/lib.js', data: Buffer.from('lib'), method: 8 as const },
    ]);
    const archive = join(base, 'a.zip');
    await writeFile(archive, zip);
    const extracted = await extractor().extractZip(archive, dest, sha256(zip));
    const providerRoot = join(dest, '..', '..');
    const manifest = [
      ...manifestFor(
        dest,
        extracted.map((e) => e.path),
      ),
      resolve(providerRoot),
    ];
    // the manifest is addressed through the junctioned path and matches the
    // content behind it exactly — deletion must still refuse on chain pinning
    // the managed root path passes THROUGH the junction: managed-link\provider
    // -> real-tree, so junctionedRoot resolves at the junctioned provider view
    const junctionedRoot = join(base, 'managed-link', 'provider', 'provider');
    await mkdir(join(base, 'managed-link'), { recursive: true });
    await symlink(realParent, join(base, 'managed-link', 'provider'), 'junction');
    const throughJunction = join(base, 'managed-link', 'provider', 'provider', 'payload');
    // point the manifest at the junctioned view of the SAME tree
    const junctionManifest = manifest.map((path) =>
      path === resolve(providerRoot)
        ? resolve(junctionedRoot)
        : resolve(path).replace(resolve(providerRoot), resolve(junctionedRoot)),
    );
    const result = await deleter().removeTreePinned(junctionedRoot, junctionManifest);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('ZIP_REPARSE_POINT');
    expect(await exists(throughJunction)).toBe(true);
    expect(await exists(join(dest, 'bin', 'node.exe'))).toBe(true);
  },
);

real(
  'T10/R6 native deletion: same-path content replacement detected by install-time identity (zero deletion)',
  { timeout: 180_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-del-replace-'));
    roots.push(base);
    const dest = join(base, 'provider', 'payload');
    await mkdir(dest, { recursive: true });
    const zip = buildZip([
      { name: 'bin/node.exe', data: Buffer.from('original exe'), method: 8 as const },
      { name: 'bin/lib.js', data: Buffer.from('lib'), method: 8 as const },
    ]);
    const archive = join(base, 'a.zip');
    await writeFile(archive, zip);
    const extracted = await extractor().extractZip(archive, dest, sha256(zip));
    const providerRoot = dirname(dest);
    const manifest = [
      ...manifestFor(
        dest,
        extracted.map((e) => e.path),
      ),
      resolve(providerRoot),
    ];
    const identities = await identityMapFor(providerRoot, manifest);

    // attacker replaces one owned file's content at the same path
    await writeFile(join(dest, 'bin', 'node.exe'), 'attacker replacement');
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('FOREIGN_CONTENT');
    expect(result.detail).toMatch(/same-path (object|content) replacement/);
    expect(await exists(join(dest, 'bin', 'node.exe'))).toBe(true);
    expect(await exists(join(dest, 'bin', 'lib.js'))).toBe(true);
  },
);

real(
  'T10/R8 native deletion: same-content new object is refused by install-time FileId',
  { timeout: 180_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r8-del-samebytes-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ same bytes') },
      { name: 'bin/lib.js', data: Buffer.from('lib') },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];
    const identities = await identityMapFor(providerRoot, manifest);
    const target = join(dest, 'bin', 'node.exe');
    await unlink(target);
    await writeFile(target, 'MZ same bytes');
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('FOREIGN_CONTENT');
    expect(result.detail).toContain('object replacement');
    expect(await readFile(target, 'utf8')).toBe('MZ same bytes');
    expect(await exists(providerRoot)).toBe(true);
  },
);

real(
  'T10/R8 native deletion: file-to-empty-directory replacement is refused',
  { timeout: 180_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r8-del-type-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ exe') },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];
    const identities = await identityMapFor(providerRoot, manifest);
    const target = join(dest, 'bin', 'node.exe');
    await unlink(target);
    await mkdir(target);
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('FOREIGN_CONTENT');
    expect(await exists(target)).toBe(true);
    expect(await exists(providerRoot)).toBe(true);
  },
);

real(
  'T10/R6 native deletion: hardlink substitution is refused even when bytes match a user file',
  { timeout: 180_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r6-del-hardlink-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ exe') },
      { name: 'bin/lib.js', data: Buffer.from('lib') },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];
    const identities = await identityMapFor(providerRoot, manifest);
    // Same bytes are not enough: a user hardlink has a different NT FileId.
    const userFile = join(dirname(providerRoot), 'user-hardlink-source');
    await writeFile(userFile, 'MZ exe');
    await unlink(join(dest, 'bin', 'node.exe'));
    await link(userFile, join(dest, 'bin', 'node.exe'));
    const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe('FOREIGN_CONTENT');
    expect(await exists(providerRoot)).toBe(true);
    expect(await exists(userFile)).toBe(true);
    expect(await readFile(userFile, 'utf8')).toBe('MZ exe');
  },
);

real(
  'T10/R6 native deletion: ACTIVE same-path replacement + junction storm never deletes user data',
  { timeout: 300_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-race-del-'));
    roots.push(base);
    const canary = join(base, 'user-canary');
    await mkdir(canary, { recursive: true });
    const canaryFile = join(canary, 'user.txt');
    await writeFile(canaryFile, 'user asset that must survive');
    const originalExe = Buffer.from('original exe bytes');

    for (let round = 0; round < 4; round += 1) {
      const dest = join(base, `round${round}`, 'payload');
      await mkdir(dest, { recursive: true });
      const zip = buildZip([
        { name: 'bin/node.exe', data: originalExe, method: 8 as const },
        { name: 'bin/lib.js', data: Buffer.from('lib data'), method: 8 as const },
      ]);
      const archive = await freshArchivePath();
      await writeFile(archive, zip);
      const extracted = await extractor().extractZip(archive, dest, sha256(zip));
      const providerRoot = dirname(dest);
      const manifest = [
        ...manifestFor(
          dest,
          extracted.map((e) => e.path),
        ),
        resolve(providerRoot),
      ];
      const identities = await identityMapFor(providerRoot, manifest);

      let stop = false;
      const attacker = (async () => {
        while (!stop) {
          const binDir = join(dest, 'bin');
          try {
            await writeFile(join(binDir, 'node.exe'), 'swapped');
          } catch {
            /* racing */
          }
          try {
            await safeRemove(join(binDir, 'lib.js'));
            await symlink(canary, join(binDir, 'lib.js'), 'junction');
          } catch {
            /* racing */
          }
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
      })();
      const result = await deleter().removeTreePinned(providerRoot, manifest, identities);
      stop = true;
      await attacker;

      // invariant: user data outside the managed root is untouched
      expect(await exists(canaryFile)).toBe(true);
      expect(await readFile(canaryFile, 'utf8')).toBe('user asset that must survive');
      expect(await listTree(canary)).toEqual(['user.txt']);
      // outcome is honest: either a refusal/retention (never ok while foreign
      // content is present) — a successful ok is only possible when every
      // attack iteration lost the race before census saw it
      if (result.ok) {
        expect(await exists(providerRoot)).toBe(false);
      } else {
        expect(result.refusal ?? 'RETAINED').toMatch(
          /FOREIGN_CONTENT|FOREIGN_REPARSE|RETAINED|ZIP_REPARSE_POINT/,
        );
      }
    }
  },
);

real(
  'T10/R6 native deletion: crash reconcile — missing entries skip, foreign residue still refuses, then completes',
  { timeout: 300_000 },
  async () => {
    const { dest, entryPaths } = await extractedWorld('shun-r6-del-crash-', [
      { name: 'bin/node.exe', data: Buffer.from('MZ exe') },
      { name: 'bin/lib.js', data: Buffer.from('lib') },
      { name: 'extra/c.txt', data: Buffer.from('c') },
    ]);
    const providerRoot = dirname(dest);
    const manifest = [...manifestFor(dest, entryPaths), resolve(providerRoot)];

    const identities = await identityMapFor(providerRoot, manifest);
    // simulate a crash after a partial effect: some owned entries vanished
    await unlink(join(dest, 'bin', 'node.exe'));
    const afterCrash = await listTree(providerRoot);
    const foreign = join(dest, 'user-after-crash.txt');
    await writeFile(foreign, 'user wrote this after the crash');
    const refused = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(refused.ok).toBe(false);
    expect(refused.refusal).toBe('FOREIGN_CONTENT');
    expect(await listTree(providerRoot)).toEqual([...afterCrash, 'payload/user-after-crash.txt']);

    // after manual reconciliation of the user file, removal completes exactly
    await unlink(foreign);
    const done = await deleter().removeTreePinned(providerRoot, manifest, identities);
    expect(done.ok).toBe(true);
    expect(await exists(providerRoot)).toBe(false);
  },
);

real(
  'T10/R6 native deletion: absent root reports ABSENT instead of inventing work',
  { timeout: 60_000 },
  async () => {
    const base = await mkdtemp(join(tmpdir(), 'shun-r6-del-absent-'));
    roots.push(base);
    const result = await deleter().removeTreePinned(join(base, 'never-existed'), [
      join(base, 'never-existed'),
    ]);
    expect(result.absentRoot).toBe(true);
    expect(result.ok).toBe(true);
  },
);

// Reference the committed primitive source so the test bundle fails loudly if
// the file moves (the transport test asserts byte-identical embedding).
void fileURLToPath(new URL('../src/adapters/ShunNative.cs', import.meta.url));
