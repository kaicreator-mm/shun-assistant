import { execSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type AuthorizedAction, AuthorizedActionSchema } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import {
  observeScopedFileSearch,
  type ScopedSearchInstrumentation,
} from '../src/scoped-file-search.ts';

const cleanup: string[] = [];
afterEach(() => {
  for (const dir of cleanup.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(): { base: string; root: string } {
  const base = mkdtempSync(join(tmpdir(), 'shun-r0-search-'));
  cleanup.push(base);
  const root = join(base, 'approved');
  mkdirSync(root);
  mkdirSync(join(root, 'nested'));
  writeFileSync(join(root, 'note.txt'), 'not read or transmitted');
  writeFileSync(join(root, 'other.log'), 'not read');
  writeFileSync(join(root, 'nested', 'second.txt'), 'not read');
  return { base, root };
}

function authorized(root: string, query = '*.txt'): AuthorizedAction {
  return AuthorizedActionSchema.parse({
    taskId: 'task-1',
    actionId: 'r0-search',
    planHash: 'b'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'actual-issuer-required-upstream',
    action: {
      actionId: 'r0-search',
      bindingRef: 'binding-1',
      op: 'file.search',
      parameters: { root, query },
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [root], write: [] },
    },
  });
}

describe('T04 trusted R0 local filesystem observation (not grant issuer/receipt)', () => {
  it('returns only bounded root-relative matching names without content or cloud disclosure', () => {
    const { root } = fixture();
    const observation = observeScopedFileSearch(authorized(root));
    expect(observation).toMatchObject({
      kind: 'R0_LOCAL_FILE_SEARCH_OBSERVATION',
      inspectedEntries: 4,
      truncated: false,
      semanticVerified: false,
      cloudDisclosure: false,
    });
    expect(observation.paths).toEqual([join('nested', 'second.txt'), 'note.txt'].sort());
    expect(JSON.stringify(observation)).not.toContain('not read');
    expect(JSON.stringify(observation)).not.toContain(root);
  });

  it('refuses changed scope, unsafe query, privileged operation and UNC root', () => {
    const { root } = fixture();
    const good = authorized(root);
    expect(() =>
      observeScopedFileSearch({
        ...good,
        action: { ...good.action, filesystemScope: { read: [root], write: [root] } },
      }),
    ).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    expect(() => observeScopedFileSearch(authorized(root, '../../*'))).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
    expect(() =>
      observeScopedFileSearch({
        ...good,
        action: { ...good.action, requiredPrivilege: 'ELEVATED' },
      }),
    ).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    expect(() => observeScopedFileSearch(authorized('//server/share'))).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
  });

  it('refuses a link/junction at any visited child, never returns a partial result', () => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    try {
      symlinkSync(
        target,
        join(root, 'nested', 'escape'),
        process.platform === 'win32' ? 'junction' : 'dir',
      );
    } catch (err) {
      // A Windows runner without symlink privileges cannot prove this physical canary.
      if ((err as NodeJS.ErrnoException).code === 'EPERM') return;
      throw err;
    }
    expect(() => observeScopedFileSearch(authorized(root))).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
  });

  it('refuses alias root and excessively deep scans rather than reporting truncated success', () => {
    const { base, root } = fixture();
    let current = root;
    for (let i = 0; i < 9; i++) {
      current = join(current, `d${i}`);
      mkdirSync(current);
    }
    expect(() => observeScopedFileSearch(authorized(root))).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    try {
      symlinkSync(root, join(base, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EPERM') return;
      throw err;
    }
    expect(() => observeScopedFileSearch(authorized(join(base, 'alias')))).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
  });
});

const isWin32 = process.platform === 'win32';

interface CanaryKernel32 {
  openNoFollow(path: string): bigint | null;
  openFollow(path: string): bigint | null;
  pinExclusive(path: string): bigint | null;
  isReparse(handle: bigint): boolean;
  finalPath(handle: bigint): string;
  close(handle: bigint): void;
}

interface NativeCanaryAddon {
  openNoFollow(path: string): bigint | null;
  openFollow(path: string): bigint | null;
  pinExclusive(path: string): bigint | null;
  isReparse(handle: bigint): boolean;
  finalPath(handle: bigint): string | null;
  close(handle: bigint): void;
}

let canaryCache: CanaryKernel32 | null = null;

/**
 * Minimal kernel32 surface used by the physical canaries themselves. This is
 * the canary's independent instrument: a separately compiled addon built on
 * disjoint declarations (kernel32 CreateFileW flag semantics), never shared
 * with the NtOpenFile/NtQueryDirectoryFile implementation addon that the
 * source under test loads.
 */
function canary(): CanaryKernel32 {
  if (canaryCache !== null) return canaryCache;
  const addon = createRequire(import.meta.url)(
    '../native/canary/shun_win32_canary.node',
  ) as NativeCanaryAddon;
  const built: CanaryKernel32 = {
    openNoFollow: (path) => addon.openNoFollow(path),
    openFollow: (path) => addon.openFollow(path),
    pinExclusive: (path) => addon.pinExclusive(path),
    isReparse: (handle) => addon.isReparse(handle),
    finalPath: (handle) => {
      const path = addon.finalPath(handle);
      expect(path).not.toBeNull();
      return path as string;
    },
    close: (handle) => {
      addon.close(handle);
    },
  };
  canaryCache = built;
  return built;
}

describe.skipIf(!isWin32)('T04 Windows handle-anchored physical canaries (real win32 host)', () => {
  it('rejects a real SMB mapped drive before the native drive-root handle open', () => {
    const smbRoot = process.env.SHUN_T04_SMB_DRIVE_ROOT;
    if (!smbRoot) {
      console.log('NATIVE_DIRECT_SMB_NEGATIVE=NOT_RUN_NO_MAPPED_DRIVE');
      return;
    }
    const native = createRequire(import.meta.url)('../native/impl/shun_win32_impl.node') as {
      dosDevice(letter: string): string | null;
      driveType(root: string): number | null;
    };
    const letter = smbRoot.slice(0, 2);
    expect(native.dosDevice(letter)?.toLowerCase()).not.toMatch(
      /^\\\\device\\\\harddiskvolume[0-9]+$/,
    );
    const opened: string[] = [];
    expect(() =>
      observeScopedFileSearch(authorized(smbRoot), {
        onDirectoryOpened: (rel) => opened.push(rel),
      }),
    ).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    expect(opened).toEqual([]);
    console.log('NATIVE_DIRECT_SMB_NEGATIVE=PASS_REAL_MAPPED_DRIVE');
  });

  it('anchors every root component, including 8.3 short-name temp paths, without aliasing', () => {
    const { root } = fixture();
    // Windows GitHub runners may supply TEMP containing RUNNER~1 while
    // GetFinalPathNameByHandleW returns RunnerAdmin. Never require those
    // spellings to compare byte-for-byte or accept a junction to compensate.
    const opened: string[] = [];
    const observed = observeScopedFileSearch(authorized(root), {
      onDirectoryOpened: (relativePath) => opened.push(relativePath),
    });
    expect(observed.paths).toEqual([join('nested', 'second.txt'), 'note.txt'].sort());
    expect(opened).toEqual(['nested']);
    expect(observed.cloudDisclosure).toBe(false);
    expect(JSON.stringify(observed)).not.toContain(root);
  });

  it('proves the OS primitive: no-follow open of a junction resolves the junction object, never the target', () => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    const esc = join(root, 'esc');
    symlinkSync(target, esc, 'junction');
    const k32 = canary();

    const noFollow = k32.openNoFollow(esc);
    expect(noFollow).not.toBeNull();
    expect(k32.isReparse(noFollow as bigint)).toBe(true);
    const noFollowPath = k32.finalPath(noFollow as bigint).replace(/^\\\\\?\\/, '');
    // Kernel32 expands 8.3 parent segments (RUNNER~1 -> RunnerAdmin).
    // Verify the no-follow handle is the *junction object* by its stable
    // final relative suffix, never by exact caller spelling.
    expect(noFollowPath.toLowerCase().endsWith('\\approved\\esc')).toBe(true);
    k32.close(noFollow as bigint);

    const follow = k32.openFollow(esc);
    expect(follow).not.toBeNull();
    expect(k32.isReparse(follow as bigint)).toBe(false);
    const followPath = k32.finalPath(follow as bigint).replace(/^\\\\\?\\/, '');
    expect(followPath.toLowerCase().endsWith('\\outside')).toBe(true);
    expect(followPath.toLowerCase()).not.toBe(noFollowPath.toLowerCase());
    k32.close(follow as bigint);
  });

  it('refuses an in-scope junction to outside scope and never records an outside directory open', () => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    writeFileSync(join(target, 'leak.txt'), 'never disclose');
    symlinkSync(target, join(root, 'esc'), 'junction');
    const opened: string[] = [];
    const instrument: ScopedSearchInstrumentation = {
      onDirectoryOpened: (relativePath) => {
        opened.push(relativePath);
      },
    };
    expect(() => observeScopedFileSearch(authorized(root), instrument)).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
    expect(JSON.stringify(opened)).not.toContain('outside');
  });

  it('refuses a junction nested one level deep only after opening its verified parent', () => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    symlinkSync(target, join(root, 'nested', 'escape'), 'junction');
    const opened: string[] = [];
    const instrument: ScopedSearchInstrumentation = {
      onDirectoryOpened: (relativePath) => {
        opened.push(relativePath);
      },
    };
    expect(() => observeScopedFileSearch(authorized(root), instrument)).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
    // The verified parent was opened and its junction entry refused; the walk
    // is deep, not a vacuous root-level refusal.
    expect(opened).toEqual(['nested']);
  });

  it('refuses a junction whose target is exclusively pinned elsewhere, without resolving the target', () => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    symlinkSync(target, join(root, 'esc'), 'junction');
    const k32 = canary();
    const pin = k32.pinExclusive(target);
    expect(pin).not.toBeNull();
    try {
      expect(() => observeScopedFileSearch(authorized(root))).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    } finally {
      k32.close(pin as bigint);
    }
  });

  it('cannot be redirected by deterministic swap attacks: deletion plus junction replacement mid-traversal never yields outside scope', () => {
    const { root } = fixture();
    const outside = join(root, '..', 'swap-outside');
    mkdirSync(outside);
    writeFileSync(join(outside, 'secret.txt'), 'never disclose');
    cleanup.push(outside);
    const events: string[] = [];
    let first = true;
    const instrument: ScopedSearchInstrumentation = {
      onDirectoryOpened: (relativePath) => {
        events.push(relativePath);
        if (!first) return;
        first = false;
        // The root and its subtree are open at this point, mid-traversal.
        const attempts: Array<[string, () => void]> = [
          ['rename-root', () => renameSync(root, `${root}__moved`)],
          ['rm-root', () => rmSync(root, { recursive: true, force: true })],
          ['junction-root', () => symlinkSync(outside, root, 'junction')],
        ];
        for (const [label, attempt] of attempts) {
          try {
            attempt();
            events.push(`${label}:succeeded`);
          } catch (err) {
            events.push(`${label}:${(err as NodeJS.ErrnoException).code ?? 'thrown'}`);
          }
        }
        // Restore whatever the attacker left behind so cleanup stays safe.
        if (!existsSync(root) && existsSync(`${root}__moved`)) renameSync(`${root}__moved`, root);
      },
    };
    let paths: readonly string[] = [];
    try {
      paths = observeScopedFileSearch(authorized(root), instrument).paths;
    } catch (err) {
      expect((err as Error).message).toBe('R0_FILE_SEARCH_REFUSED');
    }
    // Whatever the swap attempts achieved, the walk stayed on the verified
    // objects: the outside directory (junction target) is never enumerated.
    expect(events[0]).toBe('nested');
    expect(events.some((event) => event.startsWith('rename-root:'))).toBe(true);
    expect(events.some((event) => event.startsWith('rm-root:'))).toBe(true);
    expect(JSON.stringify(paths)).not.toContain('secret');
    expect(JSON.stringify(paths)).not.toContain('outside');
  });

  it('keeps the whole traversal object-anchored: a renamed ancestor never redirects the walk', () => {
    const { root } = fixture();
    const opened: string[] = [];
    const instrument: ScopedSearchInstrumentation = {
      onDirectoryOpened: () => {
        // Rename the already-open root directory mid-traversal; the walk must
        // not notice (relative opens are anchored to handles, not names). Name
        // freezing by the open handle equally satisfies the requirement.
        try {
          renameSync(root, `${root}__moved`);
          renameSync(`${root}__moved`, root);
        } catch {
          // rename blocked while the handle is open: also acceptable
        }
        opened.push('step');
      },
    };
    const observation = observeScopedFileSearch(authorized(root), instrument);
    expect(opened).toEqual(['step']);
    expect(observation.paths).toEqual([join('nested', 'second.txt'), 'note.txt'].sort());
  });

  it('refuses junction roots, device-form roots and UNC roots before opening any directory', () => {
    const { base, root } = fixture();
    symlinkSync(root, join(base, 'alias'), 'junction');
    const opened: string[] = [];
    const instrument: ScopedSearchInstrumentation = {
      onDirectoryOpened: (relativePath) => {
        opened.push(relativePath);
      },
    };
    expect(() => observeScopedFileSearch(authorized(join(base, 'alias')), instrument)).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
    expect(() => observeScopedFileSearch(authorized(`\\\\?\\${root}`), instrument)).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
    expect(() =>
      observeScopedFileSearch(authorized('\\\\localhost\\c$\\Windows'), instrument),
    ).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    expect(opened).toEqual([]);
  });

  it('refuses a subst-style drive-letter alias root (mapped-volume provenance negative)', (ctx) => {
    const { base, root } = fixture();
    const letters = ['X:', 'Y:', 'W:', 'V:', 'U:'];
    let mapped: string | null = null;
    for (const letter of letters) {
      try {
        execSync(`subst ${letter} "${base}"`, { stdio: 'pipe' });
        mapped = letter;
        break;
      } catch {}
    }
    if (mapped === null) {
      ctx.skip();
      return;
    }
    try {
      const aliasRoot = `${mapped}${root.slice(2)}`;
      expect(() => observeScopedFileSearch(authorized(aliasRoot))).toThrow(
        /^R0_FILE_SEARCH_REFUSED$/,
      );
    } finally {
      try {
        execSync(`subst ${mapped} /d`, { stdio: 'pipe' });
      } catch {
        // leave no mapping behind even on failure paths
      }
    }
  });

  it('refuses a directory symlink when the host can create one', (ctx) => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    try {
      symlinkSync(target, join(root, 'dlink'), 'dir');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EPERM') {
        ctx.skip();
        return;
      }
      throw err;
    }
    expect(() => observeScopedFileSearch(authorized(root))).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
  });

  it('survives a real concurrent rename attacker without ever returning outside-scope paths', async () => {
    const { root } = fixture();
    const { Worker } = await import('node:worker_threads');
    const workerCode = `
      const { workerData, parentPort } = require('node:worker_threads');
      const fs = require('node:fs');
      const deadline = Date.now() + workerData.ms;
      let attempts = 0, swaps = 0;
      while (Date.now() < deadline) {
        attempts++;
        try {
          fs.renameSync(workerData.target, workerData.target + '__atk');
          fs.renameSync(workerData.target + '__atk', workerData.target);
          swaps++;
        } catch {}
      }
      parentPort.postMessage({ attempts, swaps });
    `;
    const worker = new Worker(workerCode, {
      eval: true,
      workerData: { target: join(root, 'nested'), ms: 1500 },
    });
    const outcomes: string[] = [];
    let stats = { attempts: 0, swaps: 0 };
    try {
      for (let i = 0; i < 5; i++) {
        try {
          const observation = observeScopedFileSearch(authorized(root));
          outcomes.push(`ok:${observation.paths.length}`);
          // The attacker only renames the in-scope 'nested' directory, so a
          // successful walk may legitimately observe the transient '__atk'
          // spelling of that same verified object; that is an accurate
          // observation of the concurrent world, not a scope escape. What
          // must never happen is an outside-scope path or an unexpected name.
          for (const p of observation.paths) {
            expect(
              p === 'note.txt' ||
                p === join('nested', 'second.txt') ||
                p === join('nested__atk', 'second.txt'),
            ).toBe(true);
          }
          expect(JSON.stringify(observation.paths)).not.toContain('outside');
          expect(JSON.stringify(observation.paths)).not.toContain('secret');
        } catch (err) {
          expect((err as Error).message).toBe('R0_FILE_SEARCH_REFUSED');
          outcomes.push('refused');
        }
      }
    } finally {
      stats = await new Promise<{ attempts: number; swaps: number }>((resolve, reject) => {
        worker.once('message', resolve);
        worker.once('error', reject);
      });
      try {
        renameSync(join(root, 'nested__atk'), join(root, 'nested'));
      } catch {
        // the attacker loop always restores its own rename
      }
    }
    expect(stats.attempts).toBeGreaterThan(0);
    expect(stats.swaps).toBeGreaterThan(0);
    expect(outcomes.length).toBe(5);
    expect(outcomes.every((o) => o === 'refused' || o.startsWith('ok:'))).toBe(true);
  });
});
