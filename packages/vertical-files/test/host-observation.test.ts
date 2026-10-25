// T07 F02B physical host-observation falsifiers. The trusted bridge in
// src/host-observation.ts must open NOTHING by pathname: drive letters are
// attested as fixed local volumes before any handle exists, every directory
// and file is opened through a single component anchored at an already
// verified parent handle with FILE_OPEN_REPARSE_POINT, and every opened
// object is identity-checked against the FileId enumerated from its parent.
// A positive observation additionally requires TWO independent anchored
// passes with byte-identical inventory fingerprints (path, kind, size,
// mtime, 64-bit file identity AND content digest), so a mid-scan mutation
// preserving name/size/mtime is refused, never verified.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  attestsFixedLocalVolume,
  type HostObservationInstrument,
  observeVerifiedFileDuplicates,
} from '../src/host-observation.ts';

const SYSTEM32 = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');

function runCmd(command: string) {
  return spawnSync(join(SYSTEM32, 'cmd.exe'), ['/d', '/c', command], {
    encoding: 'utf8',
    windowsVerbatimArguments: true,
  });
}

type OpenLog = { dirs: string[]; files: string[]; stages: string[] };

function instrument(log: OpenLog): HostObservationInstrument {
  return {
    onStage: (stage, detail) => log.stages.push(`${stage}:${detail}`),
    onDirOpen: (_depth, name) => log.dirs.push(name),
    onFileOpen: (rel) => log.files.push(rel),
  };
}

function makeScope(prefix: string, files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  for (const [rel, content] of Object.entries(files)) {
    const target = join(dir, rel);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return { dir, dispose: () => rmSync(dir, { recursive: true, force: true }) };
}

const sha256 = (content: string) => createHash('sha256').update(content).digest('hex');

// ---------------------------------------------------------------------------
// All-platform static admission and decision units (CI-safe: zero IO).
// ---------------------------------------------------------------------------

describe('T07 F02B static scope admission (no IO)', () => {
  const refused = (input: unknown) =>
    expect(observeVerifiedFileDuplicates(input)).toEqual({
      ok: false,
      code: 'HOST_OBSERVE_SCOPE_REFUSED',
    });

  it('refuses non-plain shapes, proxies, arrays and extra/missing keys', () => {
    refused(null);
    refused(undefined);
    refused('C:\\scope');
    refused(42);
    refused([]);
    refused(new Proxy({ scopeRoot: 'C:\\scope' }, {}));
    refused({});
    refused({ scopeRoot: 'C:\\scope', extra: 1 });
    refused({ scopeRoot: 7 });
  });

  it('refuses UNC roots, relative paths, device namespaces and traversal statically', () => {
    for (const scopeRoot of [
      '\\\\localhost\\c$\\Windows',
      '\\\\server\\share',
      '//server/share/root',
      '\\\\.\\C:\\Windows',
      'relative\\scope',
      '.',
      '..',
      'C:relative',
      'C:\\scope\\..\\escape',
      'C:\\scope\\..',
      'C:\\.\\scope',
    ]) {
      refused({ scopeRoot });
    }
  });

  it('refuses hostile components (DOS devices, separators, control chars, trailing dot/space)', () => {
    for (const component of [
      'CON',
      'con',
      'aux.txt',
      'com1',
      'lpt9.log',
      'a<b',
      'a>b',
      'a:b',
      'a"b',
      'a|b',
      'a?b',
      'a*b',
      'a\u0000b',
      'a\u202eb',
      'trailing.',
      'trailing ',
      `${'x'.repeat(256)}`,
    ]) {
      refused({ scopeRoot: `C:\\ok\\${component}` });
    }
    refused({ scopeRoot: `\\${'x'.repeat(2049)}` });
    refused({ scopeRoot: `C:\\${'x'.repeat(2049)}` });
  });
});

describe('T07 F02B fixed-local-volume attestation decision', () => {
  it('attests \\Device\\HarddiskVolume* + DRIVE_FIXED only', () => {
    expect(attestsFixedLocalVolume('\\Device\\HarddiskVolume3', 3)).toBe(true);
    expect(attestsFixedLocalVolume('\\device\\harddiskvolume12', 3)).toBe(true);
    // Mapped network drive: the redirector device, never a volume device.
    expect(attestsFixedLocalVolume('\\Device\\LanmanRedirector\\;Q:0000\\server\\share', 3)).toBe(
      false,
    );
    // Subst alias and any other device namespace form.
    expect(attestsFixedLocalVolume('\\??\\C:\\some\\path', 3)).toBe(false);
    expect(attestsFixedLocalVolume('\\Device\\CdRom0', 5)).toBe(false);
    expect(attestsFixedLocalVolume('\\Device\\HarddiskVolume3', 4)).toBe(false);
    expect(attestsFixedLocalVolume(null, 3)).toBe(false);
    expect(attestsFixedLocalVolume('', 3)).toBe(false);
    expect(attestsFixedLocalVolume('\\Device\\HarddiskVolume3', null)).toBe(false);
  });
});

describe.skipIf(process.platform === 'win32')(
  'T07 F02B fails closed without a Windows native host',
  () => {
    it('refuses a statically admitted scope when no anchored host exists', () => {
      expect(observeVerifiedFileDuplicates({ scopeRoot: 'C:\\Users\\app' })).toEqual({
        ok: false,
        code: 'HOST_OBSERVE_NATIVE_UNAVAILABLE',
      });
    });
  },
);

// ---------------------------------------------------------------------------
// Physical Windows host observation (Standard User, no elevation).
// ---------------------------------------------------------------------------

describe.skipIf(process.platform !== 'win32')('T07 F02B physical host observation', () => {
  it('verifies real duplicates through anchored handles and never groups same-size different content', () => {
    const scope = makeScope('shun-f02b-pos', {
      'a.txt': 'AAAA',
      'c.txt': 'AAAA',
      'd.txt': 'BBBB',
      'unique.txt': 'unique-content',
      'empty1.dat': '',
      'empty2.dat': '',
      'sub\\b.txt': 'AAAA',
    });
    try {
      const result = observeVerifiedFileDuplicates({ scopeRoot: scope.dir });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const o = result.observation;
      expect(o.status).toBe('HOST_OBSERVED_CONTENT_VERIFIED');
      expect(o.trust).toBe('VERIFIED_HOST_OBSERVATION');
      expect(o.filesystemObserved).toBe(true);
      expect(o.duplicatesVerified).toBe(true);
      expect(o.executionAuthorized).toBe(false);
      expect(o.cloudDisclosure).toBe(false);
      expect(o.observedFiles).toBe(7);
      // 7 files + the `sub` directory entry; the root itself is not enumerated.
      expect(o.inspectedEntries).toBe(8);
      expect(o.verifiedDuplicateGroups).toEqual([
        {
          sizeBytes: 0,
          contentDigestSha256: sha256(''),
          relativePaths: ['empty1.dat', 'empty2.dat'],
        },
        {
          sizeBytes: 4,
          contentDigestSha256: sha256('AAAA'),
          relativePaths: ['a.txt', 'c.txt', 'sub\\b.txt'],
        },
      ]);
      expect(o.inventoryDigestSha256).toMatch(/^[a-f0-9]{64}$/);
      expect(o.completedTrustedChecks).toEqual([
        'WINDOWS_HANDLE_ANCHORED_INVENTORY',
        'NO_REPARSE_OR_NETWORK_FOLLOW',
        'CONTENT_DIGEST_FROM_VERIFIED_HANDLES',
        'INDEPENDENT_POSTSTATE_CHECK',
      ]);
      // Same-size different-content file must not appear in any group.
      const grouped = o.verifiedDuplicateGroups.flatMap((group) => group.relativePaths);
      expect(grouped).not.toContain('d.txt');
      expect(grouped).not.toContain('unique.txt');
      // The observation is deeply immutable.
      expect(Object.isFrozen(o)).toBe(true);
      expect(Object.isFrozen(o.verifiedDuplicateGroups)).toBe(true);
      for (const group of o.verifiedDuplicateGroups) expect(Object.isFrozen(group)).toBe(true);
      expect(() => {
        (o as unknown as { observedFiles: number }).observedFiles = 999;
      }).toThrow();
      console.log('F02B_PHYSICAL_POSITIVE_DUPLICATES=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('observes an empty scope with zero groups but still verified twice', () => {
    const scope = makeScope('shun-f02b-empty', {});
    try {
      const result = observeVerifiedFileDuplicates({ scopeRoot: scope.dir });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.observation.observedFiles).toBe(0);
      expect(result.observation.verifiedDuplicateGroups).toEqual([]);
      console.log('F02B_PHYSICAL_EMPTY_SCOPE=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses a nonexistent scope component', () => {
    const scope = makeScope('shun-f02b-absent', {});
    try {
      expect(observeVerifiedFileDuplicates({ scopeRoot: join(scope.dir, 'absent') })).toEqual({
        ok: false,
        code: 'HOST_OBSERVE_SCOPE_REFUSED',
      });
    } finally {
      scope.dispose();
    }
  });

  it('refuses a junction ancestor at that component with zero opens below it', () => {
    const scope = makeScope('shun-f02b-anc', {
      'real/scope/a.txt': 'alpha',
      'outside/escape.txt': 'outside',
    });
    try {
      const junction = join(scope.dir, 'real', 'jn');
      const made = runCmd(`mklink /J "${junction}" "${join(scope.dir, 'outside')}"`);
      expect(made.status, made.stderr).toBe(0);
      const log: OpenLog = { dirs: [], files: [], stages: [] };
      const result = observeVerifiedFileDuplicates(
        { scopeRoot: join(junction, 'scope') },
        instrument(log),
      );
      expect(result).toEqual({ ok: false, code: 'HOST_OBSERVE_ALIAS_REFUSED' });
      // The admitted prefix stops exactly at the junction component; nothing
      // below it — neither the scope directory nor the target's files — was
      // ever opened.
      expect(log.dirs.at(-1)).toBe('jn');
      expect(log.files).toEqual([]);
      expect(log.stages.some((stage) => stage.startsWith('ADMITTED'))).toBe(false);
      console.log('F02B_JUNCTION_ANCESTOR_ZERO_IO=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses an in-tree junction from enumeration metadata alone (target untouched)', () => {
    const scope = makeScope('shun-f02b-tree', {
      'scope/a.txt': 'alpha',
      'outside/escape.txt': 'outside',
    });
    try {
      const junction = join(scope.dir, 'scope', 'link-out');
      const made = runCmd(`mklink /J "${junction}" "${join(scope.dir, 'outside')}"`);
      expect(made.status, made.stderr).toBe(0);
      const log: OpenLog = { dirs: [], files: [], stages: [] };
      const result = observeVerifiedFileDuplicates(
        { scopeRoot: join(scope.dir, 'scope') },
        instrument(log),
      );
      expect(result).toEqual({ ok: false, code: 'HOST_OBSERVE_ALIAS_REFUSED' });
      // The junction TARGET must stay untouched.
      expect(log.files).not.toContain('escape.txt');
      expect(log.dirs).not.toContain('outside');
      expect(log.dirs).not.toContain('link-out');
      console.log('F02B_INTREE_JUNCTION_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses an in-tree symlink from metadata alone when creation is permitted', () => {
    const scope = makeScope('shun-f02b-symlink', {
      'scope/a.txt': 'alpha',
      'outside/escape.txt': 'outside',
    });
    try {
      try {
        symlinkSync(join(scope.dir, 'outside', 'escape.txt'), join(scope.dir, 'scope', 'sl.txt'));
      } catch {
        // Honest boundary: symlink creation needs a privilege this Standard
        // User host may lack; the junction cases above cover the reparse gate.
        console.log('F02B_INTREE_SYMLINK_REFUSED=SKIPPED_NO_SYMLINK_PRIVILEGE');
        return;
      }
      const log: OpenLog = { dirs: [], files: [], stages: [] };
      const result = observeVerifiedFileDuplicates(
        { scopeRoot: join(scope.dir, 'scope') },
        instrument(log),
      );
      expect(result).toEqual({ ok: false, code: 'HOST_OBSERVE_ALIAS_REFUSED' });
      expect(log.files).not.toContain('escape.txt');
      console.log('F02B_INTREE_SYMLINK_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses a UNC scope root statically with zero IO', () => {
    const log: OpenLog = { dirs: [], files: [], stages: [] };
    expect(
      observeVerifiedFileDuplicates({ scopeRoot: '\\\\localhost\\c$\\Windows' }, instrument(log)),
    ).toEqual({ ok: false, code: 'HOST_OBSERVE_SCOPE_REFUSED' });
    expect(log.dirs).toEqual([]);
    expect(log.files).toEqual([]);
    console.log('F02B_UNC_ROOT_STATIC_REFUSAL=PASS');
  });

  it('refuses a subst alias root by device attestation with zero opens at all', () => {
    const scope = makeScope('shun-f02b-subst', { 'scope/a.txt': 'alpha' });
    try {
      const letters = 'VWXYZ';
      let drive: string | null = null;
      for (const letter of letters) {
        if (!existsSync(`${letter}:\\`)) {
          drive = letter;
          break;
        }
      }
      if (drive === null) {
        console.log('F02B_SUBST_ZERO_IO=SKIPPED_NO_FREE_LETTER');
        return;
      }
      const made = runCmd(`subst ${drive}: "${scope.dir}"`);
      if (made.status !== 0) {
        console.log('F02B_SUBST_ZERO_IO=SKIPPED_SUBST_UNAVAILABLE');
        return;
      }
      try {
        expect(existsSync(`${drive}:\\`)).toBe(true);
        const log: OpenLog = { dirs: [], files: [], stages: [] };
        const result = observeVerifiedFileDuplicates({ scopeRoot: `${drive}:\\` }, instrument(log));
        expect(result).toEqual({ ok: false, code: 'HOST_OBSERVE_DRIVE_REFUSED' });
        // Attestation refused before a single handle existed on that drive.
        expect(log.dirs).toEqual([]);
        expect(log.files).toEqual([]);
        expect(log.stages.some((stage) => stage.startsWith('REFUSED:drive-attestation'))).toBe(
          true,
        );
        console.log(`F02B_SUBST_ZERO_IO=PASS DRIVE=${drive}:`);
      } finally {
        runCmd(`subst ${drive}: /D`);
      }
    } finally {
      scope.dispose();
    }
  });

  it('refuses a mid-scan mutation that preserves name, size and mtime (content is bound)', () => {
    const scope = makeScope('shun-f02b-mut', { 'a.txt': 'AAAA', 'b.txt': 'BBBB' });
    try {
      const stat = { mtime: new Date('2026-01-01T00:00:00.000Z') };
      utimesSync(join(scope.dir, 'a.txt'), stat.mtime, stat.mtime);
      const instrumentHook: HostObservationInstrument = {
        onPassCompleted: (pass) => {
          if (pass === 1) {
            // Same size, same mtime: ONLY the content digest can diverge.
            writeFileSync(join(scope.dir, 'a.txt'), 'CCCC');
            utimesSync(join(scope.dir, 'a.txt'), stat.mtime, stat.mtime);
          }
        },
      };
      const result = observeVerifiedFileDuplicates({ scopeRoot: scope.dir }, instrumentHook);
      expect(result).toEqual({ ok: false, code: 'HOST_OBSERVE_MUTATION_REFUSED' });
      console.log('F02B_MIDSCAN_SAMESIZE_MTIME_MUTATION_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses a scope swap between the two independent passes', () => {
    const scope = makeScope('shun-f02b-swap', { 'a.txt': 'AAAA' });
    try {
      const instrumentHook: HostObservationInstrument = {
        onPassCompleted: (pass) => {
          if (pass === 1) {
            // Replace the file object: a new NTFS file identity must break
            // the fingerprint even with identical name/size/mtime/content.
            rmSync(join(scope.dir, 'a.txt'));
            writeFileSync(join(scope.dir, 'a.txt'), 'AAAA');
          }
        },
      };
      const result = observeVerifiedFileDuplicates({ scopeRoot: scope.dir }, instrumentHook);
      expect(result).toEqual({ ok: false, code: 'HOST_OBSERVE_MUTATION_REFUSED' });
      console.log('F02B_INTERPASS_FILE_IDENTITY_SWAP_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses a file above the per-file content cap', () => {
    const scope = makeScope('shun-f02b-cap', {});
    try {
      writeFileSync(join(scope.dir, 'large.dat'), Buffer.alloc(262_145, 0x41));
      expect(observeVerifiedFileDuplicates({ scopeRoot: scope.dir })).toEqual({
        ok: false,
        code: 'HOST_OBSERVE_BOUNDS_EXCEEDED',
      });
      console.log('F02B_PER_FILE_CAP_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  }, 30_000);

  it('refuses a tree deeper than the depth bound', () => {
    const deep: Record<string, string> = {};
    let rel = 'f0';
    for (let i = 1; i <= 9; i++) rel = `${rel}\\f${i}`;
    deep[`${rel}\\leaf.txt`] = 'x';
    const scope = makeScope('shun-f02b-depth', deep);
    try {
      expect(observeVerifiedFileDuplicates({ scopeRoot: scope.dir })).toEqual({
        ok: false,
        code: 'HOST_OBSERVE_BOUNDS_EXCEEDED',
      });
      console.log('F02B_DEPTH_BOUND_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses more than 128 verified duplicate groups', () => {
    const files: Record<string, string> = {};
    for (let size = 1; size <= 129; size++) {
      files[`g${String(size).padStart(3, '0')}a.bin`] = 'x'.repeat(size);
      files[`g${String(size).padStart(3, '0')}b.bin`] = 'x'.repeat(size);
    }
    const scope = makeScope('shun-f02b-groups', files);
    try {
      expect(observeVerifiedFileDuplicates({ scopeRoot: scope.dir })).toEqual({
        ok: false,
        code: 'HOST_OBSERVE_BOUNDS_EXCEEDED',
      });
      console.log('F02B_GROUP_BOUND_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  }, 60_000);

  it('refuses a scope beyond the 4096-entry inventory bound', () => {
    const scope = makeScope('shun-f02b-entries', {});
    try {
      for (let i = 0; i < 4097; i++) {
        writeFileSync(join(scope.dir, `e${String(i).padStart(4, '0')}.dat`), '');
      }
      expect(observeVerifiedFileDuplicates({ scopeRoot: scope.dir })).toEqual({
        ok: false,
        code: 'HOST_OBSERVE_BOUNDS_EXCEEDED',
      });
      console.log('F02B_ENTRY_BOUND_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  }, 120_000);
});
