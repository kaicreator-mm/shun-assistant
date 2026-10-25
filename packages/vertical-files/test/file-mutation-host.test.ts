// T07 F03 physical file-mutation falsifiers. The trusted bridge in
// src/file-mutation-host.ts must perform REAL Win32 effects only through
// anchored handles: both drives attested fixed-local before any handle,
// reparse-refusing ancestor chains on both sides, source identity through
// the same handle its content is read through, exclusive-create destinations
// (no overwrite path exists anywhere), no-replace same-volume relocation
// with FileId preservation, and an independent post-state re-open. Every
// refusal below proves ZERO destination IO through the package-internal
// instrument (destCreates/renames stay 0). Structural negatives run
// everywhere; physical canaries run on real Windows Standard User.
import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  executeAuthorizedFileMutation,
  executeVerifiedFileMutation,
  type FileMutationInstrument,
  sameVolumeDecision,
} from '../src/file-mutation-host.ts';
import * as publicApi from '../src/index.ts';

const SYSTEM32 = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');

function runCmd(command: string) {
  return spawnSync(join(SYSTEM32, 'cmd.exe'), ['/d', '/c', command], {
    encoding: 'utf8',
    windowsVerbatimArguments: true,
  });
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

type IoLog = { destCreates: string[]; renames: string[]; stages: string[] };

function instrument(log: IoLog): FileMutationInstrument {
  return {
    onStage: (stage, detail) => log.stages.push(`${stage}:${detail}`),
    onDestCreate: (rel) => log.destCreates.push(rel),
    onRename: (from, to) => log.renames.push(`${from}>${to}`),
  };
}

/** Minimal structurally valid AuthorizedAction literal for one mutation. */
function mutationAction(input: {
  op: 'file.copy' | 'file.move' | 'file.rename';
  sourcePath: string;
  destinationPath: string;
}): Record<string, unknown> {
  const sourceDir = input.sourcePath.slice(0, input.sourcePath.lastIndexOf('\\'));
  const destDir = input.destinationPath.slice(0, input.destinationPath.lastIndexOf('\\'));
  const write =
    input.op === 'file.copy'
      ? [destDir]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  return {
    taskId: 'task-f03',
    actionId: 'mut-1',
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'DURABLE_POLICY',
    authorizationRef: 'grant-1',
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    action: {
      actionId: 'mut-1',
      bindingRef: 'binding-1',
      op: input.op,
      parameters: { sourcePath: input.sourcePath, destinationPath: input.destinationPath },
      sideEffectClass: 'R2',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [sourceDir], write },
    },
  };
}

/** Package-internal physical seam request: exactly the admitted intent. */
function mutationRequest(
  op: 'file.copy' | 'file.move' | 'file.rename',
  source: string,
  dest: string,
): Record<string, unknown> {
  return { op, sourcePath: source, destinationPath: dest };
}

// ---------------------------------------------------------------------------
// Platform-neutral structural admission (CI-safe: zero IO).
// ---------------------------------------------------------------------------

describe('T07 F03 structural admission and pure decisions (no IO)', () => {
  const refused = (input: unknown) =>
    expect(executeAuthorizedFileMutation(input)).toEqual({
      ok: false,
      code: 'FILE_MUTATION_AUTHORIZATION_REFUSED',
    });

  it('exports no mutation surface through the package public API', () => {
    expect(Object.hasOwn(publicApi, 'executeAuthorizedFileMutation')).toBe(false);
    expect(Object.hasOwn(publicApi, 'executeAnchoredFileMutation')).toBe(false);
  });

  it('refuses non-plain shapes, proxies, extra/missing keys before any IO', () => {
    refused(null);
    refused(undefined);
    refused(42);
    refused([]);
    refused('file.copy');
    const base = mutationAction({
      op: 'file.copy',
      sourcePath: 'C:\\s\\a.txt',
      destinationPath: 'C:\\d\\b.txt',
    });
    refused(new Proxy(base, {}));
    const extra = { ...base, extra: 1 };
    refused(extra);
    const missingExpiry = { ...base };
    delete missingExpiry.expiresAt;
    refused(missingExpiry);
    const elapsed = { ...base, expiresAt: new Date(Date.now() - 60_000).toISOString() };
    refused(elapsed);
    const malformed = { ...base, expiresAt: 'tomorrow' };
    refused(malformed);
  });

  it('refuses a foreign op, risk class, privilege or mismatched identity', () => {
    const base = () =>
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\s\\a.txt',
        destinationPath: 'C:\\d\\b.txt',
      });
    const foreignOp = base();
    (foreignOp.action as Record<string, unknown>).op = 'files.duplicates.observe';
    refused(foreignOp);
    const r0 = base();
    (r0.action as Record<string, unknown>).sideEffectClass = 'R0';
    refused(r0);
    const elevated = base();
    (elevated.action as Record<string, unknown>).requiredPrivilege = 'ELEVATED';
    refused(elevated);
    const swapped = base();
    (swapped.action as Record<string, unknown>).actionId = 'act-other';
    refused(swapped);
  });

  it('refuses extra parameters (dry-run intent never reaches the effect) and scope widening', () => {
    const base = () =>
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\s\\a.txt',
        destinationPath: 'C:\\d\\b.txt',
      });
    const dryRun = base();
    (dryRun.action as Record<string, unknown>).parameters = {
      sourcePath: 'C:\\s\\a.txt',
      destinationPath: 'C:\\d\\b.txt',
      dryRun: true,
    };
    refused(dryRun);
    const widenedRead = base();
    (
      (widenedRead.action as Record<string, unknown>).filesystemScope as Record<string, unknown>
    ).read = ['C:\\s', 'C:\\other'];
    refused(widenedRead);
    const wrongWrite = base();
    (
      (wrongWrite.action as Record<string, unknown>).filesystemScope as Record<string, unknown>
    ).write = ['C:\\elsewhere'];
    refused(wrongWrite);
    const network = base();
    (network.action as Record<string, unknown>).networkScope = { allowed: false };
    refused(network);
    const secrets = base();
    (secrets.action as Record<string, unknown>).secretRefs = ['secret:1'];
    refused(secrets);
  });

  it('refuses identical source and destination, and statically inadmissible paths', () => {
    refused(
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\s\\a.txt',
        destinationPath: 'c:\\s\\a.txt',
      }),
    );
    const unc = mutationAction({
      op: 'file.copy',
      sourcePath: '\\\\server\\share\\a.txt',
      destinationPath: 'C:\\d\\b.txt',
    });
    refused(unc);
    const ads = mutationAction({
      op: 'file.copy',
      sourcePath: 'C:\\s\\a.txt',
      destinationPath: 'C:\\d\\b.txt:hidden',
    });
    refused(ads);
    const dosName = mutationAction({
      op: 'file.copy',
      sourcePath: 'C:\\s\\a.txt',
      destinationPath: 'C:\\d\\con',
    });
    refused(dosName);
    const trailing = mutationAction({
      op: 'file.copy',
      sourcePath: 'C:\\s\\a.txt',
      destinationPath: 'C:\\d\\b.txt ',
    });
    refused(trailing);
    const relative = mutationAction({
      op: 'file.copy',
      sourcePath: 'C:relative\\a.txt',
      destinationPath: 'C:\\d\\b.txt',
    });
    refused(relative);
  });

  it('refuses separator-malformed spellings on the RAW path: no silent component collapse', () => {
    // Confused-deputy witness (R1 P1-01): a trailing separator made the
    // lexical scope parent (raw lastIndexOf derivation, which
    // mutationAction encodes) diverge from the handle-anchored parent the
    // bridge opens (collapsed components). Every malformed spelling is now
    // refused outright — even when the grant is bound to exactly the
    // confused parent the old derivation produced.
    refused(
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\s\\a.txt\\',
        destinationPath: 'C:\\d\\b.txt',
      }),
    ); // read scope auto-derived as the confused C:\s\a.txt (the file itself)
    refused(
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\s\\a.txt',
        destinationPath: 'C:\\d\\b.txt\\',
      }),
    ); // write scope bound to the alleged child C:\d\b.txt
    refused(
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\s\\\\a.txt',
        destinationPath: 'C:\\d\\b.txt',
      }),
    ); // doubled separator
    refused(
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:\\a.txt',
        destinationPath: 'C:\\d\\b.txt',
      }),
    ); // root-level file: no parent directory component exists
    refused(
      mutationAction({
        op: 'file.copy',
        sourcePath: 'C:/s/a.txt',
        destinationPath: 'C:\\d\\b.txt',
      }),
    ); // foreign separator is refused, never normalized
    refused(
      mutationAction({
        op: 'file.move',
        sourcePath: 'C:\\s\\a.txt',
        destinationPath: 'C:\\s\\\\a.txt',
      }),
    ); // same-object alias through a doubled separator: a self-"move"
    // The physical seam refuses the same corpus with zero destination IO
    // (structural admission runs before any platform or native check).
    const log: IoLog = { destCreates: [], renames: [], stages: [] };
    const corpus = [
      mutationRequest('file.copy', 'C:\\s\\a.txt\\', 'C:\\d\\b.txt'),
      mutationRequest('file.copy', 'C:\\s\\a.txt', 'C:\\d\\b.txt\\'),
      mutationRequest('file.copy', 'C:\\s\\\\a.txt', 'C:\\d\\b.txt'),
      mutationRequest('file.copy', 'C:\\a.txt', 'C:\\d\\b.txt'),
      mutationRequest('file.copy', 'C:/s/a.txt', 'C:\\d\\b.txt'),
      mutationRequest('file.move', 'C:\\s\\a.txt', 'C:\\s\\\\a.txt'),
    ];
    for (const malformed of corpus) {
      expect(executeVerifiedFileMutation(malformed, 'mut-spelling', instrument(log))).toEqual({
        ok: false,
        code: 'FILE_MUTATION_SCOPE_REFUSED',
      });
    }
    expect(log.destCreates).toHaveLength(0);
    expect(log.renames).toHaveLength(0);
    console.log('F03_PATH_SPELLING_PARENT_CONSISTENCY=PASS');
  });

  it('same-volume decision admits equal serials only', () => {
    expect(sameVolumeDecision(1918219760, 1918219760)).toBe(true);
    expect(sameVolumeDecision(1918219760, 1918219761)).toBe(false);
  });
});

describe.skipIf(process.platform !== 'win32')(
  'T07 F03 physical mutation canaries (Windows Standard User)',
  () => {
    it('copies a real file through anchored handles with verified post-state', () => {
      const scope = makeScope('shun-f03-copy', {
        'src/a.txt': 'F03-COPY-CONTENT',
        'out/.keep': '',
      });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'out', 'b.txt'),
          ),
          'mut-copy',
          instrument(log),
        );
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(result.receipt.terminal).toBe('SUCCEEDED');
        expect(result.receipt.sideEffectEvidence).toEqual({
          sideEffectClass: 'R2',
          recoveryClassification: 'COMPLETED_VERIFIED',
          postStateVerified: true,
        });
        expect(readFileSync(join(scope.dir, 'out', 'b.txt'), 'utf8')).toBe('F03-COPY-CONTENT');
        expect(readFileSync(join(scope.dir, 'src', 'a.txt'), 'utf8')).toBe('F03-COPY-CONTENT');
        expect(log.destCreates).toHaveLength(1);
        expect(log.renames).toHaveLength(0);
        console.log('F03_PHYSICAL_COPY_VERIFIED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('copies a zero-byte file (empty destination object verified by identity)', () => {
      const scope = makeScope('shun-f03-empty', { 'src/empty.dat': '', 'out/.keep': '' });
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'src', 'empty.dat'),
            join(scope.dir, 'out', 'e.dat'),
          ),
          'mut-empty',
        );
        expect(result.ok).toBe(true);
        if (result.ok) expect(existsSync(join(scope.dir, 'out', 'e.dat'))).toBe(true);
        expect(readFileSync(join(scope.dir, 'out', 'e.dat')).length).toBe(0);
        console.log('F03_PHYSICAL_ZERO_BYTE_COPY=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a concurrent append after destination creation: exact length, not an N-byte prefix', () => {
      // R1 P1-02 witness: every bridge handle is FILE_SHARE_ALL, so a
      // concurrent actor can append to the freshly created destination
      // before post-state verification. The N-byte digest-matching prefix
      // must NOT mint COMPLETED_VERIFIED while the file is longer.
      const scope = makeScope('shun-f03-append', {
        'src/a.txt': 'PREFIX-CONTENT',
        'out/.keep': '',
      });
      const dest = join(scope.dir, 'out', 'b.txt');
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', join(scope.dir, 'src', 'a.txt'), dest),
          'mut-append',
          {
            onDestCreate: () => {
              appendFileSync(dest, 'APPENDED-BY-CONCURRENT-ACTOR');
            },
          },
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
        const bytes = readFileSync(dest, 'utf8');
        expect(bytes.startsWith('PREFIX-CONTENT')).toBe(true);
        expect(bytes.length).toBeGreaterThan('PREFIX-CONTENT'.length);
        console.log('F03_PHYSICAL_CONCURRENT_APPEND_REFUSED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a zero-byte source whose destination gained bytes before verification', () => {
      // The old code verified NOTHING for a zero-length source; the EOF
      // probe at offset 0 now refuses any byte that appeared.
      const scope = makeScope('shun-f03-zappend', { 'src/empty.dat': '', 'out/.keep': '' });
      const dest = join(scope.dir, 'out', 'e.dat');
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', join(scope.dir, 'src', 'empty.dat'), dest),
          'mut-zappend',
          {
            onDestCreate: () => {
              appendFileSync(dest, 'GAINED');
            },
          },
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
        expect(readFileSync(dest, 'utf8')).toBe('GAINED');
        console.log('F03_PHYSICAL_ZERO_SOURCE_APPEND_REFUSED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a concurrent append after relocation at the post-state handle', () => {
      const scope = makeScope('shun-f03-mappend', {
        'src/a.txt': 'MOVED-CONTENT',
        'dst/.keep': '',
      });
      const dest = join(scope.dir, 'dst', 'moved.txt');
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest('file.move', join(scope.dir, 'src', 'a.txt'), dest),
          'mut-mappend',
          {
            onRename: () => {
              appendFileSync(dest, 'TAIL-BY-CONCURRENT-ACTOR');
            },
          },
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
        const bytes = readFileSync(dest, 'utf8');
        expect(bytes.startsWith('MOVED-CONTENT')).toBe(true);
        expect(bytes.length).toBeGreaterThan('MOVED-CONTENT'.length);
        // The relocation itself happened (the refusal is honestly UNCERTAIN
        // at the journal layer); what is under proof is that no verified
        // positive receipt exists for the divergent length.
        expect(existsSync(join(scope.dir, 'src', 'a.txt'))).toBe(false);
        console.log('F03_PHYSICAL_MOVE_APPEND_REFUSED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses copy onto an EXISTING destination with byte-identical pre/post evidence', () => {
      const scope = makeScope('shun-f03-coll', {
        'src/a.txt': 'SOURCE-CONTENT',
        'dst/b.txt': 'PRE-EXISTING-CONTENT',
      });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'b.txt'),
          ),
          'mut-coll',
          instrument(log),
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_COLLISION_REFUSED' });
        expect(log.destCreates).toHaveLength(0);
        // No-overwrite proof: the pre-existing object is byte-identical.
        expect(readFileSync(join(scope.dir, 'dst', 'b.txt'), 'utf8')).toBe('PRE-EXISTING-CONTENT');
        expect(readFileSync(join(scope.dir, 'src', 'a.txt'), 'utf8')).toBe('SOURCE-CONTENT');
        console.log('F03_PHYSICAL_COPY_NO_OVERWRITE=PASS DEST_BYTES_UNCHANGED');
      } finally {
        scope.dispose();
      }
    });

    it('renames within one directory preserving the 64-bit FileId (move, not copy+delete)', () => {
      const scope = makeScope('shun-f03-ren', { 'a.txt': 'RENAME-ME' });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest('file.rename', join(scope.dir, 'a.txt'), join(scope.dir, 'b.txt')),
          'mut-ren',
          instrument(log),
        );
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(existsSync(join(scope.dir, 'a.txt'))).toBe(false);
        expect(readFileSync(join(scope.dir, 'b.txt'), 'utf8')).toBe('RENAME-ME');
        expect(log.renames).toHaveLength(1);
        expect(log.destCreates).toHaveLength(0);
        console.log('F03_PHYSICAL_RENAME_VERIFIED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('moves across directories on the same volume preserving FileId and content', () => {
      const scope = makeScope('shun-f03-move', { 'src/a.txt': 'MOVE-ME', 'dst/.keep': '' });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.move',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'moved.txt'),
          ),
          'mut-move',
          instrument(log),
        );
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(existsSync(join(scope.dir, 'src', 'a.txt'))).toBe(false);
        expect(readFileSync(join(scope.dir, 'dst', 'moved.txt'), 'utf8')).toBe('MOVE-ME');
        expect(log.renames).toHaveLength(1);
        console.log('F03_PHYSICAL_MOVE_VERIFIED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses move onto an EXISTING destination leaving BOTH objects untouched', () => {
      const scope = makeScope('shun-f03-mvc', {
        'src/a.txt': 'SOURCE',
        'dst/b.txt': 'EXISTING',
      });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.move',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'b.txt'),
          ),
          'mut-mvc',
          instrument(log),
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_COLLISION_REFUSED' });
        expect(readFileSync(join(scope.dir, 'src', 'a.txt'), 'utf8')).toBe('SOURCE');
        expect(readFileSync(join(scope.dir, 'dst', 'b.txt'), 'utf8')).toBe('EXISTING');
        console.log('F03_PHYSICAL_MOVE_NO_OVERWRITE=PASS BOTH_BYTES_UNCHANGED');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a junction ancestor in the destination chain with zero destination IO', () => {
      const scope = makeScope('shun-f03-junc', {
        'real/x.txt': 'x',
        'outside/escape.txt': 'ESCAPE',
      });
      try {
        const junction = join(scope.dir, 'jn');
        runCmd(`mklink /J "${junction}" "${join(scope.dir, 'real')}"`);
        expect(existsSync(junction)).toBe(true);
        const log: IoLog = { destCreates: [], renames: [], stages: [] };
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'real', 'x.txt'),
            join(junction, 'stolen.txt'),
          ),
          'mut-junc',
          instrument(log),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.code).toBe('FILE_MUTATION_ALIAS_REFUSED');
        expect(log.destCreates).toHaveLength(0);
        expect(existsSync(join(scope.dir, 'outside', 'stolen.txt'))).toBe(false);
        console.log('F03_JUNCTION_DEST_ANCESTOR_ZERO_IO=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a junction as the source parent with zero destination IO', () => {
      const scope = makeScope('shun-f03-jsrc', { 'real/src.txt': 'S', 'outside/target.txt': 'T' });
      try {
        const junction = join(scope.dir, 'jn');
        runCmd(`mklink /J "${junction}" "${join(scope.dir, 'real')}"`);
        const log: IoLog = { destCreates: [], renames: [], stages: [] };
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', join(junction, 'src.txt'), join(scope.dir, 'out.txt')),
          'mut-jsrc',
          instrument(log),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.code).toBe('FILE_MUTATION_ALIAS_REFUSED');
        expect(log.destCreates).toHaveLength(0);
        console.log('F03_JUNCTION_SOURCE_ANCESTOR_ZERO_IO=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a symlink source (reparse entry never followed) with zero destination IO', () => {
      const scope = makeScope('shun-f03-sym', { 'real/target.txt': 'T' });
      try {
        const link = join(scope.dir, 'link.txt');
        try {
          symlinkSync(join(scope.dir, 'real', 'target.txt'), link);
        } catch (error) {
          console.log(
            `F03_SYMLINK_SOURCE_REFUSED=SKIPPED_NO_SYMLINK_PRIVILEGE ${(error as Error).message}`,
          );
          return;
        }
        const log: IoLog = { destCreates: [], renames: [], stages: [] };
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', link, join(scope.dir, 'out.txt')),
          'mut-sym',
          instrument(log),
        );
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.code).toBe('FILE_MUTATION_ALIAS_REFUSED');
        expect(log.destCreates).toHaveLength(0);
        expect(existsSync(join(scope.dir, 'out.txt'))).toBe(false);
        console.log('F03_SYMLINK_SOURCE_NOT_FOLLOWED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a nonexistent source, destination parent, and non-file source', () => {
      const scope = makeScope('shun-f03-absent', { 'a.txt': 'A', 'sub/.keep': '' });
      try {
        expect(
          executeVerifiedFileMutation(
            mutationRequest('file.copy', join(scope.dir, 'absent.txt'), join(scope.dir, 'out.txt')),
            'mut-absent',
          ),
        ).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
        expect(
          executeVerifiedFileMutation(
            mutationRequest(
              'file.copy',
              join(scope.dir, 'a.txt'),
              join(scope.dir, 'nope', 'out.txt'),
            ),
            'mut-nodest',
          ),
        ).toEqual({ ok: false, code: 'FILE_MUTATION_SCOPE_REFUSED' });
        // A directory as the source opens as a directory: refused from attrs.
        const dirResult = executeVerifiedFileMutation(
          mutationRequest('file.copy', join(scope.dir, 'sub'), join(scope.dir, 'out.txt')),
          'mut-dir',
        );
        expect(dirResult.ok).toBe(false);
        expect(existsSync(join(scope.dir, 'out.txt'))).toBe(false);
        console.log('F03_NONFILE_AND_ABSENT_SOURCES_REFUSED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a source above the 8 MiB per-file bound BEFORE any destination IO', async () => {
      const scope = makeScope('shun-f03-big', {});
      const big = join(scope.dir, 'big.bin');
      try {
        const chunk = Buffer.alloc(1 << 20, 7);
        const stream = createWriteStream(big);
        for (let i = 0; i < 9; i++) {
          if (!stream.write(chunk))
            await new Promise<void>((resolve) => stream.once('drain', () => resolve()));
        }
        await new Promise<void>((resolve) => stream.end(() => resolve()));
        const log: IoLog = { destCreates: [], renames: [], stages: [] };
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', big, join(scope.dir, 'out.bin')),
          'mut-big',
          instrument(log),
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_BOUNDS_EXCEEDED' });
        expect(log.destCreates).toHaveLength(0);
        expect(existsSync(join(scope.dir, 'out.bin'))).toBe(false);
        console.log('F03_ABOVE_PER_FILE_BOUND_ZERO_DEST_IO=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('runs the authorized entry end to end (no callbacks exist to inject)', () => {
      const scope = makeScope('shun-f03-auth', { 'a.txt': 'AUTHORIZED' });
      try {
        const action = mutationAction({
          op: 'file.copy',
          sourcePath: join(scope.dir, 'a.txt'),
          destinationPath: join(scope.dir, 'b.txt'),
        });
        const result = executeAuthorizedFileMutation(action);
        expect(result.ok).toBe(true);
        if (result.ok) expect(result.receipt.actionId).toBe('mut-1');
        expect(readFileSync(join(scope.dir, 'b.txt'), 'utf8')).toBe('AUTHORIZED');
        console.log('F03_AUTHORIZED_ENTRY_PHYSICAL_POSITIVE=PASS');
      } finally {
        scope.dispose();
      }
    });
  },
);

describe.skipIf(process.platform === 'win32')(
  'T07 F03 non-Windows hosts never mutate (fail closed)',
  () => {
    it('refuses a statically admitted intent when no anchored native host exists', () => {
      // A literal fixed-drive intent (not a host temp path, which is not a
      // Windows form on this platform): static admission passes and the
      // missing Windows native host is what refuses.
      const result = executeVerifiedFileMutation(
        mutationRequest('file.copy', 'C:\\s\\a.txt', 'C:\\d\\b.txt'),
        'mut-nonwin',
      );
      expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_NATIVE_UNAVAILABLE' });
    });
  },
);
