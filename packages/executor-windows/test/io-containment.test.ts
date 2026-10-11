// T04 C07 — the elevated helper's I/O channel (journal/receipt/cancel/
// evidence) must be contained on RESOLVED paths, not lexical ones: a
// junction planted inside the pinned workspace root would otherwise turn the
// elevated journal/receipt writes into an arbitrary-write primitive outside
// the root. The launcher must also verify its workspace root really lands
// inside the pinned root before burning a UAC prompt.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import { PrivilegedWindowsExecutionBackend } from '../src/privileged-backend.ts';
import {
  buildAuthorizedAction,
  createJunction,
  createTestAuthority,
  disposeTestAuthority,
  IS_ELEVATED_HOST,
  ON_WINDOWS,
  runHelperDirectly,
  type TestAuthority,
} from './helpers.ts';

describe.skipIf(!ON_WINDOWS)('C07 — junction escape on privileged I/O paths (real fs)', () => {
  let authority: TestAuthority;
  let workspace: string;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-c07-');
    workspace = join(authority.workspaceRoot, 'runs');
    mkdirSync(workspace, { recursive: true });
  });

  afterAll(() => {
    disposeTestAuthority(authority);
  });

  /** A fresh outside directory per test — junction targets must not leak. */
  function freshOutside(name: string): string {
    const dir = mkdtempSync(join(tmpdir(), `shun-c07-${name}-`));
    writeFileSync(join(dir, 'sentinel.txt'), 'outside', 'utf8');
    return dir;
  }

  function envelopeFor(
    name: string,
    io: { journalFile: string; receiptFile: string; evidenceDir: string; cancelFile?: string },
  ) {
    const target = join(workspace, `c07-${name}-target.txt`);
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: target, content: 'x' },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    const runDir = join(workspace, name);
    mkdirSync(runDir, { recursive: true });
    writeEnvelopeFile(join(runDir, 'envelope.json'), {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: io.cancelFile ? { ...io, cancelFile: io.cancelFile } : io,
    });
    return {
      run: runHelperDirectly(
        authority,
        join(runDir, 'envelope.json'),
        io.journalFile,
        io.receiptFile,
      ),
      runDir,
      target,
    };
  }

  it('junction as the evidence dir → helper refuses PRE-JOURNAL; the elevated write escapes nothing', () => {
    const outside = freshOutside('evidence');
    try {
      const runDir = join(workspace, 'c07-evidence-junction');
      mkdirSync(runDir, { recursive: true });
      const evidenceDir = join(runDir, 'evidence');
      createJunction(evidenceDir, outside); // lexical child of the root, real path outside
      const io = {
        journalFile: join(runDir, 'journal.jsonl'),
        receiptFile: join(runDir, 'receipt.json'),
        evidenceDir,
      };
      const { run } = envelopeFor('c07-evidence-junction', io);
      expect(run.exitCode).toBe(2);
      // Pre-journal refusal: no journal, no receipt — and nothing materialized
      // in the outside directory through the junction.
      expect(existsSync(io.journalFile)).toBe(false);
      expect(existsSync(io.receiptFile)).toBe(false);
      expect(readdirSync(outside)).toEqual(['sentinel.txt']);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('junction as the journal file parent → helper refuses PRE-JOURNAL', () => {
    const outside = freshOutside('journal');
    try {
      const runDir = join(workspace, 'c07-journal-junction');
      mkdirSync(runDir, { recursive: true });
      const journalDir = join(runDir, 'jdir');
      createJunction(journalDir, outside);
      const io = {
        journalFile: join(journalDir, 'journal.jsonl'),
        receiptFile: join(runDir, 'receipt.json'),
        evidenceDir: join(runDir, 'evidence'),
      };
      const { run } = envelopeFor('c07-journal-junction', io);
      expect(run.exitCode).toBe(2);
      expect(existsSync(io.journalFile)).toBe(false);
      expect(existsSync(io.receiptFile)).toBe(false);
      expect(readdirSync(outside)).toEqual(['sentinel.txt']);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('lexically-outside I/O path still refused (regression guard for the original check)', () => {
    const outside = freshOutside('lexical');
    try {
      const runDir = join(workspace, 'c07-outside-lexical');
      mkdirSync(runDir, { recursive: true });
      const io = {
        journalFile: join(outside, 'journal.jsonl'),
        receiptFile: join(outside, 'receipt.json'),
        evidenceDir: join(outside, 'evidence'),
      };
      const { run } = envelopeFor('c07-outside-lexical', io);
      expect(run.exitCode).toBe(2);
      expect(existsSync(io.journalFile)).toBe(false);
      expect(existsSync(io.receiptFile)).toBe(false);
      expect(readdirSync(outside)).toEqual(['sentinel.txt']);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('non-junction layout passes containment: the journal OPENS (outcome after startup is host-dependent)', () => {
    const runDir = join(workspace, 'c07-clean');
    mkdirSync(runDir, { recursive: true });
    const io = {
      journalFile: join(runDir, 'journal.jsonl'),
      receiptFile: join(runDir, 'receipt.json'),
      evidenceDir: join(runDir, 'evidence'),
    };
    const { run, target } = envelopeFor('c07-clean', io);
    // Containment passed: the journal opened with RECEIVED (the subject of
    // this test). What happens AFTER startup depends on the host token:
    // a filtered token refuses the ELEVATED action at elevation consistency
    // (exit 2, structured receipt); an elevated host (CI windows-latest)
    // executes the action. CI honesty: do not pin the exit code to the
    // filtered-token branch here — the elevation gate has its own tests.
    expect(existsSync(io.journalFile)).toBe(true);
    expect(journalPhases(readJournal(io.journalFile))).toContain('RECEIVED');
    if (IS_ELEVATED_HOST) {
      expect(run.exitCode).toBe(0);
      expect(existsSync(target)).toBe(true);
    } else {
      expect(run.exitCode).toBe(2);
      expect(run.receipt).toBeDefined();
    }
  });

  it('launcher refuses a workspace root that does not resolve inside the pinned root (no UAC burned)', async () => {
    const escaped = mkdtempSync(join(tmpdir(), 'shun-c07-launcher-'));
    try {
      const built = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: join(escaped, 'never.txt'), content: 'x' },
        requiredPrivilege: 'ELEVATED',
        sideEffectClass: 'R2',
        filesystemScope: { read: [], write: [escaped] },
      });
      const backend = new PrivilegedWindowsExecutionBackend({
        authorityDir: authority.authorityDir,
        workspaceRoot: escaped, // outside pin.workspaceRoot entirely
        uacGraceMs: 0,
      });
      const receipt = await backend.execute(built.action, built.grant);
      expect(receipt.terminal).toBe('REFUSED');
      expect(receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
      expect(existsSync(join(escaped, 'never.txt'))).toBe(false);
      // The launcher may persist its own refusal receipt into its own
      // workspace root, but no relay/helper artifacts may exist.
      for (const entry of readdirSync(escaped)) {
        for (const runEntry of readdirSync(join(escaped, entry))) {
          for (const file of readdirSync(join(escaped, entry, runEntry))) {
            expect(['receipt.json']).toContain(file);
          }
        }
      }
    } finally {
      rmSync(escaped, { recursive: true, force: true });
    }
  });
});
