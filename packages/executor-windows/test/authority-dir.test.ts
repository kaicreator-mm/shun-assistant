// Regression tests for the build-time authority directory define (review
// finding: the production build leaves SHUN_EXECUTOR_AUTHORITY_DIR as '' and
// the old `??` only guarded `undefined` — so every helper trust anchor
// (helper-pin.json / current-authority.json / grant-hmac.key / plans/)
// degraded to CWD-relative resolution, and the helper CWD is inherited from
// the untrusted launcher). No real elevation anywhere in this file.
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import { resolveAuthorityDirectory } from '../src/helper/authority-dir.ts';
import { sha256File, writeHelperPin } from '../src/trusted-store.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  ON_WINDOWS,
  runHelperDirectly,
  type TestAuthority,
} from './helpers.ts';

const DEFAULT_AUTHORITY_DIR = join(homedir(), '.shun', 'authority');

describe('authority directory build-define fallback (no elevation)', () => {
  it('treats the production empty define as "use the documented default"', () => {
    expect(resolveAuthorityDirectory('')).toBe(DEFAULT_AUTHORITY_DIR);
  });

  it('treats an undefined define as the documented default', () => {
    expect(resolveAuthorityDirectory(undefined)).toBe(DEFAULT_AUTHORITY_DIR);
  });

  it('treats a whitespace-only define as unset (fail back to the default)', () => {
    expect(resolveAuthorityDirectory('   ')).toBe(DEFAULT_AUTHORITY_DIR);
  });

  it('honors a genuinely defined authority directory verbatim', () => {
    expect(resolveAuthorityDirectory('D:\\shun\\authority')).toBe('D:\\shun\\authority');
    expect(resolveAuthorityDirectory('/trusted/authority')).toBe('/trusted/authority');
  });

  it('authorityDirectory() under an absent define resolves the default (typeof guard path)', async () => {
    // The bundle-time define does not exist under vitest; the runtime resolver
    // must take the same fallback as a production build.
    const { authorityDirectory } = await import('../src/helper/authority-dir.ts');
    expect(authorityDirectory()).toBe(DEFAULT_AUTHORITY_DIR);
  });
});

describe.skipIf(!ON_WINDOWS)(
  'empty-define helper bundle vs a launcher-planted CWD trust anchor (real bundle)',
  () => {
    // The attack the finding describes: a bundle built WITHOUT the override
    // (empty define) inheriting the launcher's CWD, where the launcher planted
    // a self-consistent helper-pin.json. With the bug the pin check PASSES
    // (journal opens); with the fix the helper resolves the real default store,
    // finds no pin for THIS bundle, and refuses pre-journal (writes NOTHING).
    let authority: TestAuthority;
    let plantedCwd: string;
    let runDir: string;
    let emptyDefineBundle: string;
    let envelopeFile: string;
    let journalFile: string;
    let receiptFile: string;

    beforeAll(async () => {
      authority = await createTestAuthority('shun-authdir-');
      plantedCwd = mkdtempSync(join(tmpdir(), 'shun-planted-cwd-'));
      runDir = join(plantedCwd, 'runs', 'run-1');
      mkdirSync(runDir, { recursive: true });

      // Build the helper EXACTLY like a production build: empty define.
      const { build } = await import('esbuild');
      emptyDefineBundle = join(plantedCwd, 'executor-helper.mjs');
      await build({
        entryPoints: [join(import.meta.dirname, '..', 'src', 'helper', 'executor-helper.ts')],
        bundle: true,
        platform: 'node',
        format: 'esm',
        target: 'node24',
        outfile: emptyDefineBundle,
        define: { SHUN_EXECUTOR_AUTHORITY_DIR: JSON.stringify('') },
      });

      // Launcher-planted, self-consistent pin for THIS bundle in its CWD.
      writeHelperPin(plantedCwd, {
        schemaVersion: 'shun.executor-windows.helper-pin/1',
        helperRevision: 'shun.executor-windows.helper/planted',
        helperSha256: sha256File(emptyDefineBundle),
        relaySha256: sha256File(authority.relayScript),
        workspaceRoot: plantedCwd,
        pinnedAt: new Date().toISOString(),
      });

      // A fully valid envelope whose I/O paths sit inside the planted root:
      // if the pin were honored, the journal would open and receive phases.
      const built = buildAuthorizedAction(authority, {
        op: 'windows.fs.verify',
        parameters: { path: join(plantedCwd, 'target.txt'), expectExists: false },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R0',
        filesystemScope: { read: [plantedCwd], write: [] },
      });
      envelopeFile = join(runDir, 'envelope.json');
      journalFile = join(runDir, 'journal.jsonl');
      receiptFile = join(runDir, 'receipt.json');
      writeEnvelopeFile(envelopeFile, {
        action: built.action,
        grant: built.grant,
        plan: built.plan,
        io: { journalFile, receiptFile, evidenceDir: join(runDir, 'evidence') },
      });
    });

    afterAll(() => {
      disposeTestAuthority(authority);
      rmSync(plantedCwd, { recursive: true, force: true });
    });

    it('refuses pre-journal — the planted CWD pin is NOT honored (no files written)', () => {
      const run = runHelperDirectly(
        { ...authority, helperBundle: emptyDefineBundle },
        envelopeFile,
        journalFile,
        receiptFile,
        60000,
        plantedCwd,
      );
      expect(run.exitCode).toBe(2);
      // Pre-journal refusals write nothing: had the planted pin been trusted,
      // the journal would exist and carry RECEIVED (+ a REFUSED receipt file).
      expect(existsSync(journalFile)).toBe(false);
      expect(existsSync(receiptFile)).toBe(false);
      expect(run.stderr).toContain('refus');
    });
  },
);
