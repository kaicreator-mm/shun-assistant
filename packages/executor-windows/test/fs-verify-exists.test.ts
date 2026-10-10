// T04 C14 — windows.fs.verify must honor expectExists in BOTH directions.
// The field is part of the frozen typed op surface; a verify step that can
// only ever succeed when the file EXISTS (existence assertion inverted and
// ignored) breaks absence proofs: expectedState { exists: false } can never
// verify, and a reconcile-first "no effect" claim is unprovable.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type InterpreterContext, runStep } from '../src/interpreter.ts';
import { JournalWriter } from '../src/journal.ts';
import { ON_WINDOWS } from './helpers.ts';

describe.skipIf(!ON_WINDOWS)('windows.fs.verify expectExists semantics (C14)', () => {
  const root = mkdtempSync(join(tmpdir(), 'shun-fsv-'));
  const workspace = join(root, 'ws');
  let ctx: InterpreterContext;

  beforeAll(() => {
    mkdirSync(workspace, { recursive: true });
    ctx = {
      journal: new JournalWriter(join(root, 'journal.jsonl'), process.pid),
      scope: { filesystem: { read: [workspace], write: [workspace] } },
      isElevated: false,
      deadlineAt: new Date(Date.now() + 30000),
      evidenceDir: join(root, 'evidence'),
    };
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const present = join(workspace, 'present.txt');
  const absent = join(workspace, 'absent.txt');

  it('expectExists=false PASSES when the file is absent (negative control for C14)', async () => {
    expect(existsSync(absent)).toBe(false);
    const r = await runStep(
      { op: 'windows.fs.verify', args: { path: absent, expectExists: false } },
      ctx,
    );
    expect(r.ok, JSON.stringify(r)).toBe(true);
  });

  it('expectExists=false FAILS when the file is present', async () => {
    writeFileSync(present, 'data', 'utf8');
    const r = await runStep(
      { op: 'windows.fs.verify', args: { path: present, expectExists: false } },
      ctx,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain('expected file present');
      expect(r.result.existenceOk).toBe(false);
    }
  });

  it('expectExists=true still passes when the file is present and fails when absent', async () => {
    const okR = await runStep(
      { op: 'windows.fs.verify', args: { path: present, expectExists: true } },
      ctx,
    );
    expect(okR.ok).toBe(true);
    const badR = await runStep(
      { op: 'windows.fs.verify', args: { path: absent, expectExists: true } },
      ctx,
    );
    expect(badR.ok).toBe(false);
    if (!badR.ok) {
      expect(badR.reason).toContain('expected file absent');
      // The failure dimension must be observable (C10 input): absence, not
      // a content mismatch on a nonexistent file.
      expect(badR.result.existenceOk).toBe(false);
    }
  });

  it('content dimension failure is reported distinctly from existence failure', async () => {
    const r = await runStep(
      {
        op: 'windows.fs.verify',
        args: { path: present, expectExists: true, expectContent: 'other' },
      },
      ctx,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain('content mismatch');
      expect(r.result.existenceOk).toBe(true);
      expect(r.result.contentMatches).toBe(false);
    }
  });
});
