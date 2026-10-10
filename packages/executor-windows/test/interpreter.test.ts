// Typed interpreter tests on the REAL Windows surface (non-elevated):
// fs byte-exactness incl. metacharacters, registry HKCU lifecycle, typed argv
// byte-exactness through a real child process, deadline enforcement.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type InterpreterContext,
  type InterpreterScope,
  parseRegQueryOutput,
  runStep,
} from '../src/interpreter.ts';
import { JournalWriter } from '../src/journal.ts';

const root = mkdtempSync(join(tmpdir(), 'shun-interp-'));
const workspace = join(root, 'ws');
const registryScopeKey = 'HKCU\\SOFTWARE\\ShunExecutorTests';

function ctx(overrides?: Partial<InterpreterContext>): InterpreterContext {
  const journalFile = join(root, `journal-${Math.random().toString(36).slice(2)}.jsonl`);
  const scope: InterpreterScope = {
    filesystem: { read: [workspace], write: [workspace] },
    registry: { write: [registryScopeKey] },
  };
  return {
    journal: new JournalWriter(journalFile, process.pid),
    scope,
    isElevated: false,
    deadlineAt: new Date(Date.now() + 30000),
    evidenceDir: join(root, 'evidence'),
    ...overrides,
  };
}

beforeAll(() => mkdirSync(workspace, { recursive: true }));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('fs ops', () => {
  it('windows.fs.write lands byte-exact, metacharacters and all', async () => {
    const content = 'a & b | c; d%PATH%e "f" <g> $(h) `i` \u00e9\u4f60\u597d';
    const path = join(workspace, 'metachars & ; %PX%.txt');
    const r = await runStep(
      { op: 'windows.fs.write', args: { path, content, encoding: 'utf8' } },
      ctx(),
    );
    expect(r.ok).toBe(true);
    expect(readFileSync(path, 'utf8')).toBe(content);
    if (r.ok)
      expect(r.result.sha256).toBe(createHash('sha256').update(content, 'utf8').digest('hex'));
  });

  it('windows.fs.write refuses paths outside the grant scope', async () => {
    const r = await runStep(
      {
        op: 'windows.fs.write',
        args: { path: join(root, 'outside.txt'), content: 'x', encoding: 'utf8' },
      },
      ctx(),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('scope');
  });

  it('windows.fs.verify checks existence and content digest', async () => {
    const path = join(workspace, 'verify-me.txt');
    const content = 'deterministic';
    await runStep({ op: 'windows.fs.write', args: { path, content, encoding: 'utf8' } }, ctx());
    const ok = await runStep(
      { op: 'windows.fs.verify', args: { path, expectExists: true, expectContent: content } },
      ctx(),
    );
    expect(ok.ok).toBe(true);
    const bad = await runStep(
      { op: 'windows.fs.verify', args: { path, expectExists: true, expectContent: 'other' } },
      ctx(),
    );
    expect(bad.ok).toBe(false);
  });

  it('windows.fs.delete removes a file and reports prior existence', async () => {
    const path = join(workspace, 'delete-me.txt');
    await runStep(
      { op: 'windows.fs.write', args: { path, content: 'x', encoding: 'utf8' } },
      ctx(),
    );
    const r = await runStep({ op: 'windows.fs.delete', args: { path } }, ctx());
    expect(r.ok).toBe(true);
    expect(existsSync(path)).toBe(false);
    if (r.ok) expect(r.result.existed).toBe(true);
  });
});

describe('registry ops (HKCU)', () => {
  const key = `${registryScopeKey}\\interp`;

  it('create → setValue → verify → delete lifecycle', async () => {
    const c = await runStep({ op: 'windows.registry.createKey', args: { key } }, ctx());
    expect(c.ok, JSON.stringify(c)).toBe(true);
    const s = await runStep(
      {
        op: 'windows.registry.setValue',
        args: { key, valueName: 'Greeting', type: 'REG_SZ', data: 'hello & | ; world' },
      },
      ctx(),
    );
    expect(s.ok, JSON.stringify(s)).toBe(true);
    const v = await runStep(
      {
        op: 'windows.registry.verify',
        args: { key, expectKeyExists: true, expectValues: { greeting: 'hello & | ; world' } },
      },
      ctx(),
    );
    expect(v.ok, JSON.stringify(v)).toBe(true);
    const d = await runStep({ op: 'windows.registry.deleteKey', args: { key } }, ctx());
    expect(d.ok).toBe(true);
    const gone = await runStep(
      { op: 'windows.registry.verify', args: { key, expectKeyExists: false } },
      ctx(),
    );
    expect(gone.ok).toBe(true);
  });

  it('refuses keys outside the grant registry scope', async () => {
    const r = await runStep(
      { op: 'windows.registry.createKey', args: { key: 'HKCU\\SOFTWARE\\NotShun' } },
      ctx(),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('scope');
  });

  it('parseRegQueryOutput reads typed value lines', () => {
    const out =
      '\r\n    HKCU\\SOFTWARE\\ShunExecutorTests\\interp\r\n    Greeting    REG_SZ    hello world\r\n    Count    REG_DWORD    0x2a\r\n';
    expect(parseRegQueryOutput(out)).toEqual({ greeting: 'hello world', count: '0x2a' });
  });
});

describe('proc.exec (typed argv, shell:false)', () => {
  it('arguments arrive BYTE-EXACT — metacharacters are data, not syntax', async () => {
    const probe = join(root, 'argv-probe.mjs');
    mkdirSync(root, { recursive: true });
    writeFileSync(probe, 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', 'utf8');
    const hostile = ['a & whoami', 'b | c', 'd "q" e', 'f %PATH%', 'g $(x)', 'h\ti', ''];

    const r = await runStep(
      {
        op: 'windows.proc.exec',
        args: { program: process.execPath, args: [probe, ...hostile], expectExitCode: 0 },
      },
      ctx(),
    );
    expect(r.ok, JSON.stringify(r)).toBe(true);
    const stdoutFile = r.ok ? (r.result.stdoutRef as string) : '';
    expect(JSON.parse(readFileSync(stdoutFile, 'utf8'))).toEqual([probe, ...hostile]);
  });

  it('non-zero exit is a structured step failure with the exit code', async () => {
    const r = await runStep(
      {
        op: 'windows.proc.exec',
        args: { program: process.execPath, args: ['-e', 'process.exit(3)'], expectExitCode: 0 },
      },
      ctx(),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.result.exitCode).toBe(3);
  });

  it('expected exit code matching works', async () => {
    const r = await runStep(
      {
        op: 'windows.proc.exec',
        args: { program: process.execPath, args: ['-e', 'process.exit(3)'], expectExitCode: 3 },
      },
      ctx(),
    );
    expect(r.ok).toBe(true);
  });

  it('per-step deadline kills the child and fails the step (launcher-side tree-kill path)', async () => {
    const start = Date.now();
    const r = await runStep(
      {
        op: 'windows.proc.exec',
        args: {
          program: process.execPath,
          args: ['-e', 'setInterval(()=>{},1000)'],
          expectExitCode: 0,
          timeoutMs: 1500,
        },
      },
      ctx(),
    );
    const elapsed = Date.now() - start;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.result.timedOut).toBe(true);
    expect(elapsed).toBeLessThan(10000);
  });

  it('nonexistent program is a structured failure', async () => {
    const r = await runStep(
      { op: 'windows.proc.exec', args: { program: join(workspace, 'no-such.exe'), args: [] } },
      ctx(),
    );
    expect(r.ok).toBe(false);
  });
});

describe('contextCheck', () => {
  it('matches the actual (non-elevated) token state on this test surface', async () => {
    const r = await runStep(
      { op: 'windows.proc.contextCheck', args: { expectElevated: false } },
      ctx(),
    );
    expect(r.ok).toBe(true);
  });

  it('mismatch is a structured step failure', async () => {
    const r = await runStep(
      { op: 'windows.proc.contextCheck', args: { expectElevated: true } },
      ctx(),
    );
    expect(r.ok).toBe(false);
  });
});
