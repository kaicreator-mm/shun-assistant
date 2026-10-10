// Typed op interpreter — the ONLY code that turns an allowlisted step into a
// Windows side effect (L2 §8.2 "structured subprocess execution"; §8.2.1 "no
// arbitrary shell endpoint").
//
// Shared verbatim (one bundled implementation) by:
//   - the in-process non-elevated backend path, and
//   - the one-shot elevated helper bundle;
// so both execution surfaces have byte-identical semantics. All process
// spawning is spawn() with argv arrays and shell:false — no cmd.exe, no
// string-concatenated command line exists anywhere on any path.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson, pathWithin } from '@shun/contracts';
import { resolveWithinScope } from './fs-safety.ts';
import type { JournalWriter } from './journal.ts';
import { type ExecutorStep, ExecutorStepSchema } from './ops.ts';

export interface InterpreterScope {
  filesystem?: { read: string[]; write: string[] };
  registry?: { write: string[] };
}

export interface InterpreterContext {
  journal: JournalWriter;
  scope: InterpreterScope;
  isElevated: boolean;
  /** Absolute helper-side deadline; steps check it before and during execution. */
  deadlineAt: Date;
  cancelFile?: string;
  evidenceDir: string;
}

export type StepOutcome =
  | { ok: true; result: Record<string, unknown> }
  | { ok: false; reason: string; result: Record<string, unknown> };

export class CancelledError extends Error {
  constructor() {
    super('cancel sentinel observed');
  }
}
export class DeadlineError extends Error {
  readonly where: string;

  constructor(where: string) {
    super(`helper-side deadline exceeded at ${where}`);
    this.where = where;
  }
}

/** Guard checked between phases, before and after every step. */
export function checkGuards(ctx: InterpreterContext, where: string): void {
  if (ctx.cancelFile && existsSync(ctx.cancelFile)) {
    ctx.journal.append('CANCELLED', { detail: { cancelFile: ctx.cancelFile, where } });
    throw new CancelledError();
  }
  if (now() >= ctx.deadlineAt) {
    ctx.journal.append('TIMED_OUT', { detail: { where } });
    throw new DeadlineError(where);
  }
}

// Helpers that keep the module usable from both the workspace (imports from
// source) and the esbuild bundle (identical code, bundled).
function now(): Date {
  return new Date();
}

function readScopePaths(scope: InterpreterScope): string[] {
  return [...(scope.filesystem?.read ?? []), ...(scope.filesystem?.write ?? [])];
}

function writeScopePaths(scope: InterpreterScope): string[] {
  return scope.filesystem?.write ?? [];
}

function registryScopePrefixes(scope: InterpreterScope): string[] {
  return scope.registry?.write ?? [];
}

function failScope(reason: string): StepOutcome {
  return { ok: false, reason: `scope: ${reason}`, result: {} };
}

/**
 * Run ONE step. Side-effect window = [journal EXEC_START, journal
 * EXEC_DONE/EXEC_STEP_FAILED]; the caller journals EXEC_START and the
 * terminal event around this call so §9.4 classification stays derivable
 * from the journal alone.
 */
export async function runStep(
  step: ExecutorStep | Parameters<typeof ExecutorStepSchema.parse>[0],
  ctx: InterpreterContext,
): Promise<StepOutcome> {
  // Re-parse: callers may pass input-shaped steps (schema defaults applied);
  // already-parsed steps roundtrip unchanged.
  let parsed: ExecutorStep;
  try {
    parsed = ExecutorStepSchema.parse(step) as ExecutorStep;
  } catch (e) {
    return { ok: false, reason: `step failed typed-surface validation: ${message(e)}`, result: {} };
  }
  try {
    return await runParsedStep(parsed, ctx);
  } catch (err) {
    if (err instanceof CancelledError || err instanceof DeadlineError) throw err;
    // Windows API failures (ENOENT/EINVAL/EPERM…) are structured step
    // failures, never crashes and never shell text.
    return { ok: false, reason: `op ${parsed.op} raised: ${message(err)}`, result: {} };
  }
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function runParsedStep(step: ExecutorStep, ctx: InterpreterContext): Promise<StepOutcome> {
  switch (step.op) {
    case 'windows.proc.contextCheck': {
      const actualElevated = ctx.isElevated;
      const result = { expectElevated: step.args.expectElevated, actualElevated };
      if (actualElevated !== step.args.expectElevated) {
        return { ok: false, reason: 'elevation context mismatch', result };
      }
      return { ok: true, result };
    }
    case 'windows.fs.write': {
      const within = resolveWithinScope(step.args.path, writeScopePaths(ctx.scope));
      if (!within.ok) return failScope(within.reason);
      const bytes = Buffer.byteLength(step.args.content, 'utf8');
      writeFileSync(within.resolved, step.args.content, { encoding: 'utf8' });
      return {
        ok: true,
        result: { path: within.resolved, bytes, sha256: sha256Text(step.args.content) },
      };
    }
    case 'windows.fs.delete': {
      const within = resolveWithinScope(step.args.path, writeScopePaths(ctx.scope));
      if (!within.ok) return failScope(within.reason);
      const st = statSync(within.resolved, { throwIfNoEntry: false });
      const existed = st !== undefined;
      if (existed) {
        if (st.isDirectory()) {
          return {
            ok: false,
            reason: `refusing directory delete (file-scoped op): ${within.resolved}`,
            result: { path: within.resolved },
          };
        }
        unlinkFileSync(within.resolved);
      }
      return { ok: true, result: { path: within.resolved, existed } };
    }
    case 'windows.fs.verify': {
      const within = resolveWithinScope(step.args.path, readScopePaths(ctx.scope));
      if (!within.ok) return failScope(within.reason);
      const st = statSync(within.resolved, { throwIfNoEntry: false });
      const exists = st !== undefined && !st.isDirectory();
      let contentMatches = true;
      let sha256: string | undefined;
      if (exists) {
        const content = readTextSync(within.resolved);
        sha256 = createHash('sha256').update(content, 'utf8').digest('hex');
        if (step.args.expectContent !== undefined && content !== step.args.expectContent)
          contentMatches = false;
        if (step.args.expectSha256 !== undefined && sha256 !== step.args.expectSha256)
          contentMatches = false;
      }
      const result = {
        path: within.resolved,
        exists,
        contentMatches,
        ...(sha256 ? { sha256 } : {}),
      };
      if (!exists || !contentMatches) {
        return { ok: false, reason: 'post-state verification failed inside executor', result };
      }
      return { ok: true, result };
    }
    case 'windows.registry.createKey':
      return registryExec(step, ctx, ['add', step.args.key, '/f'], () => ({}));
    case 'windows.registry.setValue':
      return registryExec(
        step,
        ctx,
        () => {
          const base = ['add', step.args.key, '/v', step.args.valueName, '/t', step.args.type];
          return step.args.type === 'REG_DWORD'
            ? [...base, '/d', String(step.args.data), '/f']
            : [...base, '/d', step.args.data as string, '/f'];
        },
        () => ({
          key: step.args.key,
          valueName: step.args.valueName,
          type: step.args.type,
          data: step.args.data,
        }),
      );
    case 'windows.registry.deleteKey':
      return registryExec(step, ctx, ['delete', step.args.key, '/f'], () => ({
        key: step.args.key,
      }));
    case 'windows.registry.verify': {
      const prefixes = registryScopePrefixes(ctx.scope);
      if (prefixes.length === 0)
        return failScope('grant declares no registry scope but the action touches the registry');
      const contained = prefixes.some((p) => pathWithin(step.args.key, p));
      if (!contained) return failScope(`registry key outside declared scope: ${step.args.key}`);
      const query = await execCaptured(REG_EXE, ['query', step.args.key], ctx, 30000);
      const exists = query.exitCode === 0;
      const values = exists ? parseRegQueryOutput(query.stdout) : {};
      let ok = true;
      if (step.args.expectKeyExists !== undefined && exists !== step.args.expectKeyExists)
        ok = false;
      for (const [name, expected] of Object.entries(step.args.expectValues ?? {})) {
        if (values[name.toLowerCase()] !== expected) ok = false;
      }
      const result = {
        key: step.args.key,
        exists,
        observedValues: values,
        expectKeyExists: step.args.expectKeyExists,
        expectValues: step.args.expectValues ?? {},
      };
      if (!ok) return { ok: false, reason: 'registry post-state mismatch', result };
      return { ok: true, result };
    }
    case 'windows.proc.exec': {
      const st = statSync(step.args.program, { throwIfNoEntry: false });
      if (!st?.isFile()) {
        return {
          ok: false,
          reason: `program does not exist or is not a file: ${step.args.program}`,
          result: {},
        };
      }
      const remainingMs = ctx.deadlineAt.getTime() - now().getTime();
      const budgetMs = Math.min(
        step.args.timeoutMs ?? Number.MAX_SAFE_INTEGER,
        Math.max(remainingMs, 0),
      );
      const r = await execCaptured(
        step.args.program,
        step.args.args,
        ctx,
        budgetMs,
        step.args.captureCapBytes,
      );
      const stdoutRef = writeEvidence(ctx.evidenceDir, step, 'stdout', r.stdout);
      const stderrRef = writeEvidence(ctx.evidenceDir, step, 'stderr', r.stderr);
      const result = {
        program: step.args.program,
        exitCode: r.exitCode,
        timedOut: r.timedOut,
        cancelled: r.cancelled,
        stdoutRef,
        stderrRef,
        stdoutBytes: r.stdoutBytes,
        stderrBytes: r.stderrBytes,
        truncated: r.truncated,
      };
      if (r.cancelled) throw new CancelledError();
      if (r.timedOut)
        return {
          ok: false,
          reason: 'child process exceeded its deadline; killed by executor',
          result,
        };
      if (r.exitCode !== step.args.expectExitCode) {
        return {
          ok: false,
          reason: `exit code ${r.exitCode} != expected ${step.args.expectExitCode}`,
          result,
        };
      }
      return { ok: true, result };
    }
  }
}

// ---- process execution (argv array, shell:false, bounded capture). ----

interface CapturedResult {
  exitCode: number | null;
  timedOut: boolean;
  cancelled: boolean;
  stdout: string;
  stderr: string;
  stdoutBytes: number;
  stderrBytes: number;
  truncated: boolean;
}

const REG_EXE = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'reg.exe');
const POLL_MS = 250;

async function execCaptured(
  program: string,
  args: string[],
  ctx: InterpreterContext,
  timeoutMs: number,
  capBytes = 262144,
): Promise<CapturedResult> {
  return new Promise((resolve) => {
    const child = spawn(program, args, {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const outStream = child.stdout;
    const errStream = child.stderr;
    if (!outStream || !errStream) throw new Error('spawn produced no stdio pipes');
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let truncated = false;
    let timedOut = false;
    let cancelled = false;
    const drain = (
      stream: NodeJS.ReadableStream,
      onText: (t: string) => void,
      onBytes: (n: number) => void,
    ) => {
      stream.on('data', (chunk: Buffer) => {
        onBytes(chunk.length);
        if (stdoutBytes + stderrBytes <= capBytes) onText(chunk.toString('utf8'));
        else truncated = true;
      });
    };
    drain(
      outStream,
      (t) => (stdout += t),
      (n) => (stdoutBytes += n),
    );
    drain(
      errStream,
      (t) => (stderr += t),
      (n) => (stderrBytes += n),
    );
    const timer = setTimeout(
      () => {
        timedOut = true;
        child.kill();
      },
      Math.max(timeoutMs, 0),
    );
    const poll = setInterval(() => {
      if (ctx.cancelFile && existsSync(ctx.cancelFile)) {
        cancelled = true;
        child.kill();
      }
    }, POLL_MS);
    const finish = (exitCode: number | null) => {
      clearTimeout(timer);
      clearInterval(poll);
      resolve({
        exitCode,
        timedOut,
        cancelled,
        stdout,
        stderr,
        stdoutBytes,
        stderrBytes,
        truncated,
      });
    };
    child.on('error', () => finish(-1));
    child.on('exit', (code) => finish(code));
  });
}

// ---- reg.exe output parsing (typed tokens; parse failure fails closed). ----

export function parseRegQueryOutput(stdout: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of stdout.split(/\r?\n/)) {
    // `    valueName    REG_SZ    data` — type tokens are not localized; a
    // line that does not match the shape is skipped, an expected value that
    // then mismatches fails the step (fail closed).
    const m = /^ {4}(.+?) {4}(REG_[A-Z]+) {4}(.*)$/.exec(line);
    if (m?.[1] !== undefined) {
      const data = m[3] ?? '';
      values[m[1].toLowerCase()] = data;
    }
  }
  return values;
}

function _normalizeKey(key: string): string {
  return key.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase();
}

// ---- small indirections (kept for test seam clarity; no shell anywhere). ----

function registryExec(
  step: Extract<
    ExecutorStep,
    {
      op: 'windows.registry.createKey' | 'windows.registry.setValue' | 'windows.registry.deleteKey';
    }
  >,
  ctx: InterpreterContext,
  argv: readonly string[] | (() => readonly string[]),
  result: () => Record<string, unknown>,
): Promise<StepOutcome> {
  const prefixes = registryScopePrefixes(ctx.scope);
  if (prefixes.length === 0)
    return Promise.resolve(
      failScope('grant declares no registry scope but the action touches the registry'),
    );
  const contained = prefixes.some((p) => pathWithin(step.args.key, p));
  if (!contained)
    return Promise.resolve(failScope(`registry key outside declared scope: ${step.args.key}`));
  const finalArgv = typeof argv === 'function' ? argv() : argv;
  const remainingMs = ctx.deadlineAt.getTime() - now().getTime();
  return execCaptured(REG_EXE, [...finalArgv], ctx, Math.max(remainingMs, 0)).then((r) => {
    if (r.timedOut) {
      return {
        ok: false,
        reason: 'registry op exceeded its deadline',
        result: { ...result(), exitCode: r.exitCode, timedOut: true },
      } as StepOutcome;
    }
    if (r.cancelled) throw new CancelledError();
    if (r.exitCode !== 0) {
      return {
        ok: false,
        reason: `reg.exe exit ${r.exitCode}`,
        result: { ...result(), exitCode: r.exitCode, stderr: r.stderr.trim().slice(0, 2000) },
      } as StepOutcome;
    }
    return { ok: true, result: result() } as StepOutcome;
  });
}

function writeEvidence(
  evidenceDir: string,
  step: ExecutorStep,
  kind: 'stdout' | 'stderr',
  content: string,
): string | undefined {
  if (content.length === 0) return undefined;
  mkdirSync(evidenceDir, { recursive: true });
  const file = join(evidenceDir, `step-${stepDigest(step)}-${kind}.txt`);
  writeFileSync(file, content, 'utf8');
  return file;
}

function stepDigest(step: ExecutorStep): string {
  return createHash('sha256').update(canonicalJson(step), 'utf8').digest('hex').slice(0, 12);
}

function unlinkFileSync(path: string): void {
  unlinkSync(path);
}

function readTextSync(path: string): string {
  return readFileSync(path, 'utf8');
}

function sha256Text(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
