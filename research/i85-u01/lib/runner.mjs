// i85-U01 shared evidence runner.
// Every evidence-bearing step appends one NDJSON event line to
// research/i85-u01/evidence/events.ndjson IMMEDIATELY after the step:
//   { ts, step, cmd, rc, outTail, sha256 }
// sha256 is computed over the FULL raw stdout+stderr bytes of the step.
// Numbers recorded anywhere in evidence come only from real run outputs.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const RESEARCH_DIR = resolve(HERE, '..');
export const EVIDENCE_DIR = resolve(RESEARCH_DIR, 'evidence');
export const EVENTS_FILE = resolve(EVIDENCE_DIR, 'events.ndjson');
export const TMP_ARTIFACTS = 'C:\\xDev\\kAiCreator\\_tmp\\i85-u01';

export function sha256Bytes(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export async function sha256File(path) {
  return sha256Bytes(await readFile(path));
}

export async function ensureDirs() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
  await mkdir(TMP_ARTIFACTS, { recursive: true }).catch(() => {});
}

/**
 * Append one event line immediately. `outTail` is truncated for the stream;
 * callers that need full output persist it separately (evidence JSON or _tmp).
 */
export async function logEvent(step, { cmd, rc, stdout = '', stderr = '', outTailMax = 600, extra }) {
  const raw = Buffer.concat([Buffer.from(stdout, 'utf8'), Buffer.from(stderr, 'utf8')]);
  const line = {
    ts: new Date().toISOString(),
    step,
    cmd,
    rc,
    outTail: raw.toString('utf8').slice(-outTailMax),
    sha256: sha256Bytes(raw),
    ...(extra ? { extra } : {}),
  };
  await appendFile(EVENTS_FILE, `${JSON.stringify(line)}\n`, 'utf8');
  return line;
}

/** Structured note event (no command executed) — e.g. a decision or a count. */
export async function logNote(step, note) {
  const line = { ts: new Date().toISOString(), step, note };
  await appendFile(EVENTS_FILE, `${JSON.stringify(line)}\n`, 'utf8');
  return line;
}

/**
 * Run one command for evidence. Command output is captured in full; the full
 * capture is handed back (and optionally persisted to the _tmp artifacts dir),
 * while events.ndjson receives rc + outTail + sha256 of the full capture.
 * All external calls made by harness code itself must use AbortSignal.timeout.
 */
export function runCmd(step, file, args, { timeoutMs = 60_000, shell = false, fullToTmp = null } = {}) {
  return new Promise((resolveRun) => {
    const child = spawn(file, args, { shell, windowsHide: true });
    const chunks = [];
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        child.kill('kill');
      }
    }, timeoutMs);
    const onOut = (d) => chunks.push(d);
    child.stdout.on('data', onOut);
    child.stderr.on('data', onOut);
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      finish(1, Buffer.from(`spawn-error: ${err.message}`));
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      finish(code === null ? 1 : code, Buffer.concat(chunks));
    });
    const finish = async (rc, buf) => {
      const text = buf.toString('utf8');
      if (fullToTmp) {
        await writeFile(resolve(TMP_ARTIFACTS, fullToTmp), text, 'utf8').catch(() => {});
      }
      const event = await logEvent(step, {
        cmd: `${file} ${args.join(' ')}`.slice(0, 400),
        rc,
        stdout: text,
      });
      resolveRun({ rc, text, event });
    };
  });
}
