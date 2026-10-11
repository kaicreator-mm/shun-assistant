// Production entry for the bounded one-shot ShunAnchorWriter (L2 v0.2 delta).
// Build-time constants pin the only writable authority root and key path.
// argv names ONE UNSIGNED strict-schema proposal file to READ. After UAC the
// elevated writer seals the exact parsed proposal with the protected key and
// immediately applies it; no caller-controlled output path ever becomes an
// elevated write primitive.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assessAnchorOwnership } from '../anchor-protection.ts';
import { readWriterPin, sha256File } from '../trusted-store.ts';
import { applyWriterJob, verifyWriterIdentity } from './apply.ts';
import { sealWriterJobProposal } from './seal.ts';

declare const SHUN_ANCHOR_WRITER_ROOT: string | undefined;
declare const SHUN_ANCHOR_WRITER_HMAC_KEY_FILE: string | undefined;

function builtPath(value: string | undefined, name: string): string {
  const trimmed = value?.trim();
  if (!trimmed) throw new Error(`${name} was not baked into this writer build; refusing`);
  return trimmed;
}

function emitAndExit(payload: Record<string, unknown>, code: number): never {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exit(code);
}

function protectedReceiptPath(root: string, jobId: string): string {
  return join(root, 'jobs', 'receipts', `${jobId}.json`);
}

function main(): never {
  const jobFile = process.argv.at(2);
  if (process.argv.length !== 3 || !jobFile) {
    return emitAndExit(
      { ok: false, code: 'USAGE', reason: 'expected exactly one unsigned writer proposal file' },
      2,
    );
  }

  const anchorRoot = builtPath(
    typeof SHUN_ANCHOR_WRITER_ROOT === 'string' ? SHUN_ANCHOR_WRITER_ROOT : undefined,
    'SHUN_ANCHOR_WRITER_ROOT',
  );
  const keyFile = builtPath(
    typeof SHUN_ANCHOR_WRITER_HMAC_KEY_FILE === 'string'
      ? SHUN_ANCHOR_WRITER_HMAC_KEY_FILE
      : undefined,
    'SHUN_ANCHOR_WRITER_HMAC_KEY_FILE',
  );
  const selfPath = fileURLToPath(import.meta.url);
  const pin = readWriterPin(anchorRoot);
  if (!pin) {
    return emitAndExit(
      { ok: false, code: 'WRITER_IDENTITY_MISMATCH', reason: 'writer-pin.json missing/corrupt' },
      2,
    );
  }
  const self = verifyWriterIdentity(selfPath, pin.writerSha256);
  if (!self.ok) return emitAndExit(self, 2);
  let nodeHash: string;
  try {
    nodeHash = sha256File(process.execPath);
  } catch (error) {
    return emitAndExit(
      {
        ok: false,
        code: 'WRITER_IDENTITY_MISMATCH',
        reason: `node.exe unreadable: ${String(error)}`,
      },
      2,
    );
  }
  if (nodeHash !== pin.nodeExeSha256) {
    return emitAndExit(
      {
        ok: false,
        code: 'WRITER_IDENTITY_MISMATCH',
        reason: `node.exe bytes differ from writer pin (${nodeHash} != ${pin.nodeExeSha256})`,
      },
      2,
    );
  }

  const preOwnership = assessAnchorOwnership(anchorRoot, keyFile);
  if (preOwnership.length > 0) {
    return emitAndExit(
      {
        ok: false,
        code: 'ANCHOR_WRITE_DENIED',
        reason: `authorization anchor ownership rejected before apply: ${preOwnership.join('; ')}`,
      },
      2,
    );
  }

  let key: string;
  let raw: unknown;
  try {
    key = readFileSync(keyFile, 'utf8').trim();
    if (!key) throw new Error('empty HMAC key');
    raw = JSON.parse(readFileSync(jobFile, 'utf8')) as unknown;
  } catch (error) {
    return emitAndExit(
      { ok: false, code: 'INPUT_UNREADABLE', reason: `writer input unavailable: ${String(error)}` },
      2,
    );
  }

  const sealed = sealWriterJobProposal(key, raw);
  if (!sealed.ok) {
    return emitAndExit({ ok: false, code: 'PROPOSAL_INVALID', reason: sealed.reason }, 2);
  }
  const result = applyWriterJob({ anchorRoot, hmacKeyBase64: key }, sealed.job);
  const ownership = assessAnchorOwnership(anchorRoot, keyFile);
  const guardedResult =
    result.ok && ownership.length > 0
      ? {
          ok: false as const,
          code: 'ANCHOR_WRITE_DENIED',
          reason: `writer produced authority objects without privileged ownership: ${ownership.join('; ')}`,
          target: result.target,
        }
      : result;
  const receipt = {
    ...guardedResult,
    writerSha256: pin.writerSha256,
    nodeExeSha256: pin.nodeExeSha256,
    finishedAt: new Date().toISOString(),
  };
  try {
    const dir = join(anchorRoot, 'jobs', 'receipts');
    mkdirSync(dir, { recursive: true });
    // Path derives only from the strict proposal schema's AnchorIdSchema.
    writeFileSync(
      protectedReceiptPath(anchorRoot, sealed.job.jobId),
      `${JSON.stringify(receipt, null, 2)}\n`,
      { encoding: 'utf8', flag: 'wx' },
    );
  } catch (error) {
    return emitAndExit(
      {
        ok: false,
        code: 'ANCHOR_WRITE_DENIED',
        reason: `protected writer receipt could not be persisted: ${String(error)}`,
        applyResult: guardedResult,
      },
      3,
    );
  }
  return emitAndExit(receipt, guardedResult.ok ? 0 : 2);
}

main();
