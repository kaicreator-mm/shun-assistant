// Unprivileged launcher for ONE protected ShunAnchorWriter job.
// It verifies the protected deployment and pinned writer/relay/interpreter
// BEFORE requesting UAC. The elevated writer itself re-verifies identity.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { assessAuthorityAnchors } from '../anchor-protection.ts';
import { resolveAgainstRoot } from '../fs-safety.ts';
import { verifyWriterIdentity } from './apply.ts';
import { WriterJobSchema } from './job.ts';
import { spawnRelay } from '../privileged-backend.ts';
import { systemPowershellExe, systemTaskkillExe } from '../system-exe.ts';
import {
  readHelperPin,
  readWriterPin,
  resolveGrantHmacKeyFile,
  sha256File,
} from '../trusted-store.ts';

export interface AnchorWriterLaunchOptions {
  authorityDir: string;
  workspaceRoot: string;
  writerBundlePath: string;
  relayScriptPath: string;
  jobFile: string;
  uacTimeoutMs?: number;
}

export type AnchorWriterLaunchResult =
  | { ok: true; jobId: string; receipt: unknown }
  | { ok: false; code: string; reason: string; jobId?: string };

export async function launchAnchorWriterJob(
  options: AnchorWriterLaunchOptions,
): Promise<AnchorWriterLaunchResult> {
  const assessment = assessAuthorityAnchors(
    options.authorityDir,
    resolveGrantHmacKeyFile(options.authorityDir),
  );
  if (assessment.forgeable) {
    return {
      ok: false,
      code: 'ANCHOR_NOT_PROTECTED',
      reason: assessment.reasons.join('; '),
    };
  }

  let rawJob: unknown;
  try {
    rawJob = JSON.parse(readFileSync(options.jobFile, 'utf8')) as unknown;
  } catch (error) {
    return { ok: false, code: 'JOB_UNREADABLE', reason: String(error) };
  }
  const parsedJob = WriterJobSchema.safeParse(rawJob);
  if (!parsedJob.success) {
    return { ok: false, code: 'JOB_MALFORMED', reason: parsedJob.error.message };
  }

  const writerPin = readWriterPin(options.authorityDir);
  if (!writerPin) {
    return { ok: false, code: 'WRITER_IDENTITY_MISMATCH', reason: 'writer pin missing/corrupt' };
  }
  const identity = verifyWriterIdentity(options.writerBundlePath, writerPin.writerSha256);
  if (!identity.ok) return identity;
  let nodeSha: string;
  try {
    nodeSha = sha256File(process.execPath);
  } catch (error) {
    return { ok: false, code: 'WRITER_IDENTITY_MISMATCH', reason: String(error) };
  }
  if (nodeSha !== writerPin.nodeExeSha256) {
    return {
      ok: false,
      code: 'WRITER_IDENTITY_MISMATCH',
      reason: 'runtime node.exe differs from writer-pin node identity',
    };
  }

  const helperPin = readHelperPin(options.authorityDir);
  if (!helperPin) {
    return { ok: false, code: 'RELAY_IDENTITY_MISMATCH', reason: 'helper pin missing/corrupt' };
  }
  if (helperPin.nodeExeSha256 !== nodeSha) {
    return {
      ok: false,
      code: 'RELAY_IDENTITY_MISMATCH',
      reason: 'writer/helper pins disagree on node.exe identity',
    };
  }
  let relaySha: string;
  try {
    relaySha = sha256File(options.relayScriptPath);
  } catch (error) {
    return { ok: false, code: 'RELAY_IDENTITY_MISMATCH', reason: String(error) };
  }
  if (relaySha !== helperPin.relaySha256) {
    return {
      ok: false,
      code: 'RELAY_IDENTITY_MISMATCH',
      reason: 'elevation relay bytes differ from protected helper pin',
    };
  }

  const workspace = resolveAgainstRoot(options.workspaceRoot, helperPin.workspaceRoot);
  if (!workspace.ok) {
    return { ok: false, code: 'WORKSPACE_ROOT_ESCAPE', reason: workspace.reason };
  }

  const powershellExe = systemPowershellExe(options.authorityDir);
  const taskkillExe = systemTaskkillExe(options.authorityDir);
  if (!powershellExe || !taskkillExe) {
    return {
      ok: false,
      code: 'SYSTEM_TOOL_IDENTITY_MISMATCH',
      reason: 'pinned PowerShell/taskkill identity unavailable',
    };
  }

  const relayFile = join(
    options.workspaceRoot,
    `anchor-writer-relay-${parsedJob.data.jobId}-${Date.now()}.json`,
  );
  const relay = await spawnRelay({
    powershellExe,
    taskkillExe,
    nodeExe: process.execPath,
    relayScript: options.relayScriptPath,
    helperBundle: options.writerBundlePath,
    helperArgs: [options.jobFile],
    relayFile,
    timeoutMs: options.uacTimeoutMs ?? 120_000,
  });
  if (relay.kind === 'UAC_DECLINED') {
    return {
      ok: false,
      code: 'UAC_DECLINED',
      reason: 'operator declined the one-shot writer elevation',
      jobId: parsedJob.data.jobId,
    };
  }
  if (relay.kind !== 'RAN' || relay.exitCode !== 0) {
    return {
      ok: false,
      code: 'WRITER_FAILED',
      reason: `writer relay ended ${relay.kind} exit=${relay.exitCode ?? 'none'}`,
      jobId: parsedJob.data.jobId,
    };
  }

  const receiptFile = join(
    options.authorityDir,
    'jobs',
    'receipts',
    `${parsedJob.data.jobId}.json`,
  );
  if (!existsSync(receiptFile)) {
    return {
      ok: false,
      code: 'WRITER_RECEIPT_MISSING',
      reason: 'writer exited success without its protected receipt',
      jobId: parsedJob.data.jobId,
    };
  }
  try {
    return {
      ok: true,
      jobId: parsedJob.data.jobId,
      receipt: JSON.parse(readFileSync(receiptFile, 'utf8')) as unknown,
    };
  } catch (error) {
    return {
      ok: false,
      code: 'WRITER_RECEIPT_CORRUPT',
      reason: String(error),
      jobId: parsedJob.data.jobId,
    };
  }
}
