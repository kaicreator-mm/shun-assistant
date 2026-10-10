// Verifier-level negatives that the diagnose integration cannot reach: the
// verifier must FAIL (never silently pass) when the receipt's reclaim claim
// diverges from what the privileged journal proves, when any multi-target
// receipt is failed/refused/partial, and the contracts coverage helper must
// catch undeclared/missing protected verifications.
import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { ExecutionReceipt } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { hashFile, verifyProtectedAssets, verifyStorageCleanup } from '../src/index.ts';

async function tmpDir(label: string): Promise<string> {
  return fsp.mkdtemp(path.join(os.tmpdir(), `shun-t07-verify-${label}-`));
}

function fakeVerificationInput(taskId: string, oracleInputs: Record<string, unknown>) {
  return {
    taskId,
    verificationPlan: {
      verifierId: 'verifier.storage-c003',
      verifierRevision: 'r1',
      checks: [{ checkId: 'reclaimed-bytes-verified' }],
    },
    executionReceipt: {
      actionId: 'a1',
      environmentId: 'env',
      providerId: 'p',
      providerVersion: '0',
      startedAt: '2026-10-10T10:00:00.000Z',
      finishedAt: '2026-10-10T10:01:00.000Z',
      terminal: 'SUCCEEDED' as const,
      outputRefs: [],
      sideEffectEvidence: {
        sideEffectClass: 'R2' as const,
        recoveryClassification: 'COMPLETED_VERIFIED' as const,
        postStateVerified: true,
      },
    },
    oracleInputs,
  };
}

function fakeStorageInput(taskId: string, protectedAssets: string[]) {
  return {
    taskId,
    targetVolume: 'X:',
    protectedAssets: protectedAssets.map((p) => ({ path: p })),
    cleanupPolicy: { eligibleCategories: ['CACHE' as const] },
  };
}

function fakeReceipt(actionId: string, terminal: ExecutionReceipt['terminal']): ExecutionReceipt {
  return {
    actionId,
    environmentId: 'env',
    providerId: 'p',
    providerVersion: '0',
    startedAt: '2026-10-10T10:00:00.000Z',
    finishedAt: '2026-10-10T10:01:00.000Z',
    terminal,
    outputRefs: [],
    sideEffectEvidence: {
      sideEffectClass: 'R2' as const,
      recoveryClassification: 'COMPLETED_VERIFIED' as const,
      postStateVerified: false,
    },
  };
}

/** Journal proving exactly one 100-byte durable deletion (a1) with RECEIPT_WRITTEN. */
async function writeProvenJournal(dir: string): Promise<string> {
  const journalPath = path.join(dir, 'journal.jsonl');
  await fsp.writeFile(
    journalPath,
    [
      JSON.stringify({ at: '2026-10-10T10:00:00.000Z', phase: 'RECEIVED', actionId: 'a1' }),
      JSON.stringify({
        at: '2026-10-10T10:00:01.000Z',
        phase: 'EXEC_DONE',
        actionId: 'a1',
        file: 'f.bin',
        bytes: 100,
      }),
      JSON.stringify({ at: '2026-10-10T10:00:02.000Z', phase: 'RECEIPT_WRITTEN', actionId: 'a1' }),
      '',
    ].join('\n'),
    'utf8',
  );
  return journalPath;
}

describe('verifyStorageCleanup reclaim honesty', () => {
  it('fails RECLAIM_NOT_VERIFIED when the claimed gross bytes exceed journal-proven deletions', async () => {
    const dir = await tmpDir('reclaim');
    const journalPath = path.join(dir, 'journal.jsonl');
    await fsp.writeFile(
      journalPath,
      [
        JSON.stringify({ at: '2026-10-10T10:00:00.000Z', phase: 'RECEIVED', actionId: 'a1' }),
        JSON.stringify({
          at: '2026-10-10T10:00:01.000Z',
          phase: 'EXEC_DONE',
          actionId: 'a1',
          file: 'f.bin',
          bytes: 100,
        }),
        '',
      ].join('\n'),
      'utf8',
    );
    const storageInput = fakeStorageInput('task-verify', []);
    const outcome = await verifyStorageCleanup({
      verificationInput: fakeVerificationInput('task-verify', {
        scopeRoots: ['C:\\scope'],
        reclaimed: { grossBytes: 999, postActionStateBytes: 0 },
      }),
      storageInput,
      protectedRealPaths: [],
      journal: { path: journalPath },
      postActionStateBytes: 0,
      deps: { preActionFingerprints: new Map() },
    });
    expect(outcome.receipt.status).toBe('FAIL');
    const reclaim = outcome.receipt.checks.find((c) => c.checkId === 'reclaimed-bytes-verified');
    expect(reclaim?.status).toBe('FAIL');
    expect(reclaim?.detail).toContain('RECLAIM_NOT_VERIFIED');
  });

  it('fails protected-assets-unchanged when no baseline is available (fail closed)', async () => {
    const dir = await tmpDir('baseline');
    const asset = path.join(dir, 'asset.txt');
    await fsp.writeFile(asset, 'content', 'utf8');
    await expect(verifyProtectedAssets({ protectedRealPaths: [asset], deps: {} })).rejects.toThrow(
      /no baseline available/,
    );
  });
});

describe('VS-P1-03 — failed/refused/partial multi-target receipts never verify PASS', () => {
  it('fails when any presented receipt is REFUSED, even if reclaim math matches the journal', async () => {
    const dir = await tmpDir('receipt-refused');
    const journalPath = await writeProvenJournal(dir);
    const outcome = await verifyStorageCleanup({
      verificationInput: fakeVerificationInput('task-multi', {
        scopeRoots: ['C:\\scope'],
        reclaimed: { grossBytes: 100, postActionStateBytes: 0 },
      }),
      storageInput: fakeStorageInput('task-multi', []),
      protectedRealPaths: [],
      journal: { path: journalPath },
      postActionStateBytes: 0,
      deps: { preActionFingerprints: new Map() },
      receipts: [fakeReceipt('a1', 'SUCCEEDED'), fakeReceipt('a2', 'REFUSED')],
    });
    expect(outcome.receipt.status).toBe('FAIL');
    const check = outcome.receipt.checks.find((c) => c.checkId === 'execution-receipts-terminal');
    expect(check?.status).toBe('FAIL');
    expect(check?.detail).toContain('a2');
  });

  it('fails when any presented receipt is a partial FAILED execution', async () => {
    const dir = await tmpDir('receipt-partial');
    const journalPath = await writeProvenJournal(dir);
    const outcome = await verifyStorageCleanup({
      verificationInput: fakeVerificationInput('task-partial', {
        scopeRoots: ['C:\\scope'],
        reclaimed: { grossBytes: 100, postActionStateBytes: 0 },
      }),
      storageInput: fakeStorageInput('task-partial', []),
      protectedRealPaths: [],
      journal: { path: journalPath },
      postActionStateBytes: 0,
      deps: { preActionFingerprints: new Map() },
      receipts: [fakeReceipt('a1', 'FAILED')],
    });
    expect(outcome.receipt.status).toBe('FAIL');
    const check = outcome.receipt.checks.find((c) => c.checkId === 'execution-receipts-terminal');
    expect(check?.status).toBe('FAIL');
  });

  it('fails a COMPLETED_VERIFIED claim that has no durable RECEIPT_WRITTEN in the journal', async () => {
    const dir = await tmpDir('receipt-nodurable');
    const journalPath = path.join(dir, 'journal.jsonl');
    // Effects journaled, but the receipt never reached durability.
    await fsp.writeFile(
      journalPath,
      [
        JSON.stringify({ at: '2026-10-10T10:00:00.000Z', phase: 'RECEIVED', actionId: 'a1' }),
        JSON.stringify({
          at: '2026-10-10T10:00:01.000Z',
          phase: 'EXEC_DONE',
          actionId: 'a1',
          file: 'f.bin',
          bytes: 100,
        }),
        '',
      ].join('\n'),
      'utf8',
    );
    const outcome = await verifyStorageCleanup({
      verificationInput: fakeVerificationInput('task-nodurable', {
        scopeRoots: ['C:\\scope'],
        reclaimed: { grossBytes: 100, postActionStateBytes: 0 },
      }),
      storageInput: fakeStorageInput('task-nodurable', []),
      protectedRealPaths: [],
      journal: { path: journalPath },
      postActionStateBytes: 0,
      deps: { preActionFingerprints: new Map() },
      receipts: [fakeReceipt('a1', 'SUCCEEDED')],
    });
    expect(outcome.receipt.status).toBe('FAIL');
    const check = outcome.receipt.checks.find((c) => c.checkId === 'execution-receipts-terminal');
    expect(check?.status).toBe('FAIL');
    expect(check?.detail).toMatch(/RECEIPT_WRITTEN/);
  });

  it('passes when every receipt succeeded and the journal is durable (positive control)', async () => {
    const dir = await tmpDir('receipt-ok');
    const journalPath = await writeProvenJournal(dir);
    const outcome = await verifyStorageCleanup({
      verificationInput: fakeVerificationInput('task-ok', {
        scopeRoots: ['C:\\scope'],
        reclaimed: { grossBytes: 100, postActionStateBytes: 0 },
      }),
      storageInput: fakeStorageInput('task-ok', []),
      protectedRealPaths: [],
      journal: { path: journalPath },
      postActionStateBytes: 0,
      deps: { preActionFingerprints: new Map() },
      receipts: [fakeReceipt('a1', 'SUCCEEDED')],
    });
    expect(outcome.receipt.status).toBe('PASS');
  });
});

describe('VS-P2-06 — protected hashing streams instead of buffering', () => {
  it('hashes a multi-chunk file correctly (streaming digest matches one-shot sha256)', async () => {
    const dir = await tmpDir('hash-stream');
    const file = path.join(dir, 'large.bin');
    // Well beyond a single internal chunk, so streaming is actually exercised.
    const payload = '0123456789abcdef'.repeat(128 * 1024); // 2 MiB
    await fsp.writeFile(file, payload, 'utf8');
    const streamed = await hashFile(file);
    const buffered = createHash('sha256').update(payload, 'utf8').digest('hex');
    expect(streamed).toBe(buffered);
  });
});
