// Verifier-level negatives that the diagnose integration cannot reach: the
// verifier must FAIL (never silently pass) when the receipt's reclaim claim
// diverges from what the privileged journal proves, and the contracts
// coverage helper must catch undeclared/missing protected verifications.
import { promises as fsp } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyProtectedAssets, verifyStorageCleanup } from '../src/index.ts';

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
