import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  ExecutionReceipt,
  GoalContract,
  ShunStoreMutation,
  StoreApplicationReceipt,
  StorePort,
} from '@shun/contracts';

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'shun-workflow-'));
}

export function goalContract(overrides?: Partial<GoalContract>): GoalContract {
  return {
    taskId: 'task-1',
    objective: 'batch-process my photos',
    objects: [{ kind: 'DIRECTORY', ref: 'C:/Users/me/Pictures' }],
    constraints: { retainRemove: 'RETAIN' },
    privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
    environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    ambiguityDisposition: 'READY',
    ...overrides,
  };
}

let receiptSeq = 0;

export function executionReceipt(overrides?: Partial<ExecutionReceipt>): ExecutionReceipt {
  receiptSeq += 1;
  const ts = '2026-10-10T12:00:00.000Z';
  return {
    actionId: `action-${receiptSeq}`,
    environmentId: 'env-local',
    providerId: 'provider-image',
    providerVersion: '1.2.3',
    startedAt: ts,
    finishedAt: ts,
    terminal: 'SUCCEEDED',
    outputRefs: ['evidence://out/1'],
    sideEffectEvidence: {
      sideEffectClass: 'R0',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    },
    ...overrides,
  };
}

export function mutation(recordId: string, payload: Record<string, unknown>): ShunStoreMutation {
  return { recordKind: 'task', recordId, payload };
}

/** Counting StorePort double: records how many times effects truly applied. */
export class CountingStore implements StorePort {
  readonly receipts = new Map<string, StoreApplicationReceipt>();
  readonly appliedEffects: string[] = [];
  /** effectIds in this set fail (transport-ambiguity) until healed. */
  readonly failing = new Set<string>();

  async apply(effectId: string, applied: ShunStoreMutation): Promise<StoreApplicationReceipt> {
    if (this.failing.has(effectId)) {
      throw new Error(`store unavailable for ${effectId} (simulated transport ambiguity)`);
    }
    const existing = this.receipts.get(effectId);
    if (existing) {
      return { ...existing, applied: false };
    }
    const receipt: StoreApplicationReceipt = {
      effectId,
      applied: true,
      receiptRef: `shunstore://effect/${effectId}`,
    };
    this.receipts.set(effectId, receipt);
    this.appliedEffects.push(effectId);
    void applied;
    return receipt;
  }
}
