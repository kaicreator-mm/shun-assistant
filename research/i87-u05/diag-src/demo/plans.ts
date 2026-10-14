// Demo plan/residue builders for the in-memory reference backend (T08).
//
// These are TEST/DEMO doubles, not the Action Controller: they exist so the
// control surface is executable before T01–T03 land. Plans are built with the
// frozen T00 schemas and hashed with the frozen `computePlanHash`, so every
// preview/approval binds to a real, re-derivable plan identity. Sibling
// packages own real planning; nothing here leaks into authority.
import { type ActionPlan, computePlanHash } from '@shun/contracts';

export const IMAGE_RESIZE_OP = 'image.resize';
export const CACHE_CLEANUP_OP = 'file.delete';

/** Loop-A style R1 plan: bounded image resize, cooperative cancel, precommitted SSIM oracle. */
export function buildImageBatchPlan(taskId: string): ActionPlan {
  const base = {
    taskId,
    capabilityId: 'image.batch_process',
    bindingRefs: ['binding-imagemagick-localwin'],
    rankingPolicyRevision: 'rank-pol-v3',
    policySnapshotRevision: 'pol-snap-2026-10-10-a',
    actions: [
      {
        actionId: 'action-resize-001',
        bindingRef: 'binding-imagemagick-localwin',
        op: IMAGE_RESIZE_OP,
        parameters: { format: 'JPG', maxLongEdgePx: 1600 },
        sideEffectClass: 'R1',
        requiredPrivilege: 'NONE',
        filesystemScope: {
          read: ['C:\\demo\\pictures'],
          write: ['C:\\demo\\pictures\\resized'],
        },
        networkScope: { allowed: false },
        timeoutMs: 600000,
        cancellation: { supported: true, mode: 'COOPERATIVE' },
        expectedState: { count: 12, outputsDecode: true },
      },
    ],
    verificationPlan: {
      verifierId: 'verifier.image-ssim',
      verifierRevision: 'r2',
      checks: [
        { checkId: 'count-conservation' },
        { checkId: 'decode-all' },
        { checkId: 'edge-bound' },
        { checkId: 'ssim-oracle' },
      ],
      oracle: {
        precommitted: true,
        spec: { metric: 'SSIM', threshold: 0.95, sampleStrategy: 'ASC_SHA256_FIRST_20' },
      },
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    // Placeholder identity: computePlanHash excludes the planHash field, so
    // the hash below is computed over exactly the content above.
    planHash: '0'.repeat(64),
  } satisfies ActionPlan;
  return { ...base, planHash: computePlanHash(base) };
}

/** Loop-C style R2 plan: bounded cache deletion; protected/user assets are excluded by the plan itself. */
export function buildStorageCleanupPlan(taskId: string): ActionPlan {
  const base = {
    taskId,
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: ['binding-storage-localwin'],
    rankingPolicyRevision: 'rank-pol-v3',
    policySnapshotRevision: 'pol-snap-2026-10-10-a',
    actions: [
      {
        actionId: 'action-cleanup-001',
        bindingRef: 'binding-storage-localwin',
        op: CACHE_CLEANUP_OP,
        parameters: { targetRefs: ['local:residue/cache-manifest'] },
        sideEffectClass: 'R2',
        requiredPrivilege: 'NONE',
        filesystemScope: {
          read: ['C:\\Users\\demo\\AppData\\Local\\DemoApp'],
          write: ['C:\\Users\\demo\\AppData\\Local\\DemoApp\\Cache'],
        },
        networkScope: { allowed: false },
        timeoutMs: 120000,
        cancellation: { supported: true, mode: 'COOPERATIVE' },
        expectedState: { cacheDirPresent: true, deletedCount: 6 },
      },
    ],
    verificationPlan: {
      verifierId: 'verifier.storage-bounded-action',
      verifierRevision: 'r1',
      checks: [
        { checkId: 'reclaimed-space' },
        { checkId: 'protected-assets-untouched' },
        { checkId: 'deletion-bounded-to-plan' },
      ],
      oracle: {
        precommitted: true,
        spec: { expectedReclaimedBytes: 76_200_000 },
      },
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    planHash: '0'.repeat(64),
  } satisfies ActionPlan;
  return { ...base, planHash: computePlanHash(base) };
}

export interface DemoResidueItem {
  path: string;
  kind: 'CACHE' | 'LOG' | 'ORPHAN' | 'UNKNOWN';
  sizeBytes: number;
  classification: string;
  evidenceRef: string;
}

/** Fixed demo residue set for the cleanup task: readable summary by default, detail on demand. */
export function buildCleanupResidue(): DemoResidueItem[] {
  return [
    {
      path: 'C:\\Users\\demo\\AppData\\Local\\DemoApp\\Cache\\chunk-001.tmp',
      kind: 'CACHE',
      sizeBytes: 24_000_000,
      classification: 'safe-to-delete (regenerable cache)',
      evidenceRef: 'local:residue/item-001',
    },
    {
      path: 'C:\\Users\\demo\\AppData\\Local\\DemoApp\\Cache\\chunk-002.tmp',
      kind: 'CACHE',
      sizeBytes: 18_000_000,
      classification: 'safe-to-delete (regenerable cache)',
      evidenceRef: 'local:residue/item-002',
    },
    {
      path: 'C:\\Users\\demo\\AppData\\Local\\DemoApp\\Logs\\demo-old.log',
      kind: 'LOG',
      sizeBytes: 8_400_000,
      classification: 'safe-to-delete (rotated log)',
      evidenceRef: 'local:residue/item-003',
    },
    {
      path: 'C:\\Users\\demo\\AppData\\Local\\DemoApp\\Cache\\shader-000.tmp',
      kind: 'CACHE',
      sizeBytes: 12_000_000,
      classification: 'safe-to-delete (regenerable cache)',
      evidenceRef: 'local:residue/item-004',
    },
    {
      path: 'C:\\Users\\demo\\AppData\\Local\\DemoApp\\Cache\\shader-001.tmp',
      kind: 'CACHE',
      sizeBytes: 11_000_000,
      classification: 'safe-to-delete (regenerable cache)',
      evidenceRef: 'local:residue/item-005',
    },
    {
      path: 'C:\\Users\\demo\\AppData\\Local\\DemoApp\\orphans\\plugin-uninstalled.dll',
      kind: 'ORPHAN',
      sizeBytes: 2_800_000,
      classification: 'safe-to-delete (orphan of an uninstalled plugin)',
      evidenceRef: 'local:residue/item-006',
    },
    {
      path: 'C:\\Users\\demo\\Documents\\budget-2026.xlsx',
      kind: 'UNKNOWN',
      sizeBytes: 148_000,
      classification: 'PROTECTED — user document, never touched by the plan',
      evidenceRef: 'local:residue/protected-001',
    },
  ];
}

/** Readable byte counts for the residue headline ("~12.3 MB", not 12918456). */
export function readableBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `~${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `~${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `~${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

/** Which demo intent a goal maps to. Demo-only heuristic, never authority. */
export function demoIntentFor(goal: string): 'clarify' | 'unresolvable' | 'cleanup' | 'images' {
  const normalized = goal.toLowerCase();
  if (normalized.includes('?') || normalized.startsWith('clarify')) return 'clarify';
  if (normalized.includes('unknown-capability')) return 'unresolvable';
  if (
    normalized.includes('cleanup') ||
    normalized.includes('clean up') ||
    normalized.includes('disk')
  ) {
    return 'cleanup';
  }
  return 'images';
}
