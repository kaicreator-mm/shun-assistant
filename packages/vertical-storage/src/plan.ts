// Bounded cleanup plan proposal + readable R2 preview + checkpoint manifest
// (L2 §9.1: adapters produce plan PROPOSALS; approval/authorization remain
// port seams). Bounded-ness is structural: targets are exhaustively
// enumerated, classified and measured before the plan hash exists, and every
// deletion this package can ever perform iterates a plan action — there is no
// code path that turns a size measurement into a deletion.
import { type Dirent, promises as fsp } from 'node:fs';
import * as path from 'node:path';
import {
  type ActionPlan,
  computePlanHash,
  PlanActionSchema,
  R2_GATE_PHASES,
} from '@shun/contracts';
import { z } from 'zod';
import type { Attribution } from './attribute.ts';
import { type CleanupCategory, classifyDirectory, touchesProtectedAsset } from './classify.ts';
import { StorageVerticalError } from './errors.ts';
import type { ObservationEvidence } from './observe.ts';
import type { ResolvedScope } from './scope.ts';
import { withinScope } from './scope.ts';

export const CleanupTargetSchema = z.strictObject({
  path: z.string().min(1),
  classification: z.enum(['CACHE', 'TEMP']),
  expectedReclaimBytes: z.number().int().nonnegative(),
  fileCount: z.number().int().nonnegative(),
});
export type CleanupTarget = z.infer<typeof CleanupTargetSchema>;

export const CheckpointManifestSchema = z.strictObject({
  checkpointRef: z.string().min(1),
  targets: z.array(
    z.strictObject({
      path: z.string().min(1),
      files: z.array(
        z.strictObject({
          path: z.string().min(1),
          sizeBytes: z.number().int().nonnegative(),
          mtimeMs: z.number(),
        }),
      ),
    }),
  ),
});
export type CheckpointManifest = z.infer<typeof CheckpointManifestSchema>;

export interface BuildCleanupPlanInput {
  taskId: string;
  targetVolume: string;
  attribution: Attribution;
  observation: ObservationEvidence;
  observationEvidenceRef: string;
  scope: ResolvedScope;
  protectedRealPaths: readonly string[];
  eligibleCategories: readonly CleanupCategory[];
  policySnapshotRevision: string;
  rankingPolicyRevision: string;
  environmentId: string;
  evidenceDir: string;
  clock: () => string;
}

export interface CleanupPlanProposal {
  plan: ActionPlan;
  targets: CleanupTarget[];
  preview: string;
  checkpoint: CheckpointManifest;
  gatePhases: readonly string[];
}

const PLAN_BINDING_REF = 'binding/shun-storage-local-windows';
export const STORAGE_CLEAN_VERIFIER_ID = 'verifier.storage-c003';
export const STORAGE_CLEAN_VERIFIER_REVISION = 'r1';

/**
 * Enumerate, classify and measure cleanup targets, write the checkpoint
 * manifest, and assemble the hashed ActionPlan. Refuses (fail-closed) unless
 * every target is (a) classified into an eligible category by path policy,
 * (b) inside the resolved scope, (c) free of protected-asset overlap.
 */
export async function buildCleanupPlan(input: BuildCleanupPlanInput): Promise<CleanupPlanProposal> {
  const {
    taskId,
    attribution,
    observation,
    scope,
    protectedRealPaths,
    eligibleCategories,
    evidenceDir,
  } = input;

  const targets: CleanupTarget[] = [];
  for (const dir of observation.directories) {
    if (dir.inaccessibleEntries.length > 0) continue;
    const classification = classifyDirectory(dir.path, {
      protectedRealPaths: [...protectedRealPaths],
      scopeRoots: scope.roots,
    });
    if (classification.cleanupCategory === null) continue; // fail-closed: unknown/user data is never a target
    if (!eligibleCategories.includes(classification.cleanupCategory)) continue;
    const targetPath = classification.path;
    if (!withinScope(targetPath, scope)) {
      throw new StorageVerticalError(
        'ACTION_NOT_BOUNDED',
        `classified target ${targetPath} escaped the resolved scope`,
      );
    }
    if (touchesProtectedAsset(targetPath, protectedRealPaths)) {
      throw new StorageVerticalError(
        'PROTECTED_ASSET_TOUCHED',
        `proposed target ${targetPath} is or contains a declared protected asset`,
      );
    }
    targets.push({
      path: targetPath,
      classification: classification.cleanupCategory,
      expectedReclaimBytes: dir.bytes,
      fileCount: dir.files,
    });
  }
  if (targets.length === 0) {
    throw new StorageVerticalError(
      'GROWTH_NOT_ATTRIBUTED',
      'no policy-eligible cleanup target survived classification',
    );
  }
  if (!targets.some((t) => t.path === attribution.growthSourcePath)) {
    throw new StorageVerticalError(
      'GROWTH_NOT_ATTRIBUTED',
      `attributed growth source ${attribution.growthSourcePath} is not among the enumerated targets`,
    );
  }

  const checkpoint = await writeCheckpointManifest(evidenceDir, taskId, targets);
  const checkpointRef = checkpoint.checkpointRef;

  const actions = targets.map((target, index) =>
    PlanActionSchema.parse({
      actionId: `action/${taskId}/storage-clean/${index}`,
      bindingRef: PLAN_BINDING_REF,
      op: 'storage.clean_directory',
      parameters: {
        targetPath: target.path,
        classification: target.classification,
        expectedReclaimBytes: target.expectedReclaimBytes,
        checkpointRef,
      },
      sideEffectClass: 'R2',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [target.path], write: [target.path] },
      networkScope: { allowed: false },
      timeoutMs: 120_000,
      cancellation: { supported: true, mode: 'COOPERATIVE' },
      expectedState: {
        targetPath: target.path,
        postCleanFiles: 0,
        manifestRef: checkpointRef,
      },
    }),
  );

  const draft = {
    taskId,
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: [PLAN_BINDING_REF],
    rankingPolicyRevision: input.rankingPolicyRevision,
    policySnapshotRevision: input.policySnapshotRevision,
    actions,
    verificationPlan: {
      verifierId: STORAGE_CLEAN_VERIFIER_ID,
      verifierRevision: STORAGE_CLEAN_VERIFIER_REVISION,
      checks: [
        { checkId: 'protected-assets-unchanged' },
        { checkId: 'reclaimed-bytes-verified' },
        { checkId: 'protected-asset-coverage' },
        { checkId: 'targets-within-scope' },
      ],
      oracle: {
        precommitted: true as const,
        spec: {
          protectedBaseline: 'declared-at-input-or-benchmark-envelope',
          reclaimSource: 'execution-journal-exec-done-entries',
        },
      },
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE' as const,
      reconcileBeforeRetry: true as const,
      retryAllowedWhen: 'DECLARED_IDEMPOTENT' as const,
      checkpointRef,
    },
  };
  const plan: ActionPlan = {
    ...draft,
    planHash: computePlanHash({ ...draft, planHash: '0'.repeat(64) }),
  };

  const preview = renderPreview({ plan, targets, attribution, input });

  return {
    plan,
    targets,
    preview,
    checkpoint,
    gatePhases: R2_GATE_PHASES,
  };
}

/**
 * Human-readable R2 preview (L2 §12: summarized user decisions; evidence
 * drill-down stays in refs). Metadata only — never file contents.
 */
export function renderPreview(context: {
  plan: ActionPlan;
  targets: CleanupTarget[];
  attribution: Attribution;
  input: BuildCleanupPlanInput;
}): string {
  const { plan, targets, attribution, input } = context;
  const lines: string[] = [];
  lines.push(`Shun storage cleanup preview — task ${plan.taskId}`);
  lines.push(`Target volume: ${input.targetVolume}`);
  lines.push(`Growth attribution: ${attribution.growthSourcePath} (${attribution.classifiedAs})`);
  lines.push(`Attribution evidence: ${attribution.explanation}`);
  lines.push(
    'Directories that will be deleted (exhaustive list; each is policy-classified and scope-checked):',
  );
  for (const target of targets) {
    lines.push(
      `  - [${target.classification}] ${target.path} — ${target.fileCount} files, ${target.expectedReclaimBytes} bytes`,
    );
  }
  lines.push('Protected assets (hash-verified, never deleted):');
  for (const p of input.protectedRealPaths) {
    lines.push(`  - ${p}`);
  }
  lines.push('Network access: none. Nothing leaves this machine.');
  lines.push(
    'Risk class R2 (destructive): execution happens only after your explicit approval; a recovery checkpoint manifest was written before execution.',
  );
  return lines.join('\n');
}

async function writeCheckpointManifest(
  evidenceDir: string,
  taskId: string,
  targets: CleanupTarget[],
): Promise<CheckpointManifest> {
  await fsp.mkdir(evidenceDir, { recursive: true });
  const manifestTargets: CheckpointManifest['targets'] = [];
  for (const target of targets) {
    const files: CheckpointManifest['targets'][number]['files'] = [];
    await inventoryFiles(target.path, target.path, files);
    manifestTargets.push({ path: target.path, files });
  }
  const manifest: Omit<CheckpointManifest, 'checkpointRef'> = { targets: manifestTargets };
  const fileName = `checkpoint-${sanitize(taskId)}.json`;
  const filePath = path.join(evidenceDir, fileName);
  await fsp.writeFile(filePath, JSON.stringify(manifest, null, 2), 'utf8');
  return { ...manifest, checkpointRef: `evidence://${sanitize(taskId)}/${fileName}` };
}

async function inventoryFiles(
  root: string,
  dir: string,
  out: CheckpointManifest['targets'][number]['files'],
  depth = 0,
): Promise<void> {
  if (depth > 16) return;
  let entries: Dirent[];
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue; // reparse points are never inventoried for deletion
    if (entry.isDirectory()) {
      await inventoryFiles(root, entryPath, out, depth + 1);
      continue;
    }
    if (!entry.isFile()) continue;
    try {
      const st = await fsp.lstat(entryPath);
      out.push({ path: entryPath, sizeBytes: st.size, mtimeMs: st.mtimeMs });
    } catch {
      // raced away between readdir and lstat: nothing to inventory
    }
  }
}

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]+/g, '_');
}
