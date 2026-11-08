/**
 * U05-B1 — proposal-only metadata plan projection.
 * Caller must be the trusted Host after exact root/INSPECT receipt verification.
 * This value never creates a human grant, K permit, or OS effect.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { ComputerFolderObservation } from '../../../../packages/domain-computer/src/computer/folder-observation.ts';

const MAX_TTL_MS = 60_000;
const MAX_DIRECTORIES = 256;
const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_HEX = /^[a-f0-9]{1,32}$/i;
// biome-ignore lint/suspicious/noControlCharactersInRegex: path refusal requires these characters
const FORBIDDEN_NAME = /[\\/:*?"<>|\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;

export type ReadOnlyPlanPreviewInput = Readonly<{
  taskId: string;
  journeyId: string;
  caseRef: unknown;
  originStepId: string;
  selectedRootRef: string;
  volumeSerial: string;
  fileId: string;
  selectedRootExpiresAtUnixMs: number;
  observation: ComputerFolderObservation;
  nowUnixMs: number;
}>;

export type ReadOnlyPlanPreview = Readonly<{
  schema: 'shun.host.selected-root-plan-preview.v1';
  status: 'PROPOSAL_ONLY';
  actionPreviewRef: string;
  taskId: string;
  journeyId: string;
  caseRef: unknown;
  originStepId: string;
  selectedRootRef: string;
  volumeSerial: string;
  fileId: string;
  evidenceRevision: string;
  observedAtUnixMs: number;
  expiresAtUnixMs: number;
  operation: 'REVIEW_METADATA_ONLY';
  expectedChange: 'NO_FILESYSTEM_CHANGE';
  recovery: 'NO_UNDO_REQUIRED';
  risk: 'NO_EFFECT';
  relativeTargets: readonly string[];
  directoryCount: number;
  rootFileCount: number;
  totalBytes: number;
  planDigest: string;
  executionAuthorized: false;
}>;

export type ReadOnlyPlanPreviewResult =
  | Readonly<{ ok: true; preview: ReadOnlyPlanPreview }>
  | Readonly<{ ok: false; code: string }>;

function safeRelativeChild(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 255 &&
    value !== '.' &&
    value !== '..' &&
    !value.endsWith(' ') &&
    !value.endsWith('.') &&
    !FORBIDDEN_NAME.test(value) &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value);
}

/**
 * Builds an immutable, bounded evidence-backed proposal. It intentionally
 * advertises only a no-effect metadata review; effect operations belong to B2.
 * Never pass unvalidated caller-provided metadata directly to this function.
 */
export function createReadOnlySelectedRootPlanPreview(
  input: ReadOnlyPlanPreviewInput,
): ReadOnlyPlanPreviewResult {
  if (!input || typeof input !== 'object') {
    return { ok: false, code: 'PLAN_PREVIEW_BINDING_REFUSED' };
  }
  const o = input.observation;
  const now = input.nowUnixMs;
  if (
    !o || o.schema !== 'shun.computer.folder-observation.v03' ||
    o.status !== 'OBSERVED_ONLY' || o.source !== 'TRUSTED_HOST_PORT' ||
    o.localOnly !== true || o.executionAuthorized !== false ||
    o.limitation !== 'METADATA_ONLY_NO_CONTENT_OR_CAUSE' ||
    !Array.isArray(o.externalDisclosures) || o.externalDisclosures.length !== 0 ||
    !o.rootFiles || !Number.isSafeInteger(o.rootFiles.bytes) ||
    o.rootFiles.bytes < 0 ||
    !Array.isArray(o.directories) ||
    o.directories.length > MAX_DIRECTORIES ||
    !Number.isSafeInteger(now) || now <= 0 ||
    !Number.isSafeInteger(input.selectedRootExpiresAtUnixMs) ||
    input.selectedRootExpiresAtUnixMs <= now ||
    input.selectedRootExpiresAtUnixMs > now + 5 * 60_000 ||
    typeof input.selectedRootRef !== 'string' ||
    !/^host:folder:[a-f0-9]{64}$/.test(input.selectedRootRef) ||
    o.rootRef !== input.selectedRootRef ||
    !SAFE_REF.test(o.scopeRevision) ||
    !SAFE_HEX.test(input.volumeSerial) ||
    !SAFE_HEX.test(input.fileId) ||
    typeof input.taskId !== 'string' || !SAFE_REF.test(input.taskId) ||
    typeof input.journeyId !== 'string' || !SAFE_REF.test(input.journeyId) ||
    typeof input.originStepId !== 'string' || !SAFE_REF.test(input.originStepId)
  ) return { ok: false, code: 'PLAN_PREVIEW_BINDING_REFUSED' };

  const observedAt = Date.parse(o.observedAt);
  if (
    !Number.isSafeInteger(observedAt) ||
    observedAt > now ||
    now - observedAt > MAX_TTL_MS ||
    !Number.isSafeInteger(o.totalBytes) || o.totalBytes < 0 ||
    !Number.isSafeInteger(o.rootFiles.count) || o.rootFiles.count < 0 ||
    o.rootFiles.count > 4096
  ) return { ok: false, code: 'PLAN_PREVIEW_EVIDENCE_STALE' };

  let caseJson: string;
  try { caseJson = JSON.stringify(input.caseRef); }
  catch { return { ok: false, code: 'PLAN_PREVIEW_CASE_INVALID' }; }
  if (typeof caseJson !== 'string' || caseJson.length < 4 || caseJson.length > 2048) {
    return { ok: false, code: 'PLAN_PREVIEW_CASE_INVALID' };
  }
  const caseRef = JSON.parse(caseJson) as Record<string, unknown>;
  if (!caseRef || typeof caseRef !== 'object' || Array.isArray(caseRef) ||
      Object.keys(caseRef).sort().join('|') !== 'digest|snapshotId' ||
      typeof caseRef.snapshotId !== 'string' || !SAFE_REF.test(caseRef.snapshotId) ||
      typeof caseRef.digest !== 'string' || !/^[a-f0-9]{64}$/.test(caseRef.digest)) {
    return { ok: false, code: 'PLAN_PREVIEW_CASE_INVALID' };
  }
  const targets: string[] = [];
  let aggregateBytes = o.rootFiles.bytes;
  const seen = new Set<string>();
  for (const entry of o.directories) {
    if (
      !entry || !safeRelativeChild(entry.relativePath) ||
      !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 ||
      !Number.isSafeInteger(entry.files) || entry.files < 0 ||
      !Number.isSafeInteger(entry.inaccessibleCount) || entry.inaccessibleCount !== 0
    ) return { ok: false, code: 'PLAN_PREVIEW_SCOPE_REFUSED' };
    const key = entry.relativePath.toLocaleLowerCase('en-US');
    if (seen.has(key)) return { ok: false, code: 'PLAN_PREVIEW_SCOPE_REFUSED' };
    seen.add(key);
    aggregateBytes += entry.bytes;
    if (!Number.isSafeInteger(aggregateBytes)) {
      return { ok: false, code: 'PLAN_PREVIEW_SCOPE_REFUSED' };
    }
    targets.push(entry.relativePath);
  }
  if (aggregateBytes !== o.totalBytes) {
    return { ok: false, code: 'PLAN_PREVIEW_SCOPE_REFUSED' };
  }
  targets.sort((a, b) => a.localeCompare(b, 'en-US'));
  const expiresAt = Math.min(input.selectedRootExpiresAtUnixMs, now + MAX_TTL_MS);
  if (expiresAt <= now) return { ok: false, code: 'PLAN_PREVIEW_EXPIRED' };
  const body = {
    schema: 'shun.host.selected-root-plan-preview.v1' as const,
    status: 'PROPOSAL_ONLY' as const,
    taskId: input.taskId,
    journeyId: input.journeyId,
    caseRef: Object.freeze(caseRef),
    originStepId: input.originStepId,
    selectedRootRef: input.selectedRootRef,
    volumeSerial: input.volumeSerial,
    fileId: input.fileId,
    evidenceRevision: o.scopeRevision,
    observedAtUnixMs: observedAt,
    expiresAtUnixMs: expiresAt,
    operation: 'REVIEW_METADATA_ONLY' as const,
    expectedChange: 'NO_FILESYSTEM_CHANGE' as const,
    recovery: 'NO_UNDO_REQUIRED' as const,
    risk: 'NO_EFFECT' as const,
    relativeTargets: Object.freeze(targets),
    directoryCount: targets.length,
    rootFileCount: o.rootFiles.count,
    totalBytes: o.totalBytes,
    executionAuthorized: false as const,
  };
  const planDigest = createHash('sha256')
    .update(JSON.stringify(body), 'utf8')
    .digest('hex');
  return {
    ok: true,
    preview: Object.freeze({
      ...body,
      planDigest,
      actionPreviewRef: 'host:preview:' + randomBytes(32).toString('hex'),
    }),
  };
}
