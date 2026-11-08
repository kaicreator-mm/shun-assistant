import { describe, expect, it } from 'vitest';
import type { ReadOnlyPlanPreviewInput } from '../src/v03/selected-root-plan-preview.ts';
import {
  createReadOnlySelectedRootPlanPreview,
  verifyReadOnlySelectedRootPlanPreview,
} from '../src/v03/selected-root-plan-preview.ts';

const NOW = 1_800_000_000_000;
const ROOT_REF = 'host:folder:' + 'a'.repeat(64);
function valid(): ReadOnlyPlanPreviewInput {
  return {
    taskId: 'task-folder-r04',
    journeyId: 'journey-folder-r04',
    caseRef: { snapshotId: 'case-r04', digest: 'a'.repeat(64) },
    originStepId: 'step-inspect-scope',
    selectedRootRef: ROOT_REF,
    volumeSerial: '1a2b3c4d',
    fileId: '0123456789abcdef',
    selectedRootExpiresAtUnixMs: NOW + 90_000,
    nowUnixMs: NOW,
    observation: {
      schema: 'shun.computer.folder-observation.v03',
      status: 'OBSERVED_ONLY',
      source: 'TRUSTED_HOST_PORT',
      rootRef: ROOT_REF,
      scopeRevision: 'folder-scope-' + 'f'.repeat(32),
      observedAt: new Date(NOW - 1_000).toISOString(),
      totalBytes: 15,
      directories: [
        {
          relativePath: 'Documents',
          bytes: 10,
          files: 1,
          lastModifiedMs: NOW - 5_000,
          inaccessibleCount: 0,
        },
      ],
      rootFiles: { count: 1, bytes: 5 },
      localOnly: true,
      externalDisclosures: [],
      executionAuthorized: false,
      limitation: 'METADATA_ONLY_NO_CONTENT_OR_CAUSE',
    },
  };
}

describe('U05-B1 selected-root proposal-only projection', () => {
  it('builds one immutable evidence-bound proposal without authority or path disclosure', () => {
    const a = createReadOnlySelectedRootPlanPreview(valid());
    const b = createReadOnlySelectedRootPlanPreview(valid());
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.preview.planDigest).toBe(b.preview.planDigest);
    expect(a.preview.actionPreviewRef).not.toBe(b.preview.actionPreviewRef);
    expect(a.preview.expiresAtUnixMs).toBe(NOW + 60_000);
    expect(a.preview.relativeTargets).toEqual(['Documents']);
    expect(a.preview.operation).toBe('REVIEW_METADATA_ONLY');
    expect(a.preview.executionAuthorized).toBe(false);
    expect(JSON.stringify(a.preview)).not.toContain('C:\\');
    expect(Object.isFrozen(a.preview)).toBe(true);
    expect(verifyReadOnlySelectedRootPlanPreview(a.preview)).toBe(true);
    expect(
      verifyReadOnlySelectedRootPlanPreview({
        ...a.preview,
        executionAuthorized: true,
      }),
    ).toBe(false);
    expect(
      verifyReadOnlySelectedRootPlanPreview({
        ...a.preview,
        totalBytes: 999999,
      }),
    ).toBe(false);
  });

  it('refuses a mismatched root ref and any absolute or traversal-like target', () => {
    const initial = valid();
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        selectedRootRef: 'host:folder:' + 'b'.repeat(64),
      }).ok,
    ).toBe(false);
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        observation: {
          ...initial.observation,
          directories: [{ ...initial.observation.directories[0]!, relativePath: '../outside' }],
        },
      }).ok,
    ).toBe(false);
  });

  it('fails closed on stale scope evidence, expired reference and incomplete coverage', () => {
    const initial = valid();
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        nowUnixMs: NOW + 90_000,
      }).ok,
    ).toBe(false);
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        observation: { ...initial.observation, observedAt: new Date(NOW - 61_000).toISOString() },
      }).ok,
    ).toBe(false);
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        observation: {
          ...initial.observation,
          directories: [{ ...initial.observation.directories[0]!, inaccessibleCount: 1 }],
        },
      }).ok,
    ).toBe(false);
  });

  it('does not accept forged permission-like or remote observations as plan evidence', () => {
    const initial = valid();
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        observation: {
          ...initial.observation,
          executionAuthorized: true,
        } as unknown as typeof initial.observation,
      }).ok,
    ).toBe(false);
    expect(
      createReadOnlySelectedRootPlanPreview({
        ...initial,
        observation: {
          ...initial.observation,
          source: 'REMOTE_MODEL',
        } as unknown as typeof initial.observation,
      }).ok,
    ).toBe(false);
  });
});
