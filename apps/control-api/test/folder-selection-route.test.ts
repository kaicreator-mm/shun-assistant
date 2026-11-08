import { describe, expect, it, vi } from 'vitest';
import type { FolderSelectionHostPort } from '../src/v03/folder-selection-host.ts';
import {
  createV03FolderSelectionRoute,
  type V03FolderSelectionRoutePort,
} from '../src/v03/folder-selection-route.ts';

const selected = {
  status: 'SELECTED' as const,
  selectionRef: 'host:folder:' + 'a'.repeat(64),
  displayName: 'Documents',
  expiresAtUnixMs: 1_800_000_060_000,
};
const step = {
  stepId: 'step-select-root',
  taskId: 'task-r04',
  journeyId: 'journey-r04',
  caseRef: { snapshotId: 'case-r04', digest: 'b'.repeat(64) },
  templateRef: { digest: 'c'.repeat(64), artifactId: 'shun.guided.select-root' },
};
const receipt = {
  status: 'RECORDED' as const,
  humanGrantIssued: false as const,
  effectSent: false as const,
  history: [],
};

describe('R04 U05-A folder selection route adapter', () => {
  it('forwards the no-input picker, decision validation, post-record stage, observation and the P1-02 plan-preview continuation', async () => {
    const staging = {
      status: 'STAGED' as const,
      actionPreviewRef: 'host:preview:' + 'b'.repeat(32),
      stepId: 'step-review-plan',
      expiresAtUnixMs: 1_800_000_120_000,
    };
    const host = {
      selectRoot: vi.fn(async () => selected),
      validateSelectionAnswer: vi.fn(() => null),
      afterSelectionRecorded: vi.fn(() => receipt),
      observeCurrentSelectedFolder: vi.fn(async () => ({
        ok: false as const,
        code: 'FOLDER_NOT_SELECTED' as const,
      })),
      stageReadOnlyPlanPreview: vi.fn(() => staging),
    };
    const route: V03FolderSelectionRoutePort = createV03FolderSelectionRoute(
      host as unknown as FolderSelectionHostPort,
    );
    expect(await route.selectRoot()).toEqual(selected);
    expect(route.validateSelectionAnswer({ answer: true }, step)).toBeNull();
    expect(route.afterSelectionRecorded({}, step, receipt)).toEqual(receipt);
    expect(await route.observeCurrentSelectedFolder()).toEqual({
      ok: false,
      code: 'FOLDER_NOT_SELECTED',
    });
    expect(route.stageReadOnlyPlanPreview()).toEqual(staging);
    expect(host.selectRoot).toHaveBeenCalledTimes(1);
    expect(host.validateSelectionAnswer).toHaveBeenCalledWith({ answer: true }, step);
    expect(host.afterSelectionRecorded).toHaveBeenCalledWith({}, step, receipt);
    expect(host.observeCurrentSelectedFolder).toHaveBeenCalledTimes(1);
    expect(host.stageReadOnlyPlanPreview).toHaveBeenCalledTimes(1);
  });

  it('fails closed when any Host capability is missing', () => {
    expect(() => createV03FolderSelectionRoute({} as FolderSelectionHostPort)).toThrow(
      'V03_FOLDER_SELECTION_HOST_UNAVAILABLE',
    );
    expect(() =>
      createV03FolderSelectionRoute({
        selectRoot: () => Promise.resolve({ status: 'CANCELLED' }),
      } as unknown as FolderSelectionHostPort),
    ).toThrow('V03_FOLDER_SELECTION_HOST_UNAVAILABLE');
  });
});
