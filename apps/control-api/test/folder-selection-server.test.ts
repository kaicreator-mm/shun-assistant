import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoShunBackend } from '../src/demo/backend.ts';
import { createControlServer } from '../src/server.ts';
import type { FolderPlanPreviewStaging } from '../src/v03/folder-selection-host.ts';

const step = {
  stepId: 'step-select-root',
  taskId: 'task-r04',
  journeyId: 'journey-r04',
  caseRef: { snapshotId: 'case-r04', digest: 'd'.repeat(64) },
  templateRef: { digest: 'e'.repeat(64), artifactId: 'shun.guided.select-root' },
};
const recorded = {
  status: 'RECORDED' as const,
  humanGrantIssued: false as const,
  effectSent: false as const,
  history: [],
};

describe('R04 U05-A folder selection HTTP boundary', () => {
  let close: (() => Promise<void>) | undefined;
  afterEach(async () => {
    if (close) await close();
    close = undefined;
  });

  it('accepts only an empty picker request and keeps observation as a truthful 409 when no root exists', async () => {
    const selectRoot = vi.fn(async () => ({ status: 'CANCELLED' as const }));
    const observeCurrentSelectedFolder = vi.fn(async () => ({
      ok: false as const,
      code: 'FOLDER_NOT_SELECTED' as const,
    }));
    const stageReadOnlyPlanPreview = vi.fn(() => ({
      status: 'STAGED' as const,
      actionPreviewRef: 'host:preview:' + 'a'.repeat(32),
      stepId: 'step-review-plan',
      expiresAtUnixMs: 1_800_000_120_000,
    }));
    const server = createControlServer({
      backend: new DemoShunBackend(),
      host: '127.0.0.1',
      port: 0,
      v03Guided: {
        state: () => ({ currentStep: step }),
        decide: () => recorded,
      } as never,
      v03FolderSelection: {
        selectRoot,
        validateSelectionAnswer: () => null,
        afterSelectionRecorded: () => recorded,
        observeCurrentSelectedFolder,
        stageReadOnlyPlanPreview,
      } as never,
    });
    const port = await server.start();
    close = () => server.close();
    const origin = 'http://127.0.0.1:' + port;

    const picked = await fetch(origin + '/api/v03/guided/select-root', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(picked.status).toBe(200);
    expect(await picked.json()).toEqual({ status: 'CANCELLED' });
    expect(selectRoot).toHaveBeenCalledTimes(1);

    const injectedPath = await fetch(origin + '/api/v03/guided/select-root', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: 'C:\\\\private' }),
    });
    expect(injectedPath.status).toBe(422);
    expect(await injectedPath.json()).toMatchObject({
      status: 'REFUSED',
      code: 'FOLDER_PICKER_ACCEPTS_NO_CALLER_INPUT',
    });
    expect(selectRoot).toHaveBeenCalledTimes(1);

    const observation = await fetch(origin + '/api/v03/guided/folder-observation');
    expect(observation.status).toBe(409);
    expect(await observation.json()).toEqual({
      ok: false,
      code: 'FOLDER_NOT_SELECTED',
    });
    expect(observeCurrentSelectedFolder).toHaveBeenCalledTimes(1);
    // The observation GET never stages anything.
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(0);
  });

  it('P1-02: POST /api/v03/guided/plan-preview accepts only an empty body and maps truthful staging statuses', async () => {
    const staged = {
      status: 'STAGED' as const,
      actionPreviewRef: 'host:preview:' + 'b'.repeat(32),
      stepId: 'step-review-plan',
      expiresAtUnixMs: 1_800_000_120_000,
    };
    const stageReadOnlyPlanPreview = vi.fn((): FolderPlanPreviewStaging => staged);
    const server = createControlServer({
      backend: new DemoShunBackend(),
      host: '127.0.0.1',
      port: 0,
      v03Guided: {
        state: () => ({ currentStep: step }),
        decide: () => recorded,
      } as never,
      v03FolderSelection: {
        selectRoot: async () => ({ status: 'CANCELLED' as const }),
        validateSelectionAnswer: () => null,
        afterSelectionRecorded: () => recorded,
        observeCurrentSelectedFolder: async () => ({
          ok: false as const,
          code: 'FOLDER_NOT_SELECTED' as const,
        }),
        stageReadOnlyPlanPreview,
      } as never,
    });
    const port = await server.start();
    close = () => server.close();
    const origin = 'http://127.0.0.1:' + port;

    const continued = await fetch(origin + '/api/v03/guided/plan-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(continued.status).toBe(200);
    expect(await continued.json()).toEqual(staged);
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(1);

    for (const body of [
      JSON.stringify({ actionPreviewRef: 'host:preview:forged' }),
      JSON.stringify({ path: 'C:\\\\private' }),
      '[]',
    ]) {
      const injected = await fetch(origin + '/api/v03/guided/plan-preview', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
      });
      expect(injected.status).toBe(422);
      expect(await injected.json()).toMatchObject({
        status: 'REFUSED',
        code: 'PLAN_PREVIEW_ACCEPTS_NO_CALLER_INPUT',
      });
    }
    // No caller input ever reached the Host staging capability.
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(1);

    // The one-shot staging outcome maps truthfully: STALE 409 / UNKNOWN 503.
    stageReadOnlyPlanPreview.mockReturnValueOnce({
      status: 'STALE' as const,
      code: 'PLAN_PREVIEW_INSPECT_RECEIPT_STALE',
    });
    const stale = await fetch(origin + '/api/v03/guided/plan-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(stale.status).toBe(409);
    expect(await stale.json()).toEqual({
      status: 'STALE',
      code: 'PLAN_PREVIEW_INSPECT_RECEIPT_STALE',
    });
    stageReadOnlyPlanPreview.mockReturnValueOnce({
      status: 'UNKNOWN' as const,
      code: 'PLAN_PREVIEW_DURABILITY_UNKNOWN',
    });
    const unknown = await fetch(origin + '/api/v03/guided/plan-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(unknown.status).toBe(503);
  });
});
