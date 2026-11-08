import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoShunBackend } from '../src/demo/backend.ts';
import { createControlServer } from '../src/server.ts';
import type {
  FolderPlanPreviewStaging,
  FolderSelectionHostPort,
} from '../src/v03/folder-selection-host.ts';
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

// P1-SCOPE-01 repair: the POST /api/v03/guided/plan-preview HTTP boundary
// tests moved here from the out-of-set folder-selection-server.test.ts
// (restored to the WIP base) — this file is in the frozen #390 G2 write set.
describe('R04 U05-B2 plan-preview HTTP boundary (admitted write-set home)', () => {
  let close: (() => Promise<void>) | undefined;
  afterEach(async () => {
    if (close) await close();
    close = undefined;
  });

  function stagingServer(
    stageReadOnlyPlanPreview: ReturnType<typeof vi.fn>,
    onPlanPreviewStaged?: (staging: FolderPlanPreviewStaging) => void,
  ) {
    return createControlServer({
      backend: new DemoShunBackend(),
      host: '127.0.0.1',
      port: 0,
      onPlanPreviewStaged,
      v03Guided: {
        state: () => ({ currentStep: step }),
        decide: () => receipt,
      } as never,
      v03FolderSelection: {
        selectRoot: async () => ({ status: 'CANCELLED' as const }),
        validateSelectionAnswer: () => null,
        afterSelectionRecorded: () => receipt,
        observeCurrentSelectedFolder: async () => ({
          ok: false as const,
          code: 'FOLDER_NOT_SELECTED' as const,
        }),
        stageReadOnlyPlanPreview,
      } as never,
    });
  }

  it('POST accepts only an empty body, maps truthful staging statuses, and notifies the trusted issuance seam exactly once per STAGED outcome', async () => {
    const staged: FolderPlanPreviewStaging = {
      status: 'STAGED',
      actionPreviewRef: 'host:preview:' + 'b'.repeat(32),
      stepId: 'step-review-plan',
      expiresAtUnixMs: 1_800_000_120_000,
    };
    const stageReadOnlyPlanPreview = vi.fn((): FolderPlanPreviewStaging => staged);
    // The composition root registers the P1-LIVE-REFS hook: only a durable
    // Host STAGED outcome may mint the live review-step reference pair, and
    // the pair itself never enters the HTTP response (console-only).
    const onPlanPreviewStaged = vi.fn();
    const server = stagingServer(stageReadOnlyPlanPreview, onPlanPreviewStaged);
    const port = await server.start();
    close = () => server.close();
    const origin = 'http://127.0.0.1:' + port;

    // The read-only observation GET never stages anything and never fires
    // the issuance seam.
    const observed = await fetch(origin + '/api/v03/guided/folder-observation');
    expect(observed.status).toBe(409);
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(0);
    expect(onPlanPreviewStaged).toHaveBeenCalledTimes(0);

    const continued = await fetch(origin + '/api/v03/guided/plan-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(continued.status).toBe(200);
    expect(await continued.json()).toEqual(staged);
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(1);
    expect(onPlanPreviewStaged).toHaveBeenCalledTimes(1);
    expect(onPlanPreviewStaged).toHaveBeenCalledWith(staged);
  });

  it('refuses every non-empty body with zero Host staging and keeps STALE/UNKNOWN truthful without firing issuance', async () => {
    const stageReadOnlyPlanPreview = vi.fn(
      (): FolderPlanPreviewStaging => ({
        status: 'STAGED',
        actionPreviewRef: 'host:preview:' + 'c'.repeat(32),
        stepId: 'step-review-plan',
        expiresAtUnixMs: 1_800_000_120_000,
      }),
    );
    const onPlanPreviewStaged = vi.fn();
    const server = stagingServer(stageReadOnlyPlanPreview, onPlanPreviewStaged);
    const port = await server.start();
    close = () => server.close();
    const origin = 'http://127.0.0.1:' + port;

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
    // No caller input ever reached the Host staging capability or the
    // issuance seam.
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(0);
    expect(onPlanPreviewStaged).toHaveBeenCalledTimes(0);

    stageReadOnlyPlanPreview.mockReturnValueOnce({
      status: 'STALE',
      code: 'PLAN_PREVIEW_INSPECT_RECEIPT_STALE',
    } as FolderPlanPreviewStaging);
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
      status: 'UNKNOWN',
      code: 'PLAN_PREVIEW_DURABILITY_UNKNOWN',
    } as FolderPlanPreviewStaging);
    const unknown = await fetch(origin + '/api/v03/guided/plan-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(unknown.status).toBe(503);
    expect(stageReadOnlyPlanPreview).toHaveBeenCalledTimes(2);
    // Non-STAGED outcomes never mint references.
    expect(onPlanPreviewStaged).toHaveBeenCalledTimes(0);
  });
});
