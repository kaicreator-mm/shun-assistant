import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoShunBackend } from '../src/demo/backend.ts';
import { createControlServer } from '../src/server.ts';

const step = {
  stepId: 'step-select-root', taskId: 'task-r04', journeyId: 'journey-r04',
  caseRef: { snapshotId: 'case-r04', digest: 'd'.repeat(64) },
  templateRef: { digest: 'e'.repeat(64), artifactId: 'shun.guided.select-root' },
};
const recorded = {
  status: 'RECORDED' as const, humanGrantIssued: false as const,
  effectSent: false as const, history: [],
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
      ok: false as const, code: 'FOLDER_NOT_SELECTED' as const,
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
      } as never,
    });
    const port = await server.start();
    close = () => server.close();
    const origin = 'http://127.0.0.1:' + port;

    const picked = await fetch(origin + '/api/v03/guided/select-root', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    expect(picked.status).toBe(200);
    expect(await picked.json()).toEqual({ status: 'CANCELLED' });
    expect(selectRoot).toHaveBeenCalledTimes(1);

    const injectedPath = await fetch(origin + '/api/v03/guided/select-root', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: 'C:\\\\private' }),
    });
    expect(injectedPath.status).toBe(422);
    expect(await injectedPath.json()).toMatchObject({
      status: 'REFUSED', code: 'FOLDER_PICKER_ACCEPTS_NO_CALLER_INPUT',
    });
    expect(selectRoot).toHaveBeenCalledTimes(1);

    const observation = await fetch(origin + '/api/v03/guided/folder-observation');
    expect(observation.status).toBe(409);
    expect(await observation.json()).toEqual({
      ok: false, code: 'FOLDER_NOT_SELECTED',
    });
    expect(observeCurrentSelectedFolder).toHaveBeenCalledTimes(1);
  });
});
