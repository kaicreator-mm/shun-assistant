import { describe, expect, it, vi } from 'vitest';
import {
  createComputerFolderObservationAdapter,
  HOST_FOLDER_OBSERVATION_SCHEMA,
} from '../../../../packages/domain-computer/src/computer/folder-observation.ts';

function hostObservation(overrides: Record<string, unknown> = {}) {
  return {
    schema: HOST_FOLDER_OBSERVATION_SCHEMA,
    status: 'OBSERVED_ONLY',
    rootRef: 'selected-root-01',
    scopeRevision: 'scope-revision-07',
    observedAt: '2026-10-30T08:00:00.000Z',
    totalBytes: 1_500,
    directories: [
      {
        relativePath: 'Pictures',
        bytes: 1_000,
        files: 12,
        lastModifiedMs: 1_760_000_000_000.5,
        inaccessibleCount: 0,
      },
      {
        relativePath: 'Documents',
        bytes: 400,
        files: 4,
        lastModifiedMs: 1_760_000_000_000,
        inaccessibleCount: 2,
      },
    ],
    rootFiles: { count: 3, bytes: 100 },
    ...overrides,
  };
}

describe('T02 selected-folder read-only observation adapter', () => {
  it('returns bounded relative metadata only from the Host-selected root', async () => {
    const observeCurrentSelectedFolder = vi.fn(async () => hostObservation());
    const adapter = createComputerFolderObservationAdapter({ observeCurrentSelectedFolder });
    const result = await adapter.observeCurrentSelectedFolder();

    expect(observeCurrentSelectedFolder).toHaveBeenCalledTimes(1);
    expect(observeCurrentSelectedFolder).toHaveBeenCalledWith();
    expect(result).toMatchObject({
      ok: true,
      observation: {
        status: 'OBSERVED_ONLY',
        source: 'TRUSTED_HOST_PORT',
        rootRef: 'selected-root-01',
        scopeRevision: 'scope-revision-07',
        totalBytes: 1_500,
        directories: [
          { relativePath: 'Documents', bytes: 400, files: 4, inaccessibleCount: 2 },
          { relativePath: 'Pictures', bytes: 1_000, files: 12 },
        ],
        rootFiles: { count: 3, bytes: 100 },
        localOnly: true,
        externalDisclosures: [],
        executionAuthorized: false,
        limitation: 'METADATA_ONLY_NO_CONTENT_OR_CAUSE',
      },
    });
    expect(Object.isFrozen(result)).toBe(true);
    if (result.ok) {
      expect(Object.isFrozen(result.observation)).toBe(true);
      expect(Object.isFrozen(result.observation.directories)).toBe(true);
      expect(JSON.stringify(result)).not.toMatch(/[A-Za-z]:\\|\\\\[^\\]/);
      expect(JSON.stringify(result)).not.toContain('file contents');
    }
  });

  it('does not accept a caller-provided path, root, scope or callback', async () => {
    const observeCurrentSelectedFolder = vi.fn(async () => hostObservation());
    const adapter = createComputerFolderObservationAdapter({ observeCurrentSelectedFolder });
    await adapter.observeCurrentSelectedFolder();
    expect(observeCurrentSelectedFolder).toHaveBeenCalledTimes(1);
    expect(observeCurrentSelectedFolder).toHaveBeenCalledWith();
    expect('selectRoot' in adapter).toBe(false);
    expect('setRoot' in adapter).toBe(false);
  });

  it('distinguishes no selected folder and unavailable Host from malformed evidence', async () => {
    const notSelected = createComputerFolderObservationAdapter({
      observeCurrentSelectedFolder: async () => ({
        schema: HOST_FOLDER_OBSERVATION_SCHEMA,
        status: 'NOT_SELECTED',
      }),
    });
    await expect(notSelected.observeCurrentSelectedFolder()).resolves.toEqual({
      ok: false,
      code: 'FOLDER_NOT_SELECTED',
    });

    const unavailable = createComputerFolderObservationAdapter({
      observeCurrentSelectedFolder: async () => {
        throw new Error('private path detail');
      },
    });
    await expect(unavailable.observeCurrentSelectedFolder()).resolves.toEqual({
      ok: false,
      code: 'FOLDER_OBSERVATION_UNAVAILABLE',
    });
  });

  it('rejects absolute paths, traversal, drive paths and extra disclosure fields', async () => {
    for (const relativePath of [
      'C:/Users/private',
      '/Users/private',
      '../private',
      'Pictures/../../private',
      'Pictures/Archive',
      '\\\\server\\share',
      'Pictures\\private',
    ]) {
      const adapter = createComputerFolderObservationAdapter({
        observeCurrentSelectedFolder: async () =>
          hostObservation({
            directories: [
              {
                relativePath,
                bytes: 1_500,
                files: 1,
                lastModifiedMs: 1_760_000_000_000,
                inaccessibleCount: 0,
              },
            ],
            rootFiles: { count: 0, bytes: 0 },
          }),
      });
      await expect(adapter.observeCurrentSelectedFolder()).resolves.toEqual({
        ok: false,
        code: 'FOLDER_OBSERVATION_INVALID',
      });
    }

    const extra = createComputerFolderObservationAdapter({
      observeCurrentSelectedFolder: async () => ({
        ...hostObservation(),
        fileContents: ['PRIVATE_FILE_CONTENT_SENTINEL'],
      }),
    });
    await expect(extra.observeCurrentSelectedFolder()).resolves.toEqual({
      ok: false,
      code: 'FOLDER_OBSERVATION_INVALID',
    });
  });

  it('accepts filesystem fractional mtime values without weakening byte/count integer checks', async () => {
    const adapter = createComputerFolderObservationAdapter({
      observeCurrentSelectedFolder: async () => hostObservation(),
    });
    const result = await adapter.observeCurrentSelectedFolder();
    expect(result).toMatchObject({
      ok: true,
      observation: {
        directories: [
          { relativePath: 'Documents', lastModifiedMs: 1_760_000_000_000 },
          { relativePath: 'Pictures', lastModifiedMs: 1_760_000_000_000.5 },
        ],
      },
    });
  });

  it('rejects inconsistent totals, duplicate names and unbounded reports', async () => {
    const cases = [
      hostObservation({ totalBytes: 1_499 }),
      hostObservation({
        directories: [hostObservation().directories[0], hostObservation().directories[0]],
      }),
      hostObservation({
        directories: Array.from({ length: 257 }, (_, i) => ({
          relativePath: `dir-${i}`,
          bytes: 0,
          files: 0,
          lastModifiedMs: 0,
          inaccessibleCount: 0,
        })),
      }),
    ];
    for (const value of cases) {
      const adapter = createComputerFolderObservationAdapter({
        observeCurrentSelectedFolder: async () => value,
      });
      await expect(adapter.observeCurrentSelectedFolder()).resolves.toEqual({
        ok: false,
        code: 'FOLDER_OBSERVATION_INVALID',
      });
    }
  });

  it('rejects proxy-backed directory arrays without invoking their iterator', async () => {
    let iteratorCalled = false;
    const raw = hostObservation({
      directories: new Proxy([], {
        get(target, property, receiver) {
          if (property === Symbol.iterator) iteratorCalled = true;
          return Reflect.get(target, property, receiver);
        },
      }),
      totalBytes: 100,
      rootFiles: { count: 1, bytes: 100 },
    });
    const adapter = createComputerFolderObservationAdapter({
      observeCurrentSelectedFolder: async () => raw,
    });
    await expect(adapter.observeCurrentSelectedFolder()).resolves.toEqual({
      ok: false,
      code: 'FOLDER_OBSERVATION_INVALID',
    });
    expect(iteratorCalled).toBe(false);
  });

  it('snapshots the trusted Host method and refuses hostile configuration getters', async () => {
    const first = vi.fn(async () => hostObservation());
    const host: { observeCurrentSelectedFolder: () => Promise<unknown> } = {
      observeCurrentSelectedFolder: first,
    };
    const adapter = createComputerFolderObservationAdapter(host);
    host.observeCurrentSelectedFolder = async () => {
      throw new Error('swapped host');
    };
    await adapter.observeCurrentSelectedFolder();
    expect(first).toHaveBeenCalledTimes(1);

    expect(() =>
      createComputerFolderObservationAdapter({
        get observeCurrentSelectedFolder(): never {
          throw new Error('private host detail');
        },
      } as never),
    ).toThrow('COMPUTER_FOLDER_HOST_CONFIGURATION_REFUSED');
  });
});
