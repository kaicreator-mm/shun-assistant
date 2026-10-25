import { describe, expect, it } from 'vitest';
import { previewScopedFileOperation } from '../src/preview.ts';

const root = 'C:\\Approved\\Jobs';

describe('T07 F01 local-only typed preview, never an executable capability', () => {
  it('produces stable preview for bounded search and duplicate report without OS observation', () => {
    const search = previewScopedFileOperation({
      taskId: 'task-1',
      scopeRoot: root,
      op: 'file.search',
      query: '*.txt',
    });
    expect(search.ok).toBe(true);
    if (!search.ok) return;
    expect(search.preview).toMatchObject({
      op: 'file.search',
      status: 'PREVIEW_ONLY',
      executionAuthorized: false,
      filesystemObserved: false,
      query: '*.txt',
    });
    expect(search.preview.intentSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(
      previewScopedFileOperation({
        taskId: 'task-1',
        scopeRoot: root,
        op: 'file.search',
        query: '*.txt',
      }),
    ).toEqual(search);
    expect(
      previewScopedFileOperation({
        taskId: 'task-1',
        scopeRoot: root,
        op: 'file.duplicates.report',
      }),
    ).toMatchObject({
      ok: true,
      preview: { op: 'file.duplicates.report', executionAuthorized: false },
    });
  });

  it('plans copy, move and rename without moving a byte or asserting overwrite safety', () => {
    for (const op of ['file.copy', 'file.move'] as const) {
      expect(
        previewScopedFileOperation({
          taskId: 'task-1',
          scopeRoot: root,
          op,
          sourcePath: 'C:\\Approved\\Jobs\\source.txt',
          destinationPath: 'C:\\Approved\\Jobs\\subdir\\destination.txt',
        }),
      ).toMatchObject({
        ok: true,
        preview: {
          op,
          destinationPath: 'C:\\Approved\\Jobs\\subdir\\destination.txt',
          executionAuthorized: false,
          filesystemObserved: false,
        },
      });
    }
    expect(
      previewScopedFileOperation({
        taskId: 'task-1',
        scopeRoot: root,
        op: 'file.rename',
        sourcePath: 'C:\\Approved\\Jobs\\source.txt',
        newName: 'renamed.txt',
      }),
    ).toMatchObject({
      ok: true,
      preview: {
        destinationPath: 'C:\\Approved\\Jobs\\renamed.txt',
        status: 'PREVIEW_ONLY',
      },
    });
  });

  it('refuses ambiguous drive, UNC, ADS, DOS device, traversal, sibling scope and self-copy', () => {
    const bad = [
      '\\\\remote\\share\\approved\\source.txt',
      'C:\\Approved\\Jobs\\..\\outside.txt',
      'C:\\Approved\\JobsSibling\\secret.txt',
      'C:\\Approved\\Jobs\\photo.txt:evil-stream',
      'C:\\Approved\\Jobs\\CON.txt',
      'C:\\Approved\\Jobs\\trailing.\\evil.txt',
      'D:\\Approved\\Jobs\\different-volume.txt',
      'C:Approved\\Jobs\\relative.txt',
    ];
    for (const sourcePath of bad) {
      expect(
        previewScopedFileOperation({
          taskId: 'task-1',
          scopeRoot: root,
          op: 'file.copy',
          sourcePath,
          destinationPath: 'C:\\Approved\\Jobs\\safe.txt',
        }),
      ).toEqual({ ok: false, code: 'FILE_PREVIEW_REFUSED' });
    }
    for (const destinationPath of [
      'C:\\Approved\\Jobs\\same.txt',
      'C:\\Approved\\Jobs\\same.txt\\child.txt',
      'C:\\other\\escape.txt',
    ]) {
      expect(
        previewScopedFileOperation({
          taskId: 'task-1',
          scopeRoot: root,
          op: 'file.move',
          sourcePath: 'C:\\Approved\\Jobs\\same.txt',
          destinationPath,
        }),
      ).toMatchObject({ ok: false, code: 'FILE_PREVIEW_REFUSED' });
    }
  });

  it('refuses unexpected privileges, shell, dynamic JS, unsupported operations and callback getters', () => {
    const base = { taskId: 'task-1', scopeRoot: root, op: 'file.search', query: '*.txt' };
    for (const extra of ['command', 'overwrite', 'provider', 'executeScopedSearch']) {
      expect(previewScopedFileOperation({ ...base, [extra]: true })).toEqual({
        ok: false,
        code: 'FILE_PREVIEW_REFUSED',
      });
    }
    expect(previewScopedFileOperation({ ...base, op: 'shell.exec' })).toMatchObject({
      ok: false,
    });
    expect(previewScopedFileOperation({ ...base, query: '../secret' })).toMatchObject({
      ok: false,
    });
    expect(
      previewScopedFileOperation({
        ...base,
        get scopeRoot() {
          throw new Error('MALICIOUS_GETTER');
        },
      }),
    ).toEqual({ ok: false, code: 'FILE_PREVIEW_REFUSED' });
  });

  it('does not suggest that overwrite safety was checked by a lexical preview', () => {
    const result = previewScopedFileOperation({
      taskId: 'task-1',
      scopeRoot: root,
      op: 'file.copy',
      sourcePath: 'C:\\Approved\\Jobs\\source.txt',
      destinationPath: 'C:\\Approved\\Jobs\\dest.txt',
    });
    expect(result).toMatchObject({
      ok: true,
      preview: {
        status: 'PREVIEW_ONLY',
        filesystemObserved: false,
        executionAuthorized: false,
        destinationOverwriteStatus: 'UNKNOWN_NOT_CHECKED',
      },
    });
    if (!result.ok) return;
    expect('overwrittenExistingFile' in result.preview).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.preview)).toBe(true);
    expect(Object.isFrozen(result.preview.pendingTrustedChecks)).toBe(true);
    expect(() => {
      (result.preview as { executionAuthorized: boolean }).executionAuthorized = true;
    }).toThrow();
    expect(
      previewScopedFileOperation({
        taskId: 'task-1',
        scopeRoot: root,
        op: 'file.copy',
        sourcePath: 'C:\\Approved\\Jobs\\source.txt',
        destinationPath: 'C:\\Approved\\Jobs\\dest.txt',
      }),
    ).toEqual(result);
  });

  it('rejects task display injection, Unicode device aliases and bidi filename/query', () => {
    const base = { taskId: 'task-1', scopeRoot: root, op: 'file.search', query: '*.txt' };
    for (const taskId of ['task\u202Eevil', 'task\nbad', 'task\u007Fbad', 'task bad']) {
      expect(previewScopedFileOperation({ ...base, taskId })).toEqual({
        ok: false,
        code: 'FILE_PREVIEW_REFUSED',
      });
    }
    expect(previewScopedFileOperation({ ...base, query: 'r\u202Etl.txt' })).toMatchObject({
      ok: false,
    });
    for (const badFileName of ['COM¹.txt', 'LPT².txt', 'COM³.log', 'rtl\u202eevil.txt']) {
      expect(
        previewScopedFileOperation({
          taskId: 'task-1',
          scopeRoot: root,
          op: 'file.rename',
          sourcePath: 'C:\\Approved\\Jobs\\source.txt',
          newName: badFileName,
        }),
      ).toEqual({ ok: false, code: 'FILE_PREVIEW_REFUSED' });
    }
  });
});
