import { describe, expect, it } from 'vitest';
import { taskAction } from '../src/plans.ts';

describe('C-002 task input authorization scope', () => {
  it('binds declared source files into the task ActionPlan read scope', () => {
    const action = taskAction({
      actionId: 'b038-task',
      bindingId: 'binding-portable-node',
      executable: 'C:\\Shun\\jit\\node.exe',
      argv: ['-e', '/* archive fixture */'],
      readPaths: ['C:\\fixture\\expected.txt'],
      outputDir: 'C:\\fixture\\candidate\\B-038',
      timeoutMs: 30_000,
    });
    expect(action.filesystemScope).toEqual({
      read: ['C:\\Shun\\jit\\node.exe', 'C:\\fixture\\expected.txt'],
      write: ['C:\\fixture\\candidate\\B-038'],
    });
  });

  it('deduplicates the executable if it is also explicitly declared as a task input', () => {
    const executable = 'C:\\Shun\\jit\\node.exe';
    const action = taskAction({
      actionId: 'task',
      bindingId: 'binding',
      executable,
      argv: [],
      readPaths: [executable],
      outputDir: 'C:\\out',
      timeoutMs: 30_000,
    });
    expect(action.filesystemScope?.read).toEqual([executable]);
  });
});
