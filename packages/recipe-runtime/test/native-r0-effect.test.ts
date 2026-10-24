import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthorizedActionSchema } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { boundedLocalShape, executeConservativeNativeR0Search } from '../src/native-r0-effect.ts';

const bases: string[] = [];
afterEach(() => {
  for (const path of bases.splice(0)) rmSync(path, { recursive: true, force: true });
});

function approved() {
  const base = mkdtempSync(join(tmpdir(), 'shun-r0-native-verified-'));
  bases.push(base);
  const root = join(base, 'approved');
  mkdirSync(root);
  mkdirSync(join(root, 'nested'));
  writeFileSync(join(root, 'note.txt'), 'NEVER_EXPOSE_SECRET_CONTENT');
  writeFileSync(join(root, 'nested', 'second.txt'), 'NEVER_READ_SECOND_CONTENT');
  const action = AuthorizedActionSchema.parse({
    taskId: 'task-1',
    actionId: 'read-only-1',
    planHash: 'f'.repeat(64),
    policySnapshotRevision: 'p1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'real-private-grant-gate-required-upstream',
    action: {
      actionId: 'read-only-1',
      bindingRef: 'b1',
      op: 'file.search',
      parameters: { root, query: '*.txt' },
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [root], write: [] },
    },
  });
  return { base, root, action };
}

describe('T04 private Win32 native R0 receipt never claims independent post-state / Task PASS', () => {
  it.skipIf(process.platform !== 'win32')(
    'performs genuine native search but returns only UNCERTAIN without separate oracle',
    async () => {
      const { root, action } = approved();
      const receipt = await executeConservativeNativeR0Search(action);
      expect(receipt).toMatchObject({
        actionId: 'read-only-1',
        environmentId: 'local-windows-user',
        providerId: 'shun-win32-r0-native',
        terminal: 'UNCERTAIN',
        outputRefs: [],
        sideEffectEvidence: {
          sideEffectClass: 'R0',
          recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
          postStateVerified: false,
        },
      });
      expect(JSON.stringify(receipt)).not.toContain(root);
      expect(JSON.stringify(receipt)).not.toContain('NEVER_EXPOSE_SECRET_CONTENT');
      expect(JSON.stringify(receipt)).not.toContain('note.txt');
      expect(receipt).not.toHaveProperty('semanticVerified');
      expect(JSON.stringify(receipt)).not.toContain('COMPLETED_VERIFIED');
      expect(JSON.stringify(receipt)).not.toContain('postStateVerified":true');
      expect(receipt).not.toHaveProperty('taskPass');
    },
  );

  it.skipIf(process.platform !== 'win32')(
    'rejects a junction pointing outside the approved scope, leaking no paths or success',
    async () => {
      const { base, root, action } = approved();
      const outside = join(base, 'outside');
      mkdirSync(outside);
      writeFileSync(join(outside, 'secret.txt'), 'NEVER_ESCAPE_SCOPE');
      symlinkSync(outside, join(root, 'escape'), 'junction');
      await expect(executeConservativeNativeR0Search(action)).rejects.toThrow(
        /^R0_NATIVE_EFFECT_UNCERTAIN$/,
      );
    },
  );

  it('refuses a widened write scope and cannot run the Win32 native port on Linux', async () => {
    const { action } = approved();
    const widened = {
      ...action,
      action: {
        ...action.action,
        filesystemScope: { read: action.action.filesystemScope?.read ?? [], write: ['/outside'] },
      },
    };
    await expect(executeConservativeNativeR0Search(widened)).rejects.toThrow(
      /^R0_NATIVE_EFFECT_UNCERTAIN$/,
    );
    if (process.platform !== 'win32') {
      await expect(executeConservativeNativeR0Search(action)).rejects.toThrow(
        /^R0_NATIVE_EFFECT_UNCERTAIN$/,
      );
    }
  });
});

describe('T04 private bounded observation defensive path guards', () => {
  it('accepts only root-relative entries and rejects NUL, rooted or traversing names', () => {
    const valid = {
      kind: 'R0_LOCAL_FILE_SEARCH_OBSERVATION',
      paths: ['nested\\second.txt', 'note.txt'],
      inspectedEntries: 4,
      truncated: false,
      semanticVerified: false,
      cloudDisclosure: false,
    } as const;
    expect(boundedLocalShape(valid)).toBe(true);
    for (const path of ['\\rooted', 'nested\0bad', '../escape', '/absolute', '\\\\server\\share']) {
      expect(boundedLocalShape({ ...valid, paths: [path] })).toBe(false);
    }
  });
});
