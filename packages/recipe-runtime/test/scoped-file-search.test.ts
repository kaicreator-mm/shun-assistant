import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type AuthorizedAction, AuthorizedActionSchema } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { observeScopedFileSearch } from '../src/scoped-file-search.ts';

const cleanup: string[] = [];
afterEach(() => {
  for (const dir of cleanup.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(): { base: string; root: string } {
  const base = mkdtempSync(join(tmpdir(), 'shun-r0-search-'));
  cleanup.push(base);
  const root = join(base, 'approved');
  mkdirSync(root);
  mkdirSync(join(root, 'nested'));
  writeFileSync(join(root, 'note.txt'), 'not read or transmitted');
  writeFileSync(join(root, 'other.log'), 'not read');
  writeFileSync(join(root, 'nested', 'second.txt'), 'not read');
  return { base, root };
}

function authorized(root: string, query = '*.txt'): AuthorizedAction {
  return AuthorizedActionSchema.parse({
    taskId: 'task-1',
    actionId: 'r0-search',
    planHash: 'b'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'actual-issuer-required-upstream',
    action: {
      actionId: 'r0-search',
      bindingRef: 'binding-1',
      op: 'file.search',
      parameters: { root, query },
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [root], write: [] },
    },
  });
}

describe('T04 trusted R0 local filesystem observation (not grant issuer/receipt)', () => {
  it('returns only bounded root-relative matching names without content or cloud disclosure', () => {
    const { root } = fixture();
    const observation = observeScopedFileSearch(authorized(root));
    expect(observation).toMatchObject({
      kind: 'R0_LOCAL_FILE_SEARCH_OBSERVATION',
      inspectedEntries: 4,
      truncated: false,
      semanticVerified: false,
      cloudDisclosure: false,
    });
    expect(observation.paths).toEqual([join('nested', 'second.txt'), 'note.txt'].sort());
    expect(JSON.stringify(observation)).not.toContain('not read');
    expect(JSON.stringify(observation)).not.toContain(root);
  });

  it('refuses changed scope, unsafe query, privileged operation and UNC root', () => {
    const { root } = fixture();
    const good = authorized(root);
    expect(() =>
      observeScopedFileSearch({
        ...good,
        action: { ...good.action, filesystemScope: { read: [root], write: [root] } },
      }),
    ).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    expect(() => observeScopedFileSearch(authorized(root, '../../*'))).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
    expect(() =>
      observeScopedFileSearch({
        ...good,
        action: { ...good.action, requiredPrivilege: 'ELEVATED' },
      }),
    ).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    expect(() => observeScopedFileSearch(authorized('//server/share'))).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
  });

  it('refuses a link/junction at any visited child, never returns a partial result', () => {
    const { base, root } = fixture();
    const target = join(base, 'outside');
    mkdirSync(target);
    writeFileSync(join(target, 'secret.txt'), 'never disclose');
    try {
      symlinkSync(
        target,
        join(root, 'nested', 'escape'),
        process.platform === 'win32' ? 'junction' : 'dir',
      );
    } catch (err) {
      // A Windows runner without symlink privileges cannot prove this physical canary.
      if ((err as NodeJS.ErrnoException).code === 'EPERM') return;
      throw err;
    }
    expect(() => observeScopedFileSearch(authorized(root))).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
  });

  it('refuses alias root and excessively deep scans rather than reporting truncated success', () => {
    const { base, root } = fixture();
    let current = root;
    for (let i = 0; i < 9; i++) {
      current = join(current, `d${i}`);
      mkdirSync(current);
    }
    expect(() => observeScopedFileSearch(authorized(root))).toThrow(/^R0_FILE_SEARCH_REFUSED$/);
    try {
      symlinkSync(root, join(base, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EPERM') return;
      throw err;
    }
    expect(() => observeScopedFileSearch(authorized(join(base, 'alias')))).toThrow(
      /^R0_FILE_SEARCH_REFUSED$/,
    );
  });
});
