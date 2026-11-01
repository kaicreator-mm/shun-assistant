import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SqliteKernelDocStore } from '../../../../packages/domain-host/src/state/kernel-doc-store.ts';

describe('R02-E public selected K durable doc CAS', () => {
  it('honors actual v0.10.3 create/cas and survives process re-open', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-k-doc-'));
    const file = join(dir, 'k.sqlite');
    try {
      let store = new SqliteKernelDocStore(file);
      expect(await store.get('K/turn-1')).toBeNull();
      expect(await store.put('K/turn-1', { phase: 'started' }, { kind: 'create' })).toEqual({
        revision: 0,
      });
      await expect(
        store.put('K/turn-1', { phase: 'duplicate' }, { kind: 'create' }),
      ).rejects.toThrow('K_DOC_CAS');
      expect(
        await store.put('K/turn-1', { phase: 'terminal' }, { kind: 'cas', revision: 0 }),
      ).toEqual({ revision: 1 });
      await expect(store.put('K/turn-1', {}, { kind: 'cas', revision: 0 })).rejects.toThrow(
        'K_DOC_CAS',
      );
      store.close();
      store = new SqliteKernelDocStore(file);
      expect(await store.get('K/turn-1')).toEqual({ value: { phase: 'terminal' }, revision: 1 });
      await store.remove('K/turn-1', { kind: 'cas', revision: 1 });
      expect(await store.get('K/turn-1')).toBeNull();
      store.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
