import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('T04 native package contents are runtime-only', () => {
  it('never publishes the test-only native canary or Rust build source', () => {
    const result = spawnSync(
      process.platform === 'win32' ? 'npm.cmd' : 'npm',
      ['pack', '--dry-run', '--json', '--ignore-scripts'],
      {
        cwd: packageRoot,
        encoding: 'utf8',
        shell: process.platform === 'win32',
        timeout: 30_000,
      },
    );
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const pack = JSON.parse(result.stdout) as Array<{
      files: Array<{ path: string }>;
    }>;
    const entries = pack[0]?.files.map((file) => file.path);
    expect(entries).toBeDefined();
    expect(entries).toContain('src/index.ts');
    expect(entries).toContain('native/impl/shun_win32_impl.node');
    expect(entries).not.toContain('native/canary/shun_win32_canary.node');
    expect(entries?.some((path) => path.startsWith('native/canary/'))).toBe(false);
    expect(entries?.some((path) => path.endsWith('.rs') || path.endsWith('Cargo.lock'))).toBe(
      false,
    );
    expect(entries?.some((path) => path.startsWith('test/'))).toBe(false);
  }, 45_000);
});
