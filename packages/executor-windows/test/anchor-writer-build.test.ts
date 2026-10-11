// R5 production artifact smoke: source typecheck is insufficient if the
// one-shot writer cannot actually bundle with its trust root/key fixed at
// build time.
import { join } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';

describe('C06 R5 anchor-writer production bundle', () => {
  it('bundles as one ESM artifact with root/key compile-time constants', async () => {
    const anchorRoot = 'C:\\ProgramData\\Shun\\authority';
    const keyFile = `${anchorRoot}\\grant-hmac.key`;
    const result = await build({
      entryPoints: [join(import.meta.dirname, '..', 'src', 'authority-writer', 'entry.ts')],
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node24',
      write: false,
      define: {
        SHUN_ANCHOR_WRITER_ROOT: JSON.stringify(anchorRoot),
        SHUN_ANCHOR_WRITER_HMAC_KEY_FILE: JSON.stringify(keyFile),
      },
    });
    expect(result.outputFiles).toHaveLength(1);
    const js = result.outputFiles[0]?.text ?? '';
    expect(js).toContain('ProgramData');
    expect(js).toContain('grant-hmac.key');
    expect(js).not.toContain('process.env.SHUN_ANCHOR_WRITER');
  });
});
