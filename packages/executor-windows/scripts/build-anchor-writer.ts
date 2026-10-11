// Build the one-shot ShunAnchorWriter into one pinned .mjs.
// A production writer has NO runtime-configurable trust root: both the
// protected anchor root and HMAC key path are compiled into the bundle.
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { sha256File } from '../src/trusted-store.ts';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const outfile = join(packageRoot, 'dist', 'anchor-writer.mjs');
mkdirSync(dirname(outfile), { recursive: true });

const anchorRoot =
  process.env.SHUN_ANCHOR_WRITER_BUILD_ROOT?.trim() || 'C:\\ProgramData\\Shun\\authority';
const keyFile =
  process.env.SHUN_ANCHOR_WRITER_BUILD_HMAC_KEY_FILE?.trim() ||
  join(anchorRoot, 'grant-hmac.key');

await build({
  entryPoints: [join(packageRoot, 'src', 'authority-writer', 'entry.ts')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile,
  sourcemap: false,
  minify: false,
  define: {
    SHUN_ANCHOR_WRITER_ROOT: JSON.stringify(anchorRoot),
    SHUN_ANCHOR_WRITER_HMAC_KEY_FILE: JSON.stringify(keyFile),
  },
  banner: {
    js: '// shun one-shot anchor writer — PINNED BUILD; trust root/key baked at build time',
  },
});

process.stdout.write(
  `anchor-writer: ${outfile}\nsha256: ${sha256File(outfile)}\nanchorRoot: ${anchorRoot}\nkeyFile: ${keyFile}\n`,
);
