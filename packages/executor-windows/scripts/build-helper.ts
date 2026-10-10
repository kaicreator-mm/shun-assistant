// Builds the one-shot privileged helper into a single bundled .mjs.
//
// Why a bundle: the helper's identity is PINNED infrastructure (L2 §4.6.1) —
// a single file is content-hashable, so the authority pin is a plain sha256
// and substitution is detectable by construction. The bundle contains the
// workspace contracts sources verbatim: one canonicalization/validation
// implementation on both sides of the privilege boundary (§8.2.1), unlike the
// U-06 demo which deliberately duplicated it across the boundary.
//
// The trusted authority store location is baked in at build time (never
// argv/env — an attacker-run launcher controls both). Override for tests via
// SHUN_EXECUTOR_BUILD_AUTHORITY_DIR; production default is
// <USERPROFILE>\.shun\authority. Changing the location changes the bundle
// hash → the helper must be re-pinned → an explicit authority event.

import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { sha256File } from '../src/trusted-store.ts';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const outfile = join(packageRoot, 'dist', 'executor-helper.mjs');
mkdirSync(dirname(outfile), { recursive: true });

const authorityDir = process.env.SHUN_EXECUTOR_BUILD_AUTHORITY_DIR ?? '';

await build({
  entryPoints: [join(packageRoot, 'src', 'helper', 'executor-helper.ts')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile,
  sourcemap: false,
  minify: false,
  define: {
    SHUN_EXECUTOR_AUTHORITY_DIR: JSON.stringify(authorityDir),
  },
  banner: {
    // `import.meta.url` is preserved by esbuild; nothing else needed. The
    // helper resolves trusted inputs from the define above only.
    js: '// shun executor-windows one-shot helper — PINNED BUILD; do not edit by hand',
  },
});

process.stdout.write(
  `helper bundle: ${outfile}\nsha256: ${sha256File(outfile)}\nauthorityDir: '${authorityDir || '<default>~/.shun/authority'}'\n`,
);
