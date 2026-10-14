// Refill the deletable cache fixture in a sandbox workspace (after a
// successful cleanup there is genuinely nothing eligible left, and the
// vertical refuse-with-GROWTH_NOT_ATTRIBUTED is the correct behavior).
import { mkdir, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { readJson, ev } from './u05-lib.mjs';

const sandbox = process.argv[2];
const env = await readJson(path.join(sandbox, 'env.json'));
const cacheDir = path.join(env.SHUN_REAL_STORAGE_ROOT, 'cache');
await mkdir(cacheDir, { recursive: true });
let n = 0;
for (let i = 0; i < 5; i++) {
  await writeFile(path.join(cacheDir, `blob-${i}.tmp`), 'x'.repeat(4096 + i * 512), 'utf8');
  n++;
}
await ev('fixture.refill', 'OK', { sandbox, files: n });
console.log(JSON.stringify({ ok: true, files: n }));
