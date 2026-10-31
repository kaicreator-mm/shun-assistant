import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ts=join(root,'packages/vertical-support/node_modules/typescript/bin/tsc');
const folders=['r02-a-build','r02-b-guided','r02-c1-gateway','r02-c2-provenance',
  'r02-d2-gate','r02-e-production'];
if(!existsSync(ts)) {
  console.error('[r02-typecheck] TSC_MISSING');
  process.exit(1);
}
for(const name of folders) {
  const path=join(root,'tests/integration/v03',name,'tsconfig.json');
  if(!existsSync(path)) {
    console.error('[r02-typecheck] CONFIG_MISSING '+name);
    process.exit(1);
  }
  const run=spawnSync(process.execPath,[ts,'--project',path,'--noEmit'],{
    cwd:root,stdio:'inherit',env:process.env,
  });
  if(run.error || run.status!==0){
    console.error('[r02-typecheck] FAIL '+name);
    process.exit(run.status && run.status>0 ? run.status : 1);
  }
}
console.log('[r02-typecheck] PASS '+folders.length);
