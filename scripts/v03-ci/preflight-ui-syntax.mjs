/**
 * Offline, zero-side-effect syntax gate for the tracked JS/TS sources.
 *
 * This is deliberately separate from lint, typecheck and Vitest: a malformed
 * source file must be diagnosed before any expensive CI qualification run.
 * Run after pnpm install and BEFORE pushing a source branch to Woodpecker.
 * Requires the workspace TypeScript devDependency (no remote service).
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const requireFromUi = createRequire(resolve(root, 'apps/control-ui/package.json'));
let ts;
try {
  ts = requireFromUi('typescript');
} catch {
  console.error('[syntax-preflight] TypeScript dependency unavailable; run pnpm install first.');
  process.exit(1);
}
const tracked = execFileSync('git', [
  'ls-files', '-z', '--', '*.js', '*.mjs', '*.cjs', '*.jsx', '*.ts', '*.tsx',
], {cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024})
  .split('\0').filter(Boolean);
if (tracked.length === 0) {
  console.error('[syntax-preflight] No tracked JS/TS files; refusing empty gate.');
  process.exit(1);
}
const kinds = new Map([
  ['.ts',ts.ScriptKind.TS],['.tsx',ts.ScriptKind.TSX],
  ['.js',ts.ScriptKind.JS],['.jsx',ts.ScriptKind.JSX],
  ['.mjs',ts.ScriptKind.JS],['.cjs',ts.ScriptKind.JS],
]);
let errors = 0;
for (const file of tracked) {
  const source = readFileSync(resolve(root,file),'utf8');
  const syntax = ts.createSourceFile(file,source,ts.ScriptTarget.Latest,true,kinds.get(extname(file)));
  for (const diagnostic of syntax.parseDiagnostics) {
    const at = syntax.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
    console.error('[syntax-preflight] '+file+':'+(at.line+1)+':'+(at.character+1)+
      ' TS'+diagnostic.code+' '+
      ts.flattenDiagnosticMessageText(diagnostic.messageText,' '));
    errors++;
  }
}
// The shipped browser modules use real Node module parsing, too.
const browser = tracked.filter(file =>
  file.startsWith('apps/control-ui/public/v03/') &&
  (file.endsWith('.js') || file.endsWith('.mjs')));
for (const file of browser) {
  const result = spawnSync(process.execPath,['--check',resolve(root,file)],{
    cwd:root,encoding:'utf8',windowsHide:true
  });
  if (result.error || result.status !== 0) {
    console.error('[syntax-preflight] Node parser rejected '+file+'\n'+
      (result.stderr||result.error?.message||'Unknown parser failure'));
    errors++;
  }
}
if (errors) {
  console.error('[syntax-preflight] BLOCK: '+errors+' syntax diagnostic(s) across '+
    tracked.length+' tracked sources; CI qualification is forbidden.');
  process.exit(1);
}
console.log('[syntax-preflight] PASS: '+tracked.length+
  ' tracked JS/TS sources, '+browser.length+' Node browser-module checks; no side effects.');
