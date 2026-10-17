// T05 #106 native-addon child bootstrap and wire protocol.
//
// Production native activation NEVER dlopens inside the privileged loader
// process. Each activation spawns ONE short-lived Node child whose entire
// program is the fixed `NATIVE_CHILD_BOOTSTRAP_SOURCE` string below, passed
// via `node -e <source> <payload>` by the parent. The child:
//   1. parses ONE strictly-shaped JSON payload from argv (v==1, closed op
//      set, absolute paths, hex digests) — no other input channel exists,
//   2. re-hashes the pinned addon and every pinned dependency on disk and
//      refuses on any drift (defense in depth behind the parent's checks),
//   3. dlopens the addon into a FRESH module object — no require() of any
//      provider content, no eval, no fs writes, no network,
//   4. answers the ONE closed-world operation, prints exactly one
//      `SHUN_NATIVE_RESULT …` JSON line, and exits.
// Everything the child prints is DATA, never instructions: the parent
// re-validates the parsed response shape and caps every string.
//
// DLL-resolution confinement (Windows): libuv dlopens with
// LOAD_WITH_ALTERED_SEARCH_PATH, so dependent DLLs resolve starting from the
// loaded addon's own directory — the per-run staging directory that holds
// exactly the digest-verified closure. The child env has no PATH and the
// child cwd is the staging directory itself, so seeded sandbox files are
// outside the DLL search chain entirely.

export type NativeChildOperation =
  | Readonly<{ kind: 'ADDON_METADATA' }>
  | Readonly<{
      kind: 'IMAGE_METADATA' /** Seeded sandbox file name; never a path. */;
      operand: string;
    }>;

export interface NativeChildPayload {
  readonly v: 1;
  readonly op: 'ADDON_METADATA' | 'IMAGE_METADATA';
  readonly addon: { readonly path: string; readonly sha256: string };
  readonly deps: ReadonlyArray<{
    readonly name: string;
    readonly sha256: string;
    readonly path: string;
  }>;
  readonly operand?: { readonly path: string; readonly sha256: string; readonly maxBytes: number };
}

export type NativeChildResponse =
  | {
      readonly ok: true;
      readonly kind: 'ADDON_METADATA';
      readonly exportCount: number;
      readonly exports: readonly string[];
      readonly addonType: string;
      readonly childAbi: string;
      readonly childNode: string;
    }
  | {
      readonly ok: true;
      readonly kind: 'IMAGE_METADATA';
      readonly metadata: Readonly<Record<string, string | number | boolean>>;
      readonly childAbi: string;
      readonly childNode: string;
    }
  | {
      readonly ok: false;
      readonly code:
        | 'REQUEST_INVALID'
        | 'ADDON_DIGEST_MISMATCH'
        | 'DEPENDENCY_DIGEST_MISMATCH'
        | 'DLOPEN_FAILED'
        | 'ADDON_SURFACE_UNUSABLE'
        | 'OPERAND_UNREADABLE'
        | 'OPERAND_DIGEST_MISMATCH'
        | 'METADATA_FAILED'
        | 'CHILD_INTERNAL';
      readonly message?: string;
    };

export const NATIVE_CHILD_RESULT_PREFIX = 'SHUN_NATIVE_RESULT ';

const MAX_EXPORT_NAMES = 64;
const MAX_NAME_CHARS = 128;
const MAX_MESSAGE_CHARS = 200;
const MAX_METADATA_FIELDS = 32;

/**
 * The ENTIRE child program. Kept single-line and double-quote-free so the
 * argv survives Windows command-line quoting unchanged. This string is part
 * of the authorized invocation (the invocation-scoped grant binds it), so it
 * must only change with a security review of the child surface.
 */
export const NATIVE_CHILD_BOOTSTRAP_SOURCE = String.raw`
var R=require('path'),F=require('fs'),C=require('crypto');
var out=null;
function done(o){if(out)return;out=o;var l='SHUN_NATIVE_RESULT '+JSON.stringify(o);if(process.stdout.write(l+'\n')){process.exit(0);}process.stdout.once('drain',function(){process.exit(0);});}
function fail(c,m){done({ok:false,code:c,message:String(m==null?'':m).slice(0,200)});}
function hex(v){return typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);}
function sha(p){var b=F.readFileSync(p);return{buf:b,digest:C.createHash('sha256').update(b).digest('hex')};}
async function main(){
var p=JSON.parse(process.argv[1]);
if(!p||p.v!==1||!p.addon||!R.isAbsolute(p.addon.path)||!hex(p.addon.sha256)||(p.op!=='ADDON_METADATA'&&p.op!=='IMAGE_METADATA')){fail('REQUEST_INVALID');}
else{
var deps=Array.isArray(p.deps)?p.deps:[];
var dir=R.dirname(p.addon.path);
var depsOk=deps.length<=64&&deps.every(function(d){return !!d&&typeof d.name==='string'&&d.name.length<=128&&R.isAbsolute(d.path)&&hex(d.sha256)&&R.dirname(d.path)===dir;});
if(!depsOk){fail('REQUEST_INVALID');}
else{
var main=sha(p.addon.path);
if(main.digest!==p.addon.sha256){fail('ADDON_DIGEST_MISMATCH');}
else{
var depBad=false;
for(var i=0;i<deps.length;i+=1){if(sha(deps[i].path).digest!==deps[i].sha256){depBad=true;break;}}
if(depBad){fail('DEPENDENCY_DIGEST_MISMATCH');}
else{
var mod={exports:{}};
try{process.dlopen(mod,p.addon.path);}catch(e){fail('DLOPEN_FAILED',e&&e.message);}
if(!out){
var addon=mod.exports;
if(p.op==='ADDON_METADATA'){
var names=Object.getOwnPropertyNames(addon);
done({ok:true,kind:'ADDON_METADATA',exportCount:names.length,exports:names.slice(0,64).map(function(s){return String(s).slice(0,128);}),addonType:typeof addon,childAbi:process.versions.modules,childNode:process.version});
}else if(typeof addon.metadata!=='function'){fail('ADDON_SURFACE_UNUSABLE');}
else{
var op=p.operand;
if(!op||!R.isAbsolute(op.path)||!hex(op.sha256)||!(op.maxBytes>0&&op.maxBytes<=8388608)){fail('REQUEST_INVALID');}
else{
var st=null;
try{st=F.statSync(op.path);}catch(e){}
if(!st||!st.isFile()||st.size<1||st.size>op.maxBytes){fail('OPERAND_UNREADABLE');}
else{
var img=sha(op.path);
if(img.digest!==op.sha256){fail('OPERAND_DIGEST_MISMATCH');}
else{
try{
addon.metadata({debuglog:function(){},input:{buffer:img.buf,failOn:'warning',limitInputPixels:268402689,limitInputChannels:5,unlimited:false,autoOrient:false}},function(e,m){
if(out){return;}
if(e){fail('METADATA_FAILED',e&&e.message);return;}
var pick={};var n=0;
for(var k in m){if(n>=32){break;}var v=m[k];if(typeof v==='string'||typeof v==='number'||typeof v==='boolean'){pick[k]=typeof v==='string'?v.slice(0,128):v;n+=1;}}
done({ok:true,kind:'IMAGE_METADATA',metadata:pick,childAbi:process.versions.modules,childNode:process.version});
});
}catch(e){if(!out){fail('METADATA_FAILED',e&&e.message);}}
}}}}}}}}}}
main().catch(function(e){if(!out){fail('CHILD_INTERNAL',e&&e.message);}});
`
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => line.length > 0)
  .join('');

export type NativeChildRunReport =
  | {
      readonly ok: true;
      readonly report: Extract<NativeChildResponse, { ok: true }>;
    }
  | {
      readonly ok: false;
      /** Structured child refusal (child RAN and reported) or unparsable output. */
      readonly code: 'NATIVE_CHILD_REFUSED' | 'NATIVE_CHILD_NO_RESULT';
      readonly childCode?: string;
      readonly message?: string;
    };

/**
 * Parent-side validation of the child's single result line. The child output
 * is untrusted data: every field is re-type-checked and capped here, and a
 * missing/garbage line degrades to NATIVE_CHILD_NO_RESULT (raw stdout/stderr
 * remain available on the run outcome for evidence).
 */
export function parseNativeChildResult(stdout: string): NativeChildRunReport {
  const lines = stdout.split('\n');
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const rawLine = lines[index];
    if (rawLine === undefined) continue;
    const line = rawLine.trim();
    if (!line.startsWith(NATIVE_CHILD_RESULT_PREFIX)) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line.slice(NATIVE_CHILD_RESULT_PREFIX.length));
    } catch {
      return { ok: false, code: 'NATIVE_CHILD_NO_RESULT' };
    }
    if (!parsed || typeof parsed !== 'object') return { ok: false, code: 'NATIVE_CHILD_NO_RESULT' };
    const value = parsed as Record<string, unknown>;
    const childAbi = typeof value.childAbi === 'string' ? value.childAbi.slice(0, 16) : '';
    const childNode = typeof value.childNode === 'string' ? value.childNode.slice(0, 16) : '';
    if (value.ok === true) {
      if (value.kind === 'ADDON_METADATA') {
        const exports = Array.isArray(value.exports) ? value.exports : [];
        const names = exports
          .filter((name): name is string => typeof name === 'string')
          .slice(0, MAX_EXPORT_NAMES)
          .map((name) => name.slice(0, MAX_NAME_CHARS));
        if (typeof value.exportCount !== 'number')
          return { ok: false, code: 'NATIVE_CHILD_NO_RESULT' };
        return {
          ok: true,
          report: {
            ok: true,
            kind: 'ADDON_METADATA',
            exportCount: value.exportCount,
            exports: Object.freeze(names),
            addonType:
              typeof value.addonType === 'string' ? value.addonType.slice(0, 16) : 'unknown',
            childAbi,
            childNode,
          },
        };
      }
      if (value.kind === 'IMAGE_METADATA' && value.metadata && typeof value.metadata === 'object') {
        const metadata: Record<string, string | number | boolean> = {};
        let count = 0;
        for (const [key, field] of Object.entries(value.metadata as Record<string, unknown>)) {
          if (count >= MAX_METADATA_FIELDS) break;
          if (typeof field === 'string' && key.length <= MAX_NAME_CHARS) {
            metadata[key.slice(0, MAX_NAME_CHARS)] = field.slice(0, MAX_NAME_CHARS);
            count += 1;
          } else if (typeof field === 'number' || typeof field === 'boolean') {
            metadata[key.slice(0, MAX_NAME_CHARS)] = field;
            count += 1;
          }
        }
        return {
          ok: true,
          report: {
            ok: true,
            kind: 'IMAGE_METADATA',
            metadata: Object.freeze(metadata),
            childAbi,
            childNode,
          },
        };
      }
      return { ok: false, code: 'NATIVE_CHILD_NO_RESULT' };
    }
    if (value.ok === false) {
      const code = typeof value.code === 'string' ? value.code : 'CHILD_INTERNAL';
      const message =
        typeof value.message === 'string' ? value.message.slice(0, MAX_MESSAGE_CHARS) : undefined;
      return { ok: false, code: 'NATIVE_CHILD_REFUSED', childCode: code, message };
    }
    return { ok: false, code: 'NATIVE_CHILD_NO_RESULT' };
  }
  return { ok: false, code: 'NATIVE_CHILD_NO_RESULT' };
}
