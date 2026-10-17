// Minimal PE import-table scanner for native-addon dependency closure
// (T05 #106). It parses ONLY what is needed to enumerate the direct DLL
// dependencies of a `.node`/DLL image: DOS header → PE signature → COFF →
// optional header → data directories → section table → import directory
// (and the delay-load import directory). Every read is bounds-checked; any
// malformed or truncated structure fails closed (`PE_PARSE_FAILED`) rather
// than yielding a partial closure.
//
// The Windows loader itself resolves dependent DLLs starting from the loaded
// image's own directory (libuv dlopens with LOAD_WITH_ALTERED_SEARCH_PATH),
// so a dependency is only satisfiable from the per-run staging directory if
// it is staged there under its exact import name. That is the property the
// closure check builds on: every import must be a known system DLL or a
// signer-declared, SHA-pinned dependency — anything else is refused before
// any process exists.

export type PeScanRefusal = 'PE_PARSE_FAILED';

export type PeImportScan =
  | {
      readonly ok: true;
      /** COFF machine type, e.g. 0x8664 for AMD64. */
      readonly machine: number;
      readonly pe32Plus: boolean;
      /** Direct DLL imports (deduplicated, original case preserved). */
      readonly imports: readonly string[];
    }
  | { readonly ok: false; readonly code: PeScanRefusal };

const MAX_IMPORT_DLLS = 4096;
const MAX_IMAGE_NAME_BYTES = 256;

function asciiZ(bytes: Buffer, offset: number): string | null {
  if (offset < 0 || offset >= bytes.length) return null;
  const end = Math.min(bytes.length, offset + MAX_IMAGE_NAME_BYTES);
  let cursor = offset;
  while (cursor < end && bytes[cursor] !== 0) cursor += 1;
  if (cursor >= end) return null;
  return bytes.toString('latin1', offset, cursor);
}

export function scanPeImports(bytes: Buffer): PeImportScan {
  try {
    if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    const peOffset = bytes.readUInt32LE(0x3c);
    if (peOffset <= 0 || peOffset + 4 + 20 > bytes.length) {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    if (bytes.toString('latin1', peOffset, peOffset + 4) !== 'PE\0\0') {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    const coff = peOffset + 4;
    const machine = bytes.readUInt16LE(coff);
    const sectionCount = bytes.readUInt16LE(coff + 2);
    const optionalSize = bytes.readUInt16LE(coff + 16);
    const optional = coff + 20;
    if (optional + optionalSize > bytes.length) return { ok: false, code: 'PE_PARSE_FAILED' };
    const magic = bytes.readUInt16LE(optional);
    const pe32Plus = magic === 0x20b;
    if (!pe32Plus && magic !== 0x10b) return { ok: false, code: 'PE_PARSE_FAILED' };
    const directoryCount = bytes.readUInt32LE(optional + (pe32Plus ? 108 : 92));
    const directories = optional + (pe32Plus ? 112 : 96);
    if (directoryCount < 2 || directories + directoryCount * 8 > bytes.length) {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    const readDirectory = (index: number): { rva: number; size: number } => ({
      rva: bytes.readUInt32LE(directories + index * 8),
      size: bytes.readUInt32LE(directories + index * 8 + 4),
    });
    const sectionTable = optional + optionalSize;
    if (sectionTable + sectionCount * 40 > bytes.length) {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    const sections: Array<{ va: number; span: number; raw: number }> = [];
    for (let index = 0; index < sectionCount; index += 1) {
      const base = sectionTable + index * 40;
      const virtualSize = bytes.readUInt32LE(base + 8);
      const virtualAddress = bytes.readUInt32LE(base + 12);
      const rawSize = bytes.readUInt32LE(base + 16);
      sections.push({
        va: virtualAddress,
        span: Math.max(virtualSize, rawSize),
        raw: bytes.readUInt32LE(base + 20),
      });
    }
    const rvaToOffset = (rva: number): number => {
      for (const section of sections) {
        if (rva >= section.va && rva < section.va + section.span) {
          return rva - section.va + section.raw;
        }
      }
      return -1;
    };
    const imports = new Set<string>();
    // Walks one thunk array (INT or IAT) purely for bounds sanity: thunk
    // entries name FUNCTIONS, which are not part of the DLL closure.
    const walkThunks = (rva: number): void => {
      let offset = rvaToOffset(rva);
      if (offset < 0) return;
      const thunkSize = pe32Plus ? 8 : 4;
      const ordinalFlag = pe32Plus ? 1n << 63n : 1n << 31n;
      for (let index = 0; index < MAX_IMPORT_DLLS; index += 1) {
        if (offset + thunkSize > bytes.length) return;
        const thunk = pe32Plus ? bytes.readBigUInt64LE(offset) : BigInt(bytes.readUInt32LE(offset));
        if (thunk === 0n) return;
        if ((thunk & ordinalFlag) !== 0n) return;
        const nameRva = Number(thunk & 0xffffffffn);
        if (rvaToOffset(nameRva) < 0) return;
        offset += thunkSize;
      }
    };
    // `delay` selects between IMAGE_IMPORT_DESCRIPTOR (20 bytes) and
    // IMAGE_DELAYLOAD_DESCRIPTOR (32 bytes). VA-form delay tables (no RVA
    // attribute bit) cannot be resolved from file bytes alone and fail closed.
    const walkDescriptors = (directory: { rva: number; size: number }, delay: boolean): boolean => {
      if (directory.rva === 0 || directory.rva === 0xffffffff) return true;
      let offset = rvaToOffset(directory.rva);
      if (offset < 0) return false;
      const stride = delay ? 32 : 20;
      for (let index = 0; index < MAX_IMPORT_DLLS; index += 1) {
        if (offset + stride > bytes.length) return false;
        let nameRva: number;
        let thunkRva: number;
        if (delay) {
          const attributes = bytes.readUInt32LE(offset);
          if (attributes === 0) return true;
          if ((attributes & 1) === 0) return false;
          nameRva = bytes.readUInt32LE(offset + 4);
          thunkRva = bytes.readUInt32LE(offset + 16);
          if (thunkRva === 0) thunkRva = bytes.readUInt32LE(offset + 12);
        } else {
          nameRva = bytes.readUInt32LE(offset + 12);
          thunkRva = bytes.readUInt32LE(offset);
          if (thunkRva === 0) thunkRva = bytes.readUInt32LE(offset + 16);
        }
        if (nameRva === 0 && thunkRva === 0) return true;
        const name = asciiZ(bytes, rvaToOffset(nameRva));
        if (!name) return false;
        imports.add(name);
        if (imports.size > MAX_IMPORT_DLLS) return false;
        if (thunkRva !== 0) walkThunks(thunkRva);
        offset += stride;
      }
      return false;
    };
    if (!walkDescriptors(readDirectory(1), false)) {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    if (directoryCount > 13 && !walkDescriptors(readDirectory(13), true)) {
      return { ok: false, code: 'PE_PARSE_FAILED' };
    }
    return {
      ok: true,
      machine,
      pe32Plus,
      imports: Object.freeze([...imports]),
    };
  } catch {
    return { ok: false, code: 'PE_PARSE_FAILED' };
  }
}

/**
 * Host product policy: DLL names the Windows loader may satisfy from the
 * trusted system directories without being declared in the signed closure.
 * API-set and extension-set virtual DLLs are matched by prefix; everything
 * else must match exactly (case-insensitively, as the loader does).
 * `node.exe` is included because NAPI addons import the host runtime.
 */
const SYSTEM_DLL_EXACT = new Set(
  [
    'ntdll.dll',
    'kernel32.dll',
    'kernelbase.dll',
    'node.exe',
    'user32.dll',
    'gdi32.dll',
    'gdiplus.dll',
    'shell32.dll',
    'shlwapi.dll',
    'advapi32.dll',
    'rpcrt4.dll',
    'ole32.dll',
    'oleaut32.dll',
    'oleacc.dll',
    'version.dll',
    'winmm.dll',
    'ws2_32.dll',
    'wsock32.dll',
    'secur32.dll',
    'sspicli.dll',
    'crypt32.dll',
    'cryptbase.dll',
    'bcrypt.dll',
    'bcryptprimitives.dll',
    'ncrypt.dll',
    'wintrust.dll',
    'msvcrt.dll',
    'ucrtbase.dll',
    'msvcp140.dll',
    'msvcp140_1.dll',
    'msvcp140_2.dll',
    'msvcp140_atomic_wait.dll',
    'vcruntime140.dll',
    'vcruntime140_1.dll',
    'comctl32.dll',
    'comdlg32.dll',
    'winspool.drv',
    'setupapi.dll',
    'imagehlp.dll',
    'dbghelp.dll',
    'psapi.dll',
    'userenv.dll',
    'normaliz.dll',
    'iphlpapi.dll',
    'dnsapi.dll',
    'msimg32.dll',
    'imm32.dll',
    'uxtheme.dll',
    'dwmapi.dll',
    'powrprof.dll',
    'wtsapi32.dll',
    'windowscodecs.dll',
    'wldp.dll',
    'd3d11.dll',
    'dxgi.dll',
    'dcomp.dll',
    'opengl32.dll',
    'glu32.dll',
  ].map((name) => name.toLowerCase()),
);

const SYSTEM_DLL_PREFIXES = ['api-ms-win-', 'ext-ms-win-'];

export function isSystemDllImportName(name: string): boolean {
  const lower = name.toLowerCase();
  if (SYSTEM_DLL_EXACT.has(lower)) return true;
  return SYSTEM_DLL_PREFIXES.some((prefix) => lower.startsWith(prefix));
}
