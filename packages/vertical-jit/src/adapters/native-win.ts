// Native Windows handle-safety primitives host (T10 / #50 R6).
//
// The actual primitive logic lives in ShunNative.cs (compiled at run time by
// Add-Type under the stock Windows PowerShell 5.1 compiler) and uses only
// native handle-relative, no-follow operations:
//
//   Extract    — locked-stream SHA + budgets + NtCreateFile(RootDirectory=…)
//                component walk; a junction/reparse substitution before or
//                during extraction can never redirect a byte outside the
//                pinned destination chain.
//   RemoveTree — pinned-chain census through NtQueryDirectoryFile on held
//                directory handles + exact-manifest membership + NT FileId /
//                content-identity re-verification + deletion strictly BY
//                HANDLE (FileDispositionInformationEx, POSIX semantics).
//
// This module owns only transport: a fixed PowerShell bootstrap command (no
// archive/destination/path string is ever passed as an argument token) and a
// base64-over-stdin protocol, mirroring the R4 fix that keeps
// spaces/parentheses in real winget filenames out of PowerShell syntax.
import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ProcessPort } from '../ports.ts';
import { AcquisitionError } from '../ports.ts';

/** One exact-entry extraction target as reported by the native extractor. */
export interface ExtractedEntry {
  readonly path: string;
  readonly kind: 'file' | 'dir';
  /** Present for files: SHA256 of the exact bytes written through the handle. */
  readonly sha256?: string;
  readonly bytes: number;
}

/** Install-time native object identity for restart-safe ownership. */
export interface NativeObjectIdentity {
  readonly path: string;
  readonly kind: 'file' | 'dir';
  readonly fileId: string;
  readonly sha256?: string;
}

/** Identity-pinned native deletion outcome. */
export interface NativeRemovalResult {
  readonly ok: boolean;
  /** The managed root was already absent (nothing existed to delete). */
  readonly absentRoot?: boolean;
  readonly removed: readonly string[];
  readonly retained: readonly string[];
  /** Refusal code from the native primitive (FOREIGN_CONTENT, FOREIGN_REPARSE, ZIP_REPARSE_POINT, NATIVE_STATUS, …). */
  readonly refusal?: string;
  readonly detail?: string;
}

/** Transport-level native failure carrying the primitive's refusal code. */
export class NativeSafetyError extends Error {
  readonly code: string;

  constructor(code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'NativeSafetyError';
    this.code = code;
  }
}

const nativeSourcePromise: Promise<string> = readFile(
  fileURLToPath(new URL('./ShunNative.cs', import.meta.url)),
  'utf8',
);

function encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function decodeBase64Text(text: string, what: string): string {
  const trimmed = text.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || trimmed.length % 4 !== 0) {
    throw new NativeSafetyError('NATIVE_TRANSPORT', `${what} is not base64`);
  }
  return Buffer.from(trimmed, 'base64').toString('utf8');
}

// Fixed bootstrap. Every data value (mode, C# source, arguments) arrives as
// base64 lines over stdin; the command argument itself never varies. Only
// single-quoted PowerShell literals appear here: libuv's Windows argument
// escaping turns embedded double quotes into \" which -Command re-parses
// badly, so the R4 spaced-filename lesson applies to the script body too.
const BOOTSTRAP = [
  "$ErrorActionPreference = 'Stop'",
  'try {',
  '  $lines = ([Console]::In.ReadToEnd()) -split ([string][char]10)',
  '  function Dec([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s.Trim())) }',
  '  $mode = $lines[0].Trim()',
  "  Add-Type -TypeDefinition (Dec $lines[1]) -Language CSharp -ReferencedAssemblies @('System.IO.Compression')",
  "  if ($mode -eq 'extract') {",
  '    $out = [Shun.Native]::Extract((Dec $lines[2]), (Dec $lines[3]), (Dec $lines[4]))',
  "  } elseif ($mode -eq 'snapshot') {",
  '    $out = [Shun.Native]::SnapshotTree((Dec $lines[2]), (Dec $lines[3]))',
  "  } elseif ($mode -eq 'delete') {",
  '    $out = [Shun.Native]::RemoveTree((Dec $lines[2]), (Dec $lines[3]), (Dec $lines[4]))',
  '  } else {',
  "    throw 'NATIVE_MODE'",
  '  }',
  '  [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$out)))',
  '} catch {',
  '  $m = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }',
  '  [Console]::Error.Write($m)',
  '  exit 1',
  '}',
].join('\n');

interface NativeInvokeOptions {
  readonly process: ProcessPort;
  readonly powershellExe: string;
  readonly timeoutMs: number;
}

async function invokeNative(
  options: NativeInvokeOptions,
  mode: 'extract' | 'snapshot' | 'delete',
  args: readonly string[],
): Promise<string> {
  const source = await nativeSourcePromise;
  const input = [mode, encode(source), ...args.map(encode)].join('\n');
  const result = await options.process.run({
    argv: [
      options.powershellExe,
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `& { ${BOOTSTRAP} }`,
    ],
    timeoutMs: options.timeoutMs,
    input,
  });
  if (result.exitCode !== 0 || result.timedOut) {
    const firstError = result.stderr
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean);
    if (firstError) {
      const separator = firstError.indexOf('\t');
      const code = separator >= 0 ? firstError.slice(0, separator) : firstError;
      const detail = separator >= 0 ? firstError.slice(separator + 1) : undefined;
      throw new NativeSafetyError(code || 'NATIVE_UNKNOWN', detail || undefined);
    }
    throw new NativeSafetyError(
      'NATIVE_UNKNOWN',
      `native ${mode} failed (${result.exitCode}${result.timedOut ? ', timed out' : ''})`,
    );
  }
  return decodeBase64Text(result.stdout, 'native output');
}

export interface SafeExtractorOptions {
  readonly timeoutMs?: number;
}

/**
 * Fixed-transport ZIP extractor backed by the native handle-relative
 * primitive. The PowerShell path is injected by trusted host composition and
 * must be absolute; no PATH lookup is performed.
 */
export class SafePowerShellZipExtractor {
  readonly #process: ProcessPort;
  readonly #powershellExe: string;
  readonly #timeoutMs: number;

  constructor(process: ProcessPort, powershellExe: string, options: SafeExtractorOptions = {}) {
    if (!isAbsolute(powershellExe)) {
      throw new Error('portable ZIP extractor requires an absolute PowerShell path');
    }
    this.#process = process;
    this.#powershellExe = powershellExe;
    this.#timeoutMs = options.timeoutMs ?? 180_000;
  }

  async extractZip(
    archivePath: string,
    destination: string,
    expectedSha256: string,
  ): Promise<readonly ExtractedEntry[]> {
    if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) {
      throw new AcquisitionError('INSTALL_FAILED', 'portable ZIP expected SHA256 is malformed');
    }
    const text = await invokeNative(
      { process: this.#process, powershellExe: this.#powershellExe, timeoutMs: this.#timeoutMs },
      'extract',
      [archivePath, destination, expectedSha256.toLowerCase()],
    );
    const entries: ExtractedEntry[] = [];
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [path, sha, bytes] = trimmed.split('\t');
      if (!path || !bytes) {
        throw new AcquisitionError('INSTALL_FAILED', 'native extractor manifest is malformed');
      }
      const parsedBytes = Number(bytes);
      if (!Number.isInteger(parsedBytes) || parsedBytes < 0) {
        throw new AcquisitionError('INSTALL_FAILED', 'native extractor manifest is malformed');
      }
      if (sha === '-') {
        entries.push({ path, kind: 'dir', bytes: 0 });
      } else if (sha && /^[0-9a-f]{64}$/.test(sha)) {
        entries.push({ path, kind: 'file', sha256: sha, bytes: parsedBytes });
      } else {
        throw new AcquisitionError('INSTALL_FAILED', 'native extractor manifest is malformed');
      }
    }
    if (entries.length === 0) {
      throw new AcquisitionError(
        'INSTALL_FAILED',
        'portable ZIP extractor returned no exact-entry manifest',
      );
    }
    return entries;
  }
}

export interface NativeDeleterOptions {
  readonly timeoutMs?: number;
}

/**
 * The native identity-pinned deletion seam consumed by the managed-portable
 * removal effect. Production wiring uses PowerShellNativeDeleter; there is no
 * pathname-based implementation of this interface by design.
 */
export interface NativeDeletionPort {
  snapshotTreePinned(
    root: string,
    manifest: readonly string[],
  ): Promise<readonly NativeObjectIdentity[]>;

  removeTreePinned(
    root: string,
    manifest: readonly string[],
    identities?: ReadonlyMap<string, NativeObjectIdentity>,
  ): Promise<NativeRemovalResult>;
}

/**
 * Identity-pinned manifest deletion through the native primitive. There is no
 * pathname-based fallback: if this primitive cannot run, removal fails closed.
 */
export class PowerShellNativeDeleter {
  readonly #process: ProcessPort;
  readonly #powershellExe: string;
  readonly #timeoutMs: number;

  constructor(process: ProcessPort, powershellExe: string, options: NativeDeleterOptions = {}) {
    if (!isAbsolute(powershellExe)) {
      throw new Error('native pinned deleter requires an absolute PowerShell path');
    }
    this.#process = process;
    this.#powershellExe = powershellExe;
    this.#timeoutMs = options.timeoutMs ?? 180_000;
  }

  async snapshotTreePinned(
    root: string,
    manifest: readonly string[],
  ): Promise<readonly NativeObjectIdentity[]> {
    if (!isAbsolute(root) || manifest.length === 0 || manifest.some((path) => !isAbsolute(path))) {
      throw new NativeSafetyError(
        'NATIVE_PATH',
        'snapshot root and manifest paths must be absolute',
      );
    }
    const text = await invokeNative(
      { process: this.#process, powershellExe: this.#powershellExe, timeoutMs: this.#timeoutMs },
      'snapshot',
      [root, manifest.join('\n')],
    );
    const identities: NativeObjectIdentity[] = [];
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [path, kind, fileId, sha] = trimmed.split('\t');
      if (
        !path ||
        (kind !== 'file' && kind !== 'dir') ||
        !fileId ||
        !/^[0-9a-f]{48}$/.test(fileId)
      ) {
        throw new NativeSafetyError('NATIVE_TRANSPORT', 'native snapshot row is malformed');
      }
      if (kind === 'file') {
        if (!sha || !/^[0-9a-f]{64}$/.test(sha)) {
          throw new NativeSafetyError('NATIVE_TRANSPORT', 'native file snapshot SHA is malformed');
        }
        identities.push({ path, kind, fileId, sha256: sha });
      } else {
        if (sha !== '-') {
          throw new NativeSafetyError('NATIVE_TRANSPORT', 'native directory snapshot is malformed');
        }
        identities.push({ path, kind, fileId });
      }
    }
    if (identities.length === 0) {
      throw new NativeSafetyError('NATIVE_TRANSPORT', 'native snapshot returned no identities');
    }
    return identities;
  }

  async removeTreePinned(
    root: string,
    manifest: readonly string[],
    identities?: ReadonlyMap<string, NativeObjectIdentity>,
  ): Promise<NativeRemovalResult> {
    if (!isAbsolute(root)) {
      return { ok: false, removed: [], retained: [], refusal: 'NATIVE_PATH', detail: root };
    }
    const paths = [...manifest];
    if (paths.length === 0 || paths.some((path) => !isAbsolute(path))) {
      return {
        ok: false,
        removed: [],
        retained: [],
        refusal: 'NATIVE_PATH',
        detail: 'manifest paths must be absolute',
      };
    }
    const identityText = [...(identities ?? new Map<string, NativeObjectIdentity>())]
      .map(([path, identity]) =>
        [resolve(path), identity.kind, identity.fileId, identity.sha256 ?? '-'].join('\t'),
      )
      .join('\n');
    let text: string;
    try {
      text = await invokeNative(
        { process: this.#process, powershellExe: this.#powershellExe, timeoutMs: this.#timeoutMs },
        'delete',
        [root, paths.join('\n'), identityText],
      );
    } catch (error) {
      if (error instanceof NativeSafetyError) {
        return { ok: false, removed: [], retained: [], refusal: error.code, detail: error.message };
      }
      throw error;
    }
    const lines = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const head = lines[0] ?? '';
    const removedLine = lines.find((line) => line.startsWith('REMOVED\t'));
    const removed = removedLine
      ? removedLine.slice('REMOVED\t'.length).split('|').filter(Boolean)
      : [];
    if (head === 'ABSENT') {
      return { ok: true, absentRoot: true, removed: [], retained: [] };
    }
    if (head.startsWith('OK\t')) {
      return { ok: true, removed, retained: [] };
    }
    if (head.startsWith('RETAINED\t')) {
      const retained = head.slice('RETAINED\t'.length).split('|').filter(Boolean);
      return { ok: false, removed, retained, refusal: 'RETAINED' };
    }
    return {
      ok: false,
      removed,
      retained: [],
      refusal: 'NATIVE_TRANSPORT',
      detail: head || 'empty native result',
    };
  }
}
