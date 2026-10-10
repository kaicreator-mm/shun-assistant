// Typed, allowlisted Windows operation surface for the local execution
// backend and the one-shot elevated helper (L2 §8.2, §8.2.1).
//
// The op enum below is the ENTIRE thing the privileged boundary can do:
// there is no passthrough op, no script op and no shell op — an unknown op is
// a structural refusal, not an interpreter error. Parameters are zod-strict,
// so any attempt to smuggle extra keys (helper paths, fault switches, shell
// text) fails schema validation before anything runs.
//
// Path rules follow §8.2.1: shell metacharacters are NOT special anywhere in
// this design (no string-concatenated shell command exists), so they pass
// through byte-exact; NTFS-illegal path characters and traversal segments
// fail closed instead.
import { z } from 'zod';

export const EXECUTOR_OPS = [
  'windows.proc.contextCheck',
  'windows.fs.write',
  'windows.fs.delete',
  'windows.fs.verify',
  'windows.registry.createKey',
  'windows.registry.setValue',
  'windows.registry.deleteKey',
  'windows.registry.verify',
  'windows.proc.exec',
] as const;
export type ExecutorOp = (typeof EXECUTOR_OPS)[number];

export const ExecutorOpSchema = z.enum(EXECUTOR_OPS);

/** Read-only ops the launcher may independently re-run as post-state verification (L2 §9.4). */
export const READONLY_OPS: readonly ExecutorOp[] = [
  'windows.proc.contextCheck',
  'windows.fs.verify',
  'windows.registry.verify',
];

/**
 * Characters illegal anywhere in an NTFS path segment (`< > " | ? *` and
 * control characters). `:` and `\` are legal at path-structure positions and
 * are validated positionally, not banned outright.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are exactly what this fail-closed filter rejects
const ILLEGAL_SEGMENT_CHARS = /[\u0000-\u001f<>:"|?*]/;

/** Reserved Win32 device names, case-insensitive, with or without extension. */
const RESERVED_DEVICE_NAMES = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  ...Array.from({ length: 9 }, (_, i) => `com${i + 1}`),
  ...Array.from({ length: 9 }, (_, i) => `lpt${i + 1}`),
]);

export const MAX_WINDOWS_PATH_LENGTH = 4096;

export type PathCheck = { ok: true } | { ok: false; reason: string };

/**
 * Fail-closed lexical validation of a Windows filesystem path the executor is
 * asked to touch. This is a contract-level filter: the executor additionally
 * enforces grant-scope containment and native realpath/reparse-point checks
 * before any filesystem call (contracts `pathWithin` documents the split).
 */
export function checkWindowsPath(path: string): PathCheck {
  if (path.length === 0) return { ok: false, reason: 'path is empty' };
  if (path.length > MAX_WINDOWS_PATH_LENGTH) {
    return { ok: false, reason: `path exceeds ${MAX_WINDOWS_PATH_LENGTH} characters` };
  }
  // Normalized-ASCII drive form (`C:\...`) or UNC (`\\server\share\...`); the
  // interpreter normalizes relatives against the action workspace, so raw
  // relatives are refused here to keep "what was validated = what is touched".
  const drive = /^[A-Za-z]:(?:\\|$)/.exec(path);
  const unc = /^\\\\[^\\]+\\[^\\]+/.exec(path);
  if (!drive && !unc) {
    return { ok: false, reason: 'path must be absolute (drive `C:\\` or UNC `\\\\server\\share`)' };
  }
  const colonIndex = path.indexOf(':');
  if (colonIndex >= 0 && !(drive && colonIndex === 1)) {
    return {
      ok: false,
      reason: 'drive-colon is the only legal `:` position (ADS/NtObject paths refused)',
    };
  }
  const segments = path.split(/[\\/]/).filter((s) => s.length > 0);
  let first = true;
  for (const segment of segments) {
    if (segment === '.' || segment === '..') {
      return {
        ok: false,
        reason: `traversal segment "${segment}" fails closed (lexical check cannot resolve landing)`,
      };
    }
    // The drive segment (`C:`) is legal despite its colon; anything past it
    // has no positional colon allowance.
    const isDriveSegment = first && /^[A-Za-z]:$/.test(segment);
    first = false;
    if (!isDriveSegment && ILLEGAL_SEGMENT_CHARS.test(segment)) {
      return {
        ok: false,
        reason: `segment "${truncate(segment)}" contains an NTFS-illegal character`,
      };
    }
    // Windows silently strips trailing dots/spaces on Win32 normalization —
    // a silent mutation of the validated path, so refuse instead.
    if (/[. ]$/.test(segment)) {
      return {
        ok: false,
        reason: `segment "${truncate(segment)}" ends with a dot/space Win32 would strip`,
      };
    }
    const base = segment.split('.')[0]?.toLowerCase() ?? '';
    if (RESERVED_DEVICE_NAMES.has(base)) {
      return { ok: false, reason: `segment "${truncate(segment)}" is a reserved device name` };
    }
  }
  return { ok: true };
}

/**
 * Registry key paths are anchored to a real root hive; long-form hive names
 * are normalized by the interpreter. Wildcards/ILLEGAL chars fail closed —
 * `reg delete HKLM\...` with a glued wildcard is exactly the accident this
 * check exists to prevent.
 */
export function checkRegistryKey(key: string): PathCheck {
  if (key.length === 0) return { ok: false, reason: 'registry key is empty' };
  if (key.length > 1024) return { ok: false, reason: 'registry key exceeds 1024 characters' };
  const short = /^(HKLM|HKCU|HKCR|HKU|HKCC)\\/i;
  const long =
    /^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\/i;
  if (!short.test(key) && !long.test(key)) {
    return { ok: false, reason: 'key must be rooted at a real hive (HKLM\\, HKCU\\, …)' };
  }
  const sub = key.split('\\').slice(1);
  for (const segment of sub) {
    if (segment === '.' || segment === '..') {
      return { ok: false, reason: `traversal segment "${segment}" fails closed` };
    }
    if (ILLEGAL_SEGMENT_CHARS.test(segment)) {
      return {
        ok: false,
        reason: `segment "${truncate(segment)}" contains an illegal registry-path character`,
      };
    }
    if (/[. ]$/.test(segment)) {
      return { ok: false, reason: `segment "${truncate(segment)}" ends with a dot/space` };
    }
  }
  return { ok: true };
}

function truncate(s: string): string {
  return s.length > 40 ? `${s.slice(0, 37)}…` : s;
}

// ---- Typed op parameters. ----

export const ContextCheckArgsSchema = z.strictObject({
  expectElevated: z.boolean(),
});
export type ContextCheckArgs = z.infer<typeof ContextCheckArgsSchema>;

export const FsWriteArgsSchema = z.strictObject({
  path: z.string().min(1),
  content: z.string(),
  encoding: z.literal('utf8').default('utf8'),
});
export type FsWriteArgs = z.infer<typeof FsWriteArgsSchema>;

export const FsDeleteArgsSchema = z.strictObject({
  path: z.string().min(1),
});
export type FsDeleteArgs = z.infer<typeof FsDeleteArgsSchema>;

export const FsVerifyArgsSchema = z.strictObject({
  path: z.string().min(1),
  expectExists: z.boolean(),
  expectContent: z.string().optional(),
  expectSha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
});
export type FsVerifyArgs = z.infer<typeof FsVerifyArgsSchema>;

export const RegistryCreateKeyArgsSchema = z.strictObject({
  key: z.string().min(1),
});
export type RegistryCreateKeyArgs = z.infer<typeof RegistryCreateKeyArgsSchema>;

export const RegistrySetValueArgsSchema = z.strictObject({
  key: z.string().min(1),
  valueName: z.string().min(1).max(16383),
  type: z.enum(['REG_SZ', 'REG_DWORD']),
  data: z.union([z.string(), z.number().int()]),
});
export type RegistrySetValueArgs = z.infer<typeof RegistrySetValueArgsSchema>;

export const RegistryDeleteKeyArgsSchema = z.strictObject({
  key: z.string().min(1),
});
export type RegistryDeleteKeyArgs = z.infer<typeof RegistryDeleteKeyArgsSchema>;

export const RegistryVerifyArgsSchema = z.strictObject({
  key: z.string().min(1),
  expectKeyExists: z.boolean().optional(),
  expectValues: z.record(z.string().min(1), z.string()).optional(),
});
export type RegistryVerifyArgs = z.infer<typeof RegistryVerifyArgsSchema>;

export const ProcExecArgsSchema = z.strictObject({
  /** Absolute path to the executable. Pinned by the plan hash; never resolvable from caller input. */
  program: z.string().min(1),
  args: z.array(z.string()),
  expectExitCode: z.number().int().default(0),
  /** Per-step cap; the helper deadline remains the outer bound. */
  timeoutMs: z.number().int().positive().optional(),
  /** Captured stdio above this size is truncated and flagged (bounded evidence). */
  captureCapBytes: z.number().int().positive().default(262144),
});
export type ProcExecArgs = z.infer<typeof ProcExecArgsSchema>;

/** Discriminated by `op`; strict so unknown keys anywhere are schema refusals. */
export const ExecutorStepSchema = z.discriminatedUnion('op', [
  z.strictObject({ op: z.literal('windows.proc.contextCheck'), args: ContextCheckArgsSchema }),
  z.strictObject({ op: z.literal('windows.fs.write'), args: FsWriteArgsSchema }),
  z.strictObject({ op: z.literal('windows.fs.delete'), args: FsDeleteArgsSchema }),
  z.strictObject({ op: z.literal('windows.fs.verify'), args: FsVerifyArgsSchema }),
  z.strictObject({
    op: z.literal('windows.registry.createKey'),
    args: RegistryCreateKeyArgsSchema,
  }),
  z.strictObject({ op: z.literal('windows.registry.setValue'), args: RegistrySetValueArgsSchema }),
  z.strictObject({
    op: z.literal('windows.registry.deleteKey'),
    args: RegistryDeleteKeyArgsSchema,
  }),
  z.strictObject({ op: z.literal('windows.registry.verify'), args: RegistryVerifyArgsSchema }),
  z.strictObject({ op: z.literal('windows.proc.exec'), args: ProcExecArgsSchema }),
]);
export type ExecutorStep = z.infer<typeof ExecutorStepSchema>;

/**
 * Semantic step validation that the schema layer cannot express: path/key
 * legality per declared type. Runs identically on the launcher side (fail
 * fast) and inside the privileged helper (authoritative). Shell
 * metacharacters deliberately do NOT fail here — they are data, not syntax,
 * in this design.
 */
export function checkStepSurface(step: ExecutorStep): PathCheck {
  switch (step.op) {
    case 'windows.fs.write':
    case 'windows.fs.delete':
    case 'windows.fs.verify':
      return checkWindowsPath(step.args.path);
    case 'windows.registry.createKey':
    case 'windows.registry.deleteKey':
    case 'windows.registry.setValue':
    case 'windows.registry.verify':
      return checkRegistryKey(step.args.key);
    case 'windows.proc.exec': {
      const program = checkWindowsPath(step.args.program);
      if (!program.ok) return { ok: false, reason: `program: ${program.reason}` };
      return { ok: true };
    }
    case 'windows.proc.contextCheck':
      return { ok: true };
  }
}
