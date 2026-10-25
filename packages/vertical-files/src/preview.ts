// T07 F01: pure, deterministic, bounded file operation proposals.
//
// Preview is NOT authorization, not an OS observation, and never calls fs.
// A later trusted Windows effect Host MUST reject reparse/UNC/subst, recheck
// roots and no-overwrite immediately before commit, and journal STARTED first.
import { createHash } from 'node:crypto';
import { win32 } from 'node:path';

type FileOperation =
  | 'file.search'
  | 'file.duplicates.report'
  | 'file.copy'
  | 'file.move'
  | 'file.rename';

export type FilePreviewRequest = Readonly<
  { taskId: string; scopeRoot: string } & (
    | { op: 'file.search'; query: string }
    | { op: 'file.duplicates.report' }
    | { op: 'file.copy' | 'file.move'; sourcePath: string; destinationPath: string }
    | { op: 'file.rename'; sourcePath: string; newName: string }
  )
>;

export type FilePreview = Readonly<{
  schema: 'shun.files.preview.v02';
  taskId: string;
  op: FileOperation;
  scopeRoot: string;
  sourcePath?: string;
  destinationPath?: string;
  query?: string;
  intentSha256: string;
  status: 'PREVIEW_ONLY';
  executionAuthorized: false;
  filesystemObserved: false;
  overwrittenExistingFile: false;
  pendingTrustedChecks: readonly [
    'CURRENT_ACTION_CONTROLLER_GRANT',
    'OS_CANONICAL_SCOPE_AND_REPARSE',
    'NO_OVERWRITE_AT_EFFECT_TIME',
    'DURABLE_PRE_EFFECT_JOURNAL',
    'INDEPENDENT_POSTSTATE_AND_RECONCILIATION',
  ];
}>;

export type FilePreviewResult =
  | { ok: true; preview: FilePreview }
  | { ok: false; code: 'FILE_PREVIEW_REFUSED' };

const PENDING = [
  'CURRENT_ACTION_CONTROLLER_GRANT',
  'OS_CANONICAL_SCOPE_AND_REPARSE',
  'NO_OVERWRITE_AT_EFFECT_TIME',
  'DURABLE_PRE_EFFECT_JOURNAL',
  'INDEPENDENT_POSTSTATE_AND_RECONCILIATION',
] as const;

const DEVICE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;
const BAD_SEGMENT = /[<>:"|?*]/;

function hasControlCharacters(value: string): boolean {
  for (const char of value) {
    if (char.charCodeAt(0) < 32) return true;
  }
  return false;
}
const MAX_PATH = 1024;
const MAX_QUERY = 128;

function cleanSegment(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= 255 &&
    name !== '.' &&
    name !== '..' &&
    !BAD_SEGMENT.test(name) &&
    !hasControlCharacters(name) &&
    !DEVICE.test(name) &&
    !/[. ]$/.test(name)
  );
}

/** Lexical sanity only. DOES NOT assert safe resolved filesystem identity. */
function localWindowsPath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length < 4 || raw.length > MAX_PATH) return null;
  const value = raw.replaceAll('/', '\\');
  if (!/^[a-zA-Z]:\\/.test(value) || value.startsWith('\\\\')) return null;
  const segments = value.slice(3).split('\\');
  if (!segments.every(cleanSegment)) return null;
  const normalized = win32.normalize(value);
  return /^[a-zA-Z]:\\/.test(normalized) ? normalized : null;
}

function within(child: string, root: string): boolean {
  const base = root.endsWith('\\') ? root : root + '\\';
  return child.toLowerCase().startsWith(base.toLowerCase());
}

function queryOk(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_QUERY &&
    !/[\\/:<>"|]/.test(value) &&
    !hasControlCharacters(value) &&
    !value.includes('..')
  );
}

/** Has no OS side effects; NEVER an executable capability or grant. */
export function previewScopedFileOperation(value: unknown): FilePreviewResult {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
      return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
    const raw = value as Record<string, unknown>;
    const op = raw.op;
    const taskId = raw.taskId;
    const root = localWindowsPath(raw.scopeRoot);
    if (typeof taskId !== 'string' || taskId.length < 1 || taskId.length > 128 || !root)
      return { ok: false, code: 'FILE_PREVIEW_REFUSED' };

    const basics = ['taskId', 'scopeRoot', 'op'];
    const extensions =
      op === 'file.search'
        ? ['query']
        : op === 'file.duplicates.report'
          ? []
          : op === 'file.copy' || op === 'file.move'
            ? ['sourcePath', 'destinationPath']
            : op === 'file.rename'
              ? ['sourcePath', 'newName']
              : null;
    if (extensions === null) return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
    const allowed = [...basics, ...extensions];
    if (Object.keys(raw).some((key) => !allowed.includes(key)))
      return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
    let sourcePath: string | undefined;
    let destinationPath: string | undefined;
    let query: string | undefined;
    if (op === 'file.search') {
      if (!queryOk(raw.query)) return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
      query = raw.query;
    } else if (op !== 'file.duplicates.report') {
      const src = localWindowsPath(raw.sourcePath);
      if (!src || !within(src, root)) return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
      sourcePath = src;
      if (op === 'file.copy' || op === 'file.move') {
        const dest = localWindowsPath(raw.destinationPath);
        if (!dest) return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
        destinationPath = dest;
      } else {
        if (typeof raw.newName !== 'string' || !cleanSegment(raw.newName))
          return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
        destinationPath = win32.join(win32.dirname(src), raw.newName);
      }
      if (
        !within(destinationPath, root) ||
        sourcePath.toLowerCase() === destinationPath.toLowerCase() ||
        within(destinationPath, sourcePath)
      )
        return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
    }

    // Canonical, fixed-field digest is a proposal identity, NOT a MAC, grant
    // signature, path-to-handle binding, or preview approval.
    const intent = { taskId, op, scopeRoot: root, sourcePath, destinationPath, query };
    const intentSha256 = createHash('sha256').update(JSON.stringify(intent)).digest('hex');
    return {
      ok: true,
      preview: {
        schema: 'shun.files.preview.v02',
        ...intent,
        intentSha256,
        status: 'PREVIEW_ONLY',
        executionAuthorized: false,
        filesystemObserved: false,
        overwrittenExistingFile: false,
        pendingTrustedChecks: PENDING,
      },
    };
  } catch {
    // Malicious proxy/getter cannot leak paths or force preview success.
    return { ok: false, code: 'FILE_PREVIEW_REFUSED' };
  }
}
