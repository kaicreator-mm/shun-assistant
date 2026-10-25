// T07 F02A: pure candidate grouping of REPORTED metadata, not OS observation.
// Same size is NOT proof of identical file content. No fs, native, shell or grants.
import { createHash } from 'node:crypto';

const MAX_FILES = 4096;
const MAX_GROUPS = 128;
const MAX_PATH = 1024;
const BAD_COMPONENT = /[<>:"|?*\u202a-\u202e\u2066-\u2069]/u;

function hasControlCharacters(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code < 32 || (code >= 127 && code <= 159)) return true;
  }
  return false;
}
const DEVICE = /^(con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/i;

type SameSizeCandidate = Readonly<{ sizeBytes: number; relativePaths: readonly string[] }>;
export type ReportedDuplicateCandidates = Readonly<{
  schema: 'shun.files.duplicate-candidates.v02';
  status: 'REPORTED_METADATA_ONLY';
  trust: 'UNVERIFIED_INPUT';
  scopeRoot: string;
  fileCount: number;
  sameSizeCandidates: readonly SameSizeCandidate[];
  inputDigestSha256: string;
  filesystemObserved: false;
  duplicatesVerified: false;
  executionAuthorized: false;
  cloudDisclosure: false;
  pendingTrustedChecks: readonly [
    'WINDOWS_HANDLE_ANCHORED_INVENTORY',
    'NO_REPARSE_OR_NETWORK_FOLLOW',
    'CONTENT_DIGEST_FROM_VERIFIED_HANDLES',
    'INDEPENDENT_POSTSTATE_CHECK',
  ];
}>;
export type DuplicateCandidateResult =
  | { ok: true; report: ReportedDuplicateCandidates }
  | { ok: false; code: 'FILE_CANDIDATES_REFUSED' };

const REQUIRED = [
  'WINDOWS_HANDLE_ANCHORED_INVENTORY',
  'NO_REPARSE_OR_NETWORK_FOLLOW',
  'CONTENT_DIGEST_FROM_VERIFIED_HANDLES',
  'INDEPENDENT_POSTSTATE_CHECK',
] as const;

function plainWithExactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  if (
    Object.getPrototypeOf(value) !== Object.prototype &&
    Object.getPrototypeOf(value) !== null
  )
    return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  return (
    names.length === keys.length &&
    keys.every(
      (key) =>
        descriptors[key]?.get === undefined &&
        descriptors[key]?.set === undefined &&
        Object.hasOwn(descriptors, key),
    )
  );
}

function validComponent(part: string): boolean {
  return (
    part.length > 0 &&
    part.length <= 255 &&
    part !== '.' &&
    part !== '..' &&
    !BAD_COMPONENT.test(part) &&
    !hasControlCharacters(part) &&
    !DEVICE.test(part) &&
    !/[. ]$/.test(part)
  );
}

function localScope(value: unknown): string | null {
  if (typeof value !== 'string' || value.length < 4 || value.length > MAX_PATH) return null;
  const path = value.replaceAll('/', '\\');
  if (!/^[a-zA-Z]:\\/.test(path) || path.startsWith('\\\\')) return null;
  if (!path.slice(3).split('\\').every(validComponent)) return null;
  return path[0]?.toUpperCase() + path.slice(1);
}

function relativeFile(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PATH) return null;
  const path = value.replaceAll('/', '\\');
  if (path.startsWith('\\') || !path.split('\\').every(validComponent)) return null;
  return path;
}

/**
 * Reports possible duplicates by equal byte count only, from caller-reported
 * data. Even a successful report is NEVER a trusted inventory, a content
 * equality result, an approval token or an executable capability.
 */
export function reportDuplicateCandidates(value: unknown): DuplicateCandidateResult {
  try {
    if (!plainWithExactKeys(value, ['scopeRoot', 'files'])) throw new Error('REFUSED');
    const scopeRoot = localScope(value.scopeRoot);
    const rawFiles = value.files;
    if (!scopeRoot || !Array.isArray(rawFiles) || rawFiles.length > MAX_FILES)
      throw new Error('REFUSED');

    const normalized: Array<{ relativePath: string; sizeBytes: number }> = [];
    const seen = new Set<string>();
    for (const raw of rawFiles) {
      if (!plainWithExactKeys(raw, ['relativePath', 'sizeBytes'])) throw new Error('REFUSED');
      const relativePath = relativeFile(raw.relativePath);
      const sizeBytes = raw.sizeBytes;
      if (
        relativePath === null ||
        typeof sizeBytes !== 'number' ||
        !Number.isSafeInteger(sizeBytes) ||
        sizeBytes < 0
      )
        throw new Error('REFUSED');
      const collisionKey = relativePath.toLowerCase();
      if (seen.has(collisionKey)) throw new Error('REFUSED');
      seen.add(collisionKey);
      normalized.push({ relativePath, sizeBytes });
    }

    normalized.sort(
      (a, b) =>
        a.relativePath.toLowerCase().localeCompare(b.relativePath.toLowerCase(), 'en') ||
        a.relativePath.localeCompare(b.relativePath, 'en'),
    );
    const bySize = new Map<number, string[]>();
    for (const item of normalized) {
      const paths = bySize.get(item.sizeBytes) ?? [];
      paths.push(item.relativePath);
      bySize.set(item.sizeBytes, paths);
    }
    const sameSizeCandidates = [...bySize]
      .filter(([, paths]) => paths.length > 1)
      .sort(([a], [b]) => a - b)
      .map(([sizeBytes, relativePaths]) => ({ sizeBytes, relativePaths }));
    if (sameSizeCandidates.length > MAX_GROUPS) throw new Error('REFUSED');
    const inputDigestSha256 = createHash('sha256')
      .update(JSON.stringify({ scopeRoot, files: normalized }))
      .digest('hex');
    return {
      ok: true,
      report: {
        schema: 'shun.files.duplicate-candidates.v02',
        status: 'REPORTED_METADATA_ONLY',
        trust: 'UNVERIFIED_INPUT',
        scopeRoot,
        fileCount: normalized.length,
        sameSizeCandidates,
        inputDigestSha256,
        filesystemObserved: false,
        duplicatesVerified: false,
        executionAuthorized: false,
        cloudDisclosure: false,
        pendingTrustedChecks: REQUIRED,
      },
    };
  } catch {
    return { ok: false, code: 'FILE_CANDIDATES_REFUSED' };
  }
}
