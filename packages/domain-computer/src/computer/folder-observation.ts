import { types } from 'node:util';

/**
 * T02 — selected-folder read-only metadata observation adapter.
 *
 * The actual filesystem walk remains Host-owned and reuses the existing
 * vertical-storage resolveScope/observeStorage implementation. This public
 * Computer seam accepts no path, runner, scope or callback from the caller:
 * the trusted Host resolves the user's current selected-root reference and
 * returns only bounded relative metadata. File contents and absolute paths
 * never cross this boundary.
 */

export const COMPUTER_FOLDER_OBSERVATION_SCHEMA = 'shun.computer.folder-observation.v03' as const;
export const HOST_FOLDER_OBSERVATION_SCHEMA = 'shun.host-folder-observation.v1' as const;

export interface ComputerFolderObservationHostPort {
  /** Host resolves the authenticated user's current selected root internally. */
  observeCurrentSelectedFolder(): Promise<unknown>;
}

export interface ComputerFolderDirectoryStat {
  readonly relativePath: string;
  readonly bytes: number;
  readonly files: number;
  readonly lastModifiedMs: number;
  readonly inaccessibleCount: number;
}

export interface ComputerFolderObservation {
  readonly schema: typeof COMPUTER_FOLDER_OBSERVATION_SCHEMA;
  readonly status: 'OBSERVED_ONLY';
  readonly source: 'TRUSTED_HOST_PORT';
  readonly rootRef: string;
  readonly scopeRevision: string;
  readonly observedAt: string;
  readonly totalBytes: number;
  readonly directories: readonly ComputerFolderDirectoryStat[];
  readonly rootFiles: Readonly<{ count: number; bytes: number }>;
  readonly localOnly: true;
  readonly externalDisclosures: readonly [];
  readonly executionAuthorized: false;
  readonly limitation: 'METADATA_ONLY_NO_CONTENT_OR_CAUSE';
}

export type ComputerFolderObservationResult =
  | Readonly<{ ok: true; observation: ComputerFolderObservation }>
  | Readonly<{
      ok: false;
      code:
        | 'FOLDER_NOT_SELECTED'
        | 'FOLDER_OBSERVATION_UNAVAILABLE'
        | 'FOLDER_OBSERVATION_INVALID';
    }>;

const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const RESERVED_DOS = /^(con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function exactDataKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  try {
    if (!isRecord(value)) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    return keys.length === expected.length &&
      keys.every((key) =>
        typeof key === 'string' &&
        expected.includes(key) &&
        Object.hasOwn(descriptors[key] ?? {}, 'value') &&
        descriptors[key]?.get === undefined &&
        descriptors[key]?.set === undefined
      );
  } catch {
    return false;
  }
}

function safeRelativePath(value: unknown): value is string {
  // vertical-storage emits one entry per direct child directory of the
  // selected root. Do not accept nested paths or caller-selected descendants.
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 255 &&
    value !== '.' &&
    value !== '..' &&
    !value.startsWith('/') &&
    !value.startsWith('\\') &&
    !/^[a-z]:/i.test(value) &&
    !value.includes('/') &&
    !value.includes('\\') &&
    !/[<>:"|?*]/u.test(value) &&
    !CONTROL_OR_BIDI.test(value) &&
    !RESERVED_DOS.test(value) &&
    !/[. ]$/u.test(value);
}

function nonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function finiteTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER;
}

function safeArrayItems(value: unknown, maximum: number): unknown[] | null {
  try {
    if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    const length = lengthDescriptor?.value;
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0 || length > maximum) return null;
    if (Reflect.ownKeys(value).length !== length + 1) return null;
    const items: unknown[] = [];
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.get !== undefined || descriptor.set !== undefined) return null;
      items.push(descriptor.value);
    }
    return items;
  } catch {
    return null;
  }
}

function canonicalUtc(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

type ParsedHostObservation = Readonly<{
  rootRef: string;
  scopeRevision: string;
  observedAt: string;
  totalBytes: number;
  directories: readonly ComputerFolderDirectoryStat[];
  rootFiles: Readonly<{ count: number; bytes: number }>;
}>;

function parseHostObservation(raw: unknown): ParsedHostObservation | 'NOT_SELECTED' | null {
  try {
    if (!isRecord(raw)) return null;
    if (
      exactDataKeys(raw, ['schema', 'status']) &&
      raw.schema === HOST_FOLDER_OBSERVATION_SCHEMA &&
      raw.status === 'NOT_SELECTED'
    ) return 'NOT_SELECTED';

    if (!exactDataKeys(raw, [
      'schema', 'status', 'rootRef', 'scopeRevision', 'observedAt',
      'totalBytes', 'directories', 'rootFiles',
    ])) return null;
    const directoryItems = safeArrayItems(raw.directories, 256);
    const rootFilesRaw = raw.rootFiles;
    if (
      raw.schema !== HOST_FOLDER_OBSERVATION_SCHEMA ||
      raw.status !== 'OBSERVED_ONLY' ||
      typeof raw.rootRef !== 'string' || !SAFE_REF.test(raw.rootRef) ||
      typeof raw.scopeRevision !== 'string' || !SAFE_REF.test(raw.scopeRevision) ||
      !canonicalUtc(raw.observedAt) ||
      !nonnegativeSafeInteger(raw.totalBytes) ||
      directoryItems === null ||
      !exactDataKeys(rootFilesRaw, ['count', 'bytes']) ||
      !nonnegativeSafeInteger(rootFilesRaw.count) ||
      rootFilesRaw.count > 4096 ||
      !nonnegativeSafeInteger(rootFilesRaw.bytes)
    ) return null;

    const directories: ComputerFolderDirectoryStat[] = [];
    const seen = new Set<string>();
    let aggregateBytes = rootFilesRaw.bytes;
    for (const item of directoryItems) {
      if (!exactDataKeys(item, ['relativePath', 'bytes', 'files', 'lastModifiedMs', 'inaccessibleCount'])) return null;
      if (
        !safeRelativePath(item.relativePath) ||
        !nonnegativeSafeInteger(item.bytes) ||
        !nonnegativeSafeInteger(item.files) ||
        !finiteTimestamp(item.lastModifiedMs) ||
        !nonnegativeSafeInteger(item.inaccessibleCount) ||
        item.files > 1_000_000 ||
        item.inaccessibleCount > 1_000_000
      ) return null;
      const collision = item.relativePath.toLocaleLowerCase('en-US');
      if (seen.has(collision)) return null;
      seen.add(collision);
      aggregateBytes += item.bytes;
      if (!Number.isSafeInteger(aggregateBytes)) return null;
      directories.push({
        relativePath: item.relativePath,
        bytes: item.bytes,
        files: item.files,
        lastModifiedMs: item.lastModifiedMs,
        inaccessibleCount: item.inaccessibleCount,
      });
    }
    if (aggregateBytes !== raw.totalBytes) return null;
    directories.sort((a, b) =>
      a.relativePath.toLocaleLowerCase('en-US').localeCompare(b.relativePath.toLocaleLowerCase('en-US'), 'en-US') ||
      a.relativePath.localeCompare(b.relativePath, 'en-US')
    );

    return {
      rootRef: raw.rootRef,
      scopeRevision: raw.scopeRevision,
      observedAt: raw.observedAt,
      totalBytes: raw.totalBytes,
      directories,
      rootFiles: { count: rootFilesRaw.count, bytes: rootFilesRaw.bytes },
    };
  } catch {
    return null;
  }
}

/**
 * Trusted Host port adapter. It has no path-taking method; the Host must
 * resolve the current user-selected root and enforce vertical-storage scope.
 */
export function createComputerFolderObservationAdapter(host: ComputerFolderObservationHostPort) {
  let observeCurrentSelectedFolder: ComputerFolderObservationHostPort['observeCurrentSelectedFolder'];
  try {
    const rawObserve = host?.observeCurrentSelectedFolder;
    if (typeof rawObserve !== 'function') throw new Error('COMPUTER_FOLDER_HOST_CONFIGURATION_REFUSED');
    observeCurrentSelectedFolder = rawObserve.bind(host);
  } catch {
    throw new TypeError('COMPUTER_FOLDER_HOST_CONFIGURATION_REFUSED');
  }

  return Object.freeze({
    async observeCurrentSelectedFolder(): Promise<ComputerFolderObservationResult> {
      let raw: unknown;
      try {
        raw = await observeCurrentSelectedFolder();
      } catch {
        return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
      }
      let parsed: ParsedHostObservation | 'NOT_SELECTED' | null;
      try {
        parsed = parseHostObservation(raw);
      } catch {
        parsed = null;
      }
      if (parsed === 'NOT_SELECTED') return { ok: false, code: 'FOLDER_NOT_SELECTED' };
      if (!parsed) return { ok: false, code: 'FOLDER_OBSERVATION_INVALID' };
      return deepFreeze({
        ok: true as const,
        observation: deepFreeze({
          schema: COMPUTER_FOLDER_OBSERVATION_SCHEMA,
          status: 'OBSERVED_ONLY',
          source: 'TRUSTED_HOST_PORT',
          ...parsed,
          localOnly: true,
          externalDisclosures: [],
          executionAuthorized: false,
          limitation: 'METADATA_ONLY_NO_CONTENT_OR_CAUSE',
        }),
      });
    },
  });
}
