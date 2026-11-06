/**
 * R04 U05-A — private, task-bound folder selection and metadata observation.
 * Absolute paths and OS identity remain inside this Host module and SQLite.
 */
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { basename, resolve, win32 } from 'node:path';
import { readdir } from 'node:fs/promises';
import {
  HOST_FOLDER_OBSERVATION_SCHEMA,
  createComputerFolderObservationAdapter,
  type ComputerFolderObservationResult,
} from '../../../../packages/domain-computer/src/computer/folder-observation.ts';
import type { HostGuidedService, GuidedDecisionReceipt } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { observeStorage, resolveScope, type ObservationEvidence, type ResolvedScope } from '@shun/vertical-storage';
import { loadFolderPicker, type FolderPickerNativePort } from '../../native/folder-picker/index.ts';

const SELECTION_REF = /^host:folder:[a-f0-9]{64}$/;
const SID = /^S-1-[0-9-]+$/;
const HEX_ID = /^[a-f0-9]{1,32}$/i;
const MAX_TTL_MS = 5 * 60_000;
const MAX_DIRECTORIES = 256;
const MAX_ROOT_FILES = 4096;
const SELECTION_DDL = `CREATE TABLE folder_selection_records (
  selection_ref TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  display_name TEXT NOT NULL,
  task_id TEXT NOT NULL,
  journey_id TEXT NOT NULL,
  case_ref_json TEXT NOT NULL,
  origin_step_id TEXT NOT NULL,
  template_digest TEXT NOT NULL,
  user_sid TEXT NOT NULL,
  logon_sid TEXT NOT NULL,
  session_id INTEGER NOT NULL,
  volume TEXT NOT NULL,
  volume_serial TEXT NOT NULL,
  file_id TEXT NOT NULL,
  expires_at_unix_ms INTEGER NOT NULL,
  created_at_unix_ms INTEGER NOT NULL
)`;

type FolderIdentity = Readonly<{
  userSid: string; logonSid: string; sessionId: number;
  volumeSerial: string; fileId: string;
}>;
type DirectoryIdentity = FolderIdentity & Readonly<{
  isDirectory: boolean; isReparsePoint: boolean;
  isNetworkPath: boolean; isVolumeRoot: boolean;
}>;
type SelectionRow = {
  selection_ref: string; path: string; display_name: string;
  task_id: string; journey_id: string; case_ref_json: string;
  origin_step_id: string; template_digest: string;
  user_sid: string; logon_sid: string; session_id: number;
  volume: string; volume_serial: string; file_id: string;
  expires_at_unix_ms: number; created_at_unix_ms: number;
};

export interface FolderSelectionStoragePort {
  resolveScope(volume: string, declared: { roots: readonly string[] }): Promise<ResolvedScope>;
  observeStorage(scope: ResolvedScope, clock: () => string): Promise<ObservationEvidence>;
}
export type FolderSelectionResult =
  | { readonly status: 'SELECTED'; readonly selectionRef: string; readonly displayName: string; readonly expiresAtUnixMs: number }
  | { readonly status: 'CANCELLED' }
  | { readonly status: 'STALE' | 'REFUSED'; readonly code: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function safeDisplayName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 160 &&
    value !== '.' && value !== '..' && !value.startsWith(' ') && !value.endsWith(' ') &&
    !value.endsWith('.') && !/[\\\\/:*?"<>|]/u.test(value) &&
    !/[\\u0000-\\u001f\\u007f-\\u009f\\u202a-\\u202e\\u2066-\\u2069]/u.test(value) &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\\.|$)/i.test(value);
}
function safeLocalDirectoryPath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 4 || value.length > 32767) return false;
  if (value.startsWith('\\\\') || value.startsWith('\\\\?\\') || value.startsWith('\\\\.\\')) return false;
  if (!/^[A-Za-z]:\\/.test(value) || !win32.isAbsolute(value)) return false;
  if (value.split(/[\\\\/]/).includes('..')) return false;
  const normalized = win32.normalize(value);
  if (normalized.toLowerCase() !== value.toLowerCase()) return false;
  const root = win32.parse(value).root;
  return root.length > 0 &&
    value.replace(/[\\\\]+$/g, '').toLowerCase() !== root.replace(/[\\\\]+$/g, '').toLowerCase();
}
function validIdentity(value: unknown): value is FolderIdentity {
  if (!isRecord(value)) return false;
  return typeof value.userSid === 'string' && SID.test(value.userSid) &&
    typeof value.logonSid === 'string' && SID.test(value.logonSid) &&
    Number.isSafeInteger(value.sessionId) && (value.sessionId as number) > 0 &&
    typeof value.volumeSerial === 'string' && HEX_ID.test(value.volumeSerial) &&
    typeof value.fileId === 'string' && HEX_ID.test(value.fileId);
}
function sameIdentity(expected: SelectionRow, user: FolderIdentity, directory: DirectoryIdentity): boolean {
  return user.userSid === expected.user_sid && user.logonSid === expected.logon_sid &&
    user.sessionId === expected.session_id && directory.userSid === expected.user_sid &&
    directory.logonSid === expected.logon_sid && directory.sessionId === expected.session_id &&
    directory.volumeSerial.toLowerCase() === expected.volume_serial.toLowerCase() &&
    directory.fileId.toLowerCase() === expected.file_id.toLowerCase() &&
    directory.isDirectory && !directory.isReparsePoint &&
    !directory.isNetworkPath && !directory.isVolumeRoot;
}
function extractSelectionAnswer(raw: unknown): string | null {
  if (!isRecord(raw) || raw.decision !== 'ANSWER' || !isRecord(raw.outcome) ||
      raw.outcome.event !== 'USER_SUBMIT' || raw.outcome.source !== 'USER' ||
      !Array.isArray(raw.outcome.answers) || raw.outcome.answers.length !== 1) return null;
  const answer = raw.outcome.answers[0];
  return isRecord(answer) && answer.fieldId === 'selectedRoot' &&
    typeof answer.value === 'string' && SELECTION_REF.test(answer.value) ? answer.value : null;
}

export class FolderSelectionHost {
  readonly #guided: HostGuidedService;
  readonly #native: FolderPickerNativePort;
  readonly #db: DatabaseSync;
  readonly #clock: () => number;
  readonly #storage: FolderSelectionStoragePort;
  readonly #observationAdapter: ReturnType<typeof createComputerFolderObservationAdapter>;

  constructor(input: {
    readonly guided: HostGuidedService;
    readonly databaseFile: string;
    readonly native: FolderPickerNativePort;
    readonly clock?: () => number;
    readonly storage?: FolderSelectionStoragePort;
  }) {
    if (!input || !input.guided || typeof input.databaseFile !== 'string' ||
        !input.databaseFile || input.databaseFile === ':memory:' ||
        (!win32.isAbsolute(input.databaseFile) && !input.databaseFile.startsWith('/')) ||
        !input.native || typeof input.native.selectFolder !== 'function' ||
        typeof input.native.currentIdentity !== 'function' ||
        typeof input.native.inspectDirectory !== 'function') {
      throw new TypeError('FOLDER_SELECTION_HOST_CONFIG_REQUIRED');
    }
    this.#guided = input.guided;
    this.#native = input.native;
    this.#clock = input.clock ?? Date.now;
    this.#storage = input.storage ?? { resolveScope, observeStorage };
    this.#db = new DatabaseSync(resolve(input.databaseFile));
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#initializeLedger();
    this.#observationAdapter = createComputerFolderObservationAdapter({
      observeCurrentSelectedFolder: () => this.#observeRaw(),
    });
  }

  #initializeLedger(): void {
    const objects = this.#db.prepare(
      "SELECT name, type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    ).all() as unknown as { name: string; type: string }[];
    if (objects.length === 0) {
      this.#db.exec(SELECTION_DDL);
      return;
    }
    if (objects.length !== 1 || objects[0]?.name !== 'folder_selection_records' ||
        objects[0]?.type !== 'table') throw new Error('FOLDER_SELECTION_LEDGER_SCHEMA_REFUSED');
    const columns = this.#db.prepare('PRAGMA table_info(folder_selection_records)').all() as
      unknown as { name: string }[];
    const expected = [
      'selection_ref','path','display_name','task_id','journey_id','case_ref_json',
      'origin_step_id','template_digest','user_sid','logon_sid','session_id','volume',
      'volume_serial','file_id','expires_at_unix_ms','created_at_unix_ms',
    ];
    if (columns.map((column) => column.name).join('|') !== expected.join('|')) {
      throw new Error('FOLDER_SELECTION_LEDGER_SCHEMA_REFUSED');
    }
  }
