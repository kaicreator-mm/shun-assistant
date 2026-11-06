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

type UserIdentity = Readonly<{ userSid: string; logonSid: string; sessionId: number }>;
type FolderIdentity = UserIdentity & Readonly<{ volumeSerial: string; fileId: string }>;
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
function validUserIdentity(value: unknown): value is UserIdentity {
  return isRecord(value) && typeof value.userSid === 'string' && SID.test(value.userSid) &&
    typeof value.logonSid === 'string' && SID.test(value.logonSid) &&
    Number.isSafeInteger(value.sessionId) && (value.sessionId as number) > 0;
}
function validIdentity(value: unknown): value is FolderIdentity {
  return validUserIdentity(value) && typeof (value as Record<string, unknown>).volumeSerial === 'string' &&
    HEX_ID.test((value as Record<string, string>).volumeSerial) &&
    typeof (value as Record<string, unknown>).fileId === 'string' &&
    HEX_ID.test((value as Record<string, string>).fileId);
}
function sameIdentity(expected: SelectionRow, user: UserIdentity, directory: DirectoryIdentity): boolean {
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


  async selectRoot(): Promise<FolderSelectionResult> {
    const state = this.#guided.state();
    const context = this.#guided.readTrustedContext();
    if (!context || context.state !== 'CURRENT' ||
        context.step.templateRef.artifactId !== 'shun.guided.select-root' ||
        state.currentStep?.stepId !== context.step.stepId) {
      return { status: 'STALE', code: 'GUIDED_SELECT_ROOT_NOT_CURRENT' };
    }
    let picked: ReturnType<FolderPickerNativePort['selectFolder']>;
    try {
      picked = this.#native.selectFolder();
    } catch {
      return { status: 'REFUSED', code: 'FOLDER_PICKER_UNAVAILABLE' };
    }
    if (picked.status === 'CANCELLED') return { status: 'CANCELLED' };
    if (picked.status !== 'SELECTED' || !safeLocalDirectoryPath(picked.path) ||
        !safeDisplayName(picked.displayName) || !validIdentity(picked.identity)) {
      return { status: 'REFUSED', code: picked.status === 'REFUSED' ? picked.code : 'FOLDER_PICKER_RESULT_INVALID' };
    }
    const currentUser = this.#native.currentIdentity();
    const directory = this.#native.inspectDirectory(picked.path);
    if (!validUserIdentity(currentUser) || !isRecord(directory) ||
        !sameIdentity({
          user_sid: picked.identity.userSid,
          logon_sid: picked.identity.logonSid,
          session_id: picked.identity.sessionId,
          volume_serial: picked.identity.volumeSerial,
          file_id: picked.identity.fileId,
        } as SelectionRow, currentUser, directory as DirectoryIdentity)) {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_IDENTITY_REFUSED' };
    }
    if (
      currentUser.userSid !== picked.identity.userSid ||
      currentUser.logonSid !== picked.identity.logonSid ||
      currentUser.sessionId !== picked.identity.sessionId
    ) return { status: 'REFUSED', code: 'FOLDER_SELECTION_SESSION_MISMATCH' };

    const now = this.#clock();
    const expiresAtUnixMs = now + MAX_TTL_MS;
    const selectionRef = `host:folder:${randomBytes(32).toString('hex')}`;
    const volume = win32.parse(picked.path).root.slice(0, 2);
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#db.prepare(`INSERT INTO folder_selection_records (
        selection_ref,path,display_name,task_id,journey_id,case_ref_json,
        origin_step_id,template_digest,user_sid,logon_sid,session_id,volume,
        volume_serial,file_id,expires_at_unix_ms,created_at_unix_ms
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        selectionRef, picked.path, picked.displayName, context.step.taskId,
        context.step.journeyId, stableJson(context.step.caseRef), context.step.stepId,
        context.step.templateRef.digest, picked.identity.userSid, picked.identity.logonSid,
        picked.identity.sessionId, volume, picked.identity.volumeSerial,
        picked.identity.fileId, expiresAtUnixMs, now,
      );
      this.#db.exec('COMMIT');
    } catch {
      this.#db.exec('ROLLBACK');
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_LEDGER_WRITE_REFUSED' };
    }
    return { status: 'SELECTED', selectionRef, displayName: picked.displayName, expiresAtUnixMs };
  }

  validateSelectionAnswer(raw: unknown, step: {
    readonly stepId: string; readonly taskId: string; readonly journeyId: string;
    readonly caseRef: unknown; readonly templateRef: { readonly digest: string; readonly artifactId: string };
  }): GuidedDecisionReceipt | null {
    if (!isRecord(raw) || raw.decision !== 'ANSWER' ||
        !isRecord(raw.outcome) || raw.outcome.event !== 'USER_SUBMIT') return null;
    if (step.templateRef.artifactId !== 'shun.guided.select-root') {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_STEP_REFUSED' };
    }
    const selectionRef = extractSelectionAnswer(raw);
    if (!selectionRef) return { status: 'REFUSED', code: 'FOLDER_SELECTION_REQUIRED' };
    const row = this.#selectionRow(selectionRef);
    if (!row) return { status: 'REFUSED', code: 'FOLDER_SELECTION_UNKNOWN' };
    const now = this.#clock();
    if (row.expires_at_unix_ms <= now) return { status: 'STALE', code: 'FOLDER_SELECTION_EXPIRED' };
    if (row.task_id !== step.taskId || row.journey_id !== step.journeyId ||
        row.case_ref_json !== stableJson(step.caseRef) || row.origin_step_id !== step.stepId ||
        row.template_digest !== step.templateRef.digest ||
        raw.stepId !== step.stepId || raw.stepDigest !== step.templateRef.digest ||
        stableJson(raw.caseRef) !== stableJson(step.caseRef)) {
      return { status: 'STALE', code: 'FOLDER_SELECTION_STEP_BINDING_MISMATCH' };
    }
    return this.#verifySelectionIdentity(row)
      ? null
      : { status: 'STALE', code: 'FOLDER_SELECTION_IDENTITY_DRIFT' };
  }

  afterSelectionRecorded(raw: unknown, step: {
    readonly stepId: string; readonly taskId: string; readonly journeyId: string;
    readonly caseRef: unknown; readonly templateRef: { readonly digest: string; readonly artifactId: string };
  }, receipt: GuidedDecisionReceipt): GuidedDecisionReceipt {
    if (receipt.status !== 'RECORDED') return receipt;
    const selectionRef = extractSelectionAnswer(raw);
    const row = selectionRef ? this.#selectionRow(selectionRef) : undefined;
    if (!selectionRef || !row || !this.#verifySelectionIdentity(row) ||
        row.expires_at_unix_ms <= this.#clock() ||
        row.task_id !== step.taskId || row.journey_id !== step.journeyId ||
        row.case_ref_json !== stableJson(step.caseRef) || row.origin_step_id !== step.stepId ||
        row.template_digest !== step.templateRef.digest) {
      return { status: 'UNKNOWN', code: 'FOLDER_SELECTION_POST_DECISION_RECHECK_FAILED' };
    }
    const staged = this.#guided.stageTrustedSelectedRoot({
      selectionRef,
      expiresAtUnixMs: row.expires_at_unix_ms,
    });
    return staged.status === 'CURRENT'
      ? receipt
      : { status: 'UNKNOWN', code: `GUIDED_SELECTED_ROOT_STAGE_FAILED:${staged.code}` };
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
