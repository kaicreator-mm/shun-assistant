/**
 * R04 U05-A — private, task-bound folder selection and metadata observation.
 * Absolute paths remain inside this Host module and SQLite; no OS user identity is persisted.
 */
import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, realpathSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { basename, dirname, posix, resolve, win32 } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  type ObservationEvidence,
  observeStorage,
  type ResolvedScope,
  resolveScope,
} from '@shun/vertical-storage';
import {
  type ComputerFolderObservationResult,
  createComputerFolderObservationAdapter,
  HOST_FOLDER_OBSERVATION_SCHEMA,
} from '../../../../packages/domain-computer/src/computer/folder-observation.ts';
import type {
  GuidedDecisionReceipt,
  HostGuidedService,
} from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  type FolderPickerNativePort,
  loadFolderPicker,
  type NativeDirectoryLease,
  type NativeFolderSelection,
} from '../../native/folder-picker/index.ts';

const SELECTION_REF = /^host:folder:[a-f0-9]{64}$/;
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
  volume TEXT NOT NULL,
  volume_serial TEXT NOT NULL,
  file_id TEXT NOT NULL,
  expires_at_unix_ms INTEGER NOT NULL,
  created_at_unix_ms INTEGER NOT NULL
)`;

type FolderIdentity = Readonly<{ volumeSerial: string; fileId: string }>;
type DirectoryIdentity = FolderIdentity &
  Readonly<{
    isDirectory: boolean;
    isReparsePoint: boolean;
    isNetworkPath: boolean;
    isVolumeRoot: boolean;
  }>;
type SelectionRow = {
  selection_ref: string;
  path: string;
  display_name: string;
  task_id: string;
  journey_id: string;
  case_ref_json: string;
  origin_step_id: string;
  template_digest: string;
  volume: string;
  volume_serial: string;
  file_id: string;
  expires_at_unix_ms: number;
  created_at_unix_ms: number;
};

export interface FolderSelectionStoragePort {
  resolveScope(volume: string, declared: { roots: readonly string[] }): Promise<ResolvedScope>;
  observeStorage(scope: ResolvedScope, clock: () => string): Promise<ObservationEvidence>;
}
export type FolderSelectionResult =
  | {
      readonly status: 'SELECTED';
      readonly selectionRef: string;
      readonly displayName: string;
      readonly expiresAtUnixMs: number;
    }
  | { readonly status: 'CANCELLED' }
  | { readonly status: 'STALE' | 'REFUSED'; readonly code: string };

export type FolderSelectionRecoveryResult =
  | { readonly status: 'RECOVERED'; readonly selectionRef: string; readonly stagedStepId: string }
  | { readonly status: 'NOT_APPLICABLE' }
  | { readonly status: 'STALE' | 'REFUSED'; readonly code: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
function safeDisplayName(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 160 &&
    value !== '.' &&
    value !== '..' &&
    !value.startsWith(' ') &&
    !value.endsWith(' ') &&
    !value.endsWith('.') &&
    !/[\\/:*?"<>|]/u.test(value) &&
    // biome-ignore lint/suspicious/noControlCharactersInRegex: control/bidi characters are exactly what this fail-closed filter rejects
    !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value) &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value)
  );
}
function safeLocalDirectoryPath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 4 || value.length > 32767) return false;
  // The production factory and native loader both refuse non-Windows hosts.
  // Allow an absolute POSIX path only for the lower-level mocked Host tests
  // that exercise Guided restart semantics in Linux CI.
  if (process.platform !== 'win32') {
    return (
      value.startsWith('/') &&
      posix.isAbsolute(value) &&
      posix.normalize(value) === value &&
      !value.split('/').includes('..')
    );
  }
  if (value.startsWith('\\\\') || value.startsWith('\\\\?\\') || value.startsWith('\\\\.\\'))
    return false;
  if (!/^[A-Za-z]:\\/.test(value) || !win32.isAbsolute(value)) return false;
  if (value.split(/[\\\\/]/).includes('..')) return false;
  const normalized = win32.normalize(value);
  if (normalized.toLowerCase() !== value.toLowerCase()) return false;
  const root = win32.parse(value).root;
  return (
    root.length > 0 &&
    value.replace(/[\\\\]+$/g, '').toLowerCase() !== root.replace(/[\\\\]+$/g, '').toLowerCase()
  );
}
function validIdentity(value: unknown): value is FolderIdentity {
  return (
    isRecord(value) &&
    typeof value.volumeSerial === 'string' &&
    HEX_ID.test(value.volumeSerial) &&
    typeof value.fileId === 'string' &&
    HEX_ID.test(value.fileId)
  );
}
function validDirectoryIdentity(value: unknown): value is DirectoryIdentity {
  return (
    validIdentity(value) &&
    isRecord(value) &&
    typeof value.isDirectory === 'boolean' &&
    typeof value.isReparsePoint === 'boolean' &&
    typeof value.isNetworkPath === 'boolean' &&
    typeof value.isVolumeRoot === 'boolean'
  );
}
function sameDirectoryIdentity(
  expected: Pick<SelectionRow, 'volume_serial' | 'file_id'>,
  directory: DirectoryIdentity,
): boolean {
  return (
    directory.volumeSerial.toLowerCase() === expected.volume_serial.toLowerCase() &&
    directory.fileId.toLowerCase() === expected.file_id.toLowerCase() &&
    directory.isDirectory &&
    !directory.isReparsePoint &&
    !directory.isNetworkPath &&
    !directory.isVolumeRoot
  );
}
function extractSelectionAnswer(raw: unknown): string | null {
  if (
    !isRecord(raw) ||
    raw.decision !== 'ANSWER' ||
    !isRecord(raw.outcome) ||
    raw.outcome.event !== 'USER_SUBMIT' ||
    raw.outcome.source !== 'USER' ||
    !Array.isArray(raw.outcome.answers) ||
    raw.outcome.answers.length !== 1
  )
    return null;
  const answer = raw.outcome.answers[0];
  return isRecord(answer) &&
    answer.fieldId === 'selectedRoot' &&
    typeof answer.value === 'string' &&
    SELECTION_REF.test(answer.value)
    ? answer.value
    : null;
}

/** Same binding rules as `extractSelectionAnswer`, for the durable accepted
 * answer envelope read back through the guided service's trusted readback. */
function selectionRefFromRecordedAnswer(answer: unknown): string | null {
  if (
    !isRecord(answer) ||
    answer.event !== 'USER_SUBMIT' ||
    answer.source !== 'USER' ||
    !Array.isArray(answer.answers) ||
    answer.answers.length !== 1
  )
    return null;
  const answerItem = answer.answers[0];
  return isRecord(answerItem) &&
    answerItem.fieldId === 'selectedRoot' &&
    typeof answerItem.value === 'string' &&
    SELECTION_REF.test(answerItem.value)
    ? answerItem.value
    : null;
}

export class FolderSelectionHost {
  readonly #guided: HostGuidedService;
  readonly #native: FolderPickerNativePort;
  readonly #db: DatabaseSync;
  readonly #clock: () => number;
  readonly #storage: FolderSelectionStoragePort;
  readonly #observationAdapter: ReturnType<typeof createComputerFolderObservationAdapter>;
  /** One modal picker at a time: the async dialog must not overlap itself. */
  #pickInFlight = false;
  /**
   * Best-effort native directory lease held during one observation. The
   * metadata walk remains path-based and can race with namespace changes;
   * this lease is defense-in-depth, not an atomic scan guarantee.
   */
  #observationLease: NativeDirectoryLease | null = null;  #observationLease: NativeDirectoryLease | null = null;

  constructor(input: {
    readonly guided: HostGuidedService;
    readonly databaseFile: string;
    readonly native: FolderPickerNativePort;
    readonly clock?: () => number;
    readonly storage?: FolderSelectionStoragePort;
  }) {
    if (
      typeof input.databaseFile !== 'string' ||
      !input.databaseFile ||
      input.databaseFile === ':memory:' ||
      (!win32.isAbsolute(input.databaseFile) && !input.databaseFile.startsWith('/')) ||
      !input.native ||
      typeof input.native.pickFolder !== 'function' ||
      typeof input.native.inspectFolder !== 'function' ||
      typeof input.native.acquireDirectoryLease !== 'function' ||
      typeof input.native.verifyDirectoryLease !== 'function' ||
      typeof input.native.releaseDirectoryLease !== 'function' ||
      typeof input.native.directoryLeasePath !== 'function'
    ) {
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
    if (
      !context ||
      context.state !== 'CURRENT' ||
      context.step.templateRef.artifactId !== 'shun.guided.select-root' ||
      state.currentStep?.stepId !== context.step.stepId
    ) {
      return { status: 'STALE', code: 'GUIDED_SELECT_ROOT_NOT_CURRENT' };
    }
    if (this.#pickInFlight) {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_PICK_IN_PROGRESS' };
    }
    this.#pickInFlight = true;
    let picked: NativeFolderSelection;
    try {
      // The frozen async contract: the modal Shell dialog runs on a dedicated
      // COM STA worker. The Node main event loop stays free while it is open,
      // so concurrent route calls must be refused instead of stacked.
      try {
        picked = await this.#native.pickFolder();
      } catch {
        return { status: 'REFUSED', code: 'FOLDER_PICKER_UNAVAILABLE' };
      }
    } finally {
      this.#pickInFlight = false;
    }
    if (picked.status === 'CANCELLED') return { status: 'CANCELLED' };
    if (
      picked.status !== 'SELECTED' ||
      !safeLocalDirectoryPath(picked.path) ||
      !safeDisplayName(picked.displayName) ||
      !validIdentity(picked.identity)
    ) {
      return {
        status: 'REFUSED',
        code: picked.status === 'REFUSED' ? picked.code : 'FOLDER_PICKER_RESULT_INVALID',
      };
    }
    let directory: ReturnType<FolderPickerNativePort['inspectFolder']>;
    try {
      directory = this.#native.inspectFolder(picked.path);
    } catch {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_IDENTITY_UNAVAILABLE' };
    }
    if (
      !validDirectoryIdentity(directory) ||
      !sameDirectoryIdentity(
        {
          volume_serial: picked.identity.volumeSerial,
          file_id: picked.identity.fileId,
        } as Pick<SelectionRow, 'volume_serial' | 'file_id'>,
        directory,
      )
    ) {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_IDENTITY_REFUSED' };
    }

    const now = this.#clock();
    const expiresAtUnixMs = now + MAX_TTL_MS;
    const selectionRef = `host:folder:${randomBytes(32).toString('hex')}`;
    const volume =
      process.platform === 'win32'
        ? win32.parse(picked.path).root.slice(0, 2)
        : posix.parse(picked.path).root;
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#db
        .prepare(
          'INSERT INTO folder_selection_records (' +
            'selection_ref,path,display_name,task_id,journey_id,case_ref_json,' +
            'origin_step_id,template_digest,volume,volume_serial,file_id,' +
            'expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        )
        .run(
          selectionRef,
          picked.path,
          picked.displayName,
          context.step.taskId,
          context.step.journeyId,
          stableJson(context.step.caseRef),
          context.step.stepId,
          context.step.templateRef.digest,
          volume,
          picked.identity.volumeSerial,
          picked.identity.fileId,
          expiresAtUnixMs,
          now,
        );
      this.#db.exec('COMMIT');
    } catch {
      this.#db.exec('ROLLBACK');
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_LEDGER_WRITE_REFUSED' };
    }
    return { status: 'SELECTED', selectionRef, displayName: picked.displayName, expiresAtUnixMs };
  }

  validateSelectionAnswer(
    raw: unknown,
    step: {
      readonly stepId: string;
      readonly taskId: string;
      readonly journeyId: string;
      readonly caseRef: unknown;
      readonly templateRef: { readonly digest: string; readonly artifactId: string };
    },
  ): GuidedDecisionReceipt | null {
    if (
      !isRecord(raw) ||
      raw.decision !== 'ANSWER' ||
      !isRecord(raw.outcome) ||
      raw.outcome.event !== 'USER_SUBMIT'
    )
      return null;
    if (step.templateRef.artifactId !== 'shun.guided.select-root') {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_STEP_REFUSED' };
    }
    const selectionRef = extractSelectionAnswer(raw);
    if (!selectionRef) return { status: 'REFUSED', code: 'FOLDER_SELECTION_REQUIRED' };
    const row = this.#selectionRow(selectionRef);
    if (!row) return { status: 'REFUSED', code: 'FOLDER_SELECTION_UNKNOWN' };
    const now = this.#clock();
    if (row.expires_at_unix_ms <= now) return { status: 'STALE', code: 'FOLDER_SELECTION_EXPIRED' };
    if (
      row.task_id !== step.taskId ||
      row.journey_id !== step.journeyId ||
      row.case_ref_json !== stableJson(step.caseRef) ||
      row.origin_step_id !== step.stepId ||
      row.template_digest !== step.templateRef.digest ||
      raw.stepId !== step.stepId ||
      raw.stepDigest !== step.templateRef.digest ||
      stableJson(raw.caseRef) !== stableJson(step.caseRef)
    ) {
      return { status: 'STALE', code: 'FOLDER_SELECTION_STEP_BINDING_MISMATCH' };
    }
    return this.#verifySelectionIdentity(row)
      ? null
      : { status: 'STALE', code: 'FOLDER_SELECTION_IDENTITY_DRIFT' };
  }

  afterSelectionRecorded(
    raw: unknown,
    step: {
      readonly stepId: string;
      readonly taskId: string;
      readonly journeyId: string;
      readonly caseRef: unknown;
      readonly templateRef: { readonly digest: string; readonly artifactId: string };
    },
    receipt: GuidedDecisionReceipt,
  ): GuidedDecisionReceipt {
    if (receipt.status !== 'RECORDED') return receipt;
    const selectionRef = extractSelectionAnswer(raw);
    const row = selectionRef ? this.#selectionRow(selectionRef) : undefined;
    if (
      !selectionRef ||
      !row ||
      !this.#verifySelectionIdentity(row) ||
      row.expires_at_unix_ms <= this.#clock() ||
      row.task_id !== step.taskId ||
      row.journey_id !== step.journeyId ||
      row.case_ref_json !== stableJson(step.caseRef) ||
      row.origin_step_id !== step.stepId ||
      row.template_digest !== step.templateRef.digest
    ) {
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

  /**
   * P1-02 explicit startup recovery for the crash window in which the
   * durable select-root USER_SUBMIT answer is committed (guided state is
   * CONSUMED on the select-root step) but the next INSPECT step was never
   * staged. Host-only: this method is never exposed through any route.
   *
   * It re-reads the exact accepted answer from the guided ledger and the
   * exact selection row, then verifies expiry, task/journey/Case/origin
   * step/template-digest binding and native root identity before re-invoking
   * the existing Host-only
   * `stageTrustedSelectedRoot()`. Stale, expired or mismatched rows remain
   * refused/stale — recovery never extends a TTL, restages a consumed
   * answer silently or issues any authority.
   */
  recoverInterruptedSelection(): FolderSelectionRecoveryResult {
    const context = this.#guided.readTrustedContext();
    if (
      !context ||
      context.state !== 'CONSUMED' ||
      context.step.templateRef.artifactId !== 'shun.guided.select-root'
    ) {
      return { status: 'NOT_APPLICABLE' };
    }
    const step = context.step;
    const answer = this.#guided.readRecordedAnswer(step.stepId);
    const selectionRef = selectionRefFromRecordedAnswer(answer);
    if (!selectionRef) {
      return { status: 'REFUSED', code: 'FOLDER_SELECTION_RECOVERY_ANSWER_UNPROVEN' };
    }
    const row = this.#selectionRow(selectionRef);
    if (!row) return { status: 'REFUSED', code: 'FOLDER_SELECTION_UNKNOWN' };
    if (row.expires_at_unix_ms <= this.#clock()) {
      return { status: 'STALE', code: 'FOLDER_SELECTION_EXPIRED' };
    }
    if (
      row.task_id !== step.taskId ||
      row.journey_id !== step.journeyId ||
      row.case_ref_json !== stableJson(step.caseRef) ||
      row.origin_step_id !== step.stepId ||
      row.template_digest !== step.templateRef.digest
    ) {
      return { status: 'STALE', code: 'FOLDER_SELECTION_STEP_BINDING_MISMATCH' };
    }
    if (!this.#verifySelectionIdentity(row)) {
      return { status: 'STALE', code: 'FOLDER_SELECTION_IDENTITY_DRIFT' };
    }
    const staged = this.#guided.stageTrustedSelectedRoot({
      selectionRef,
      expiresAtUnixMs: row.expires_at_unix_ms,
    });
    if (staged.status !== 'CURRENT') {
      return { status: 'REFUSED', code: `GUIDED_SELECTED_ROOT_RECOVERY_REFUSED:${staged.code}` };
    }
    return { status: 'RECOVERED', selectionRef, stagedStepId: staged.step.stepId };
  }

  async observeCurrentSelectedFolder(): Promise<ComputerFolderObservationResult> {
    const binding = this.#captureObservationBinding();
    if (!binding) return { ok: false, code: 'FOLDER_NOT_SELECTED' };
    const row = this.#selectionRow(binding.selectionRef);
    if (!row || !this.#rowMatchesObservationBinding(row, binding)) {
      return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
    }

    // Defense-in-depth: acquire a reparse-free native directory lease before
    // the path-based metadata walk and recheck the root identity afterwards.
    // This does NOT make readdir/resolveScope/observeStorage handle-relative
    // or atomic; a transient path replacement during that walk remains an
    // Owner-accepted v0.3.0 residual risk.
    let lease: NativeDirectoryLease;
    try {
      lease = this.#native.acquireDirectoryLease(row.path);
    } catch {
      return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
    }
    try {
      if (!this.#leaseMatchesRow(lease, row) || !this.#verifySelectionIdentity(row)) {
        return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
      }
      this.#observationLease = lease;
      let result: ComputerFolderObservationResult;
      try {
        result = await this.#observationAdapter.observeCurrentSelectedFolder();
      } finally {
        this.#observationLease = null;
      }
      if (!result.ok) return result;

      // The metadata scan is asynchronous. Re-read the exact live INSPECT
      // binding, the persisted row and BOTH native identities (pinned handle
      // + recorded path) immediately before the Host-owned
      // OBSERVATION_RECEIPT transition. A stale scan can never consume a
      // newer Case/step or a replaced directory.
      const latestRow = this.#selectionRow(binding.selectionRef);
      if (
        !this.#sameObservationBinding(binding) ||
        !latestRow ||
        !this.#rowMatchesObservationBinding(latestRow, binding) ||
        !this.#verifyLeaseAgainstRow(lease, latestRow) ||
        !this.#verifySelectionIdentity(latestRow)
      ) {
        return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
      }
      const receipt = this.#guided.recordHostObservationReceipt();
      if (receipt.status !== 'RECORDED') {
        return { ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' };
      }
      return result;
    } finally {
      try {
        this.#native.releaseDirectoryLease(lease);
      } catch {
        // Cleanup is best-effort; the observation outcome is already decided.
      }
    }
  }

  #leaseMatchesRow(lease: NativeDirectoryLease, row: SelectionRow): boolean {
    return (
      validDirectoryIdentity(lease.directory) &&
      sameDirectoryIdentity(row, lease.directory)
    );
  }

  #verifyLeaseAgainstRow(lease: NativeDirectoryLease, row: SelectionRow): boolean {
    try {
      const directory = this.#native.verifyDirectoryLease(lease);
      return validDirectoryIdentity(directory) && sameDirectoryIdentity(row, directory);
    } catch {
      return false;
    }
  }

  #selectionRow(selectionRef: string): SelectionRow | undefined {
    return this.#db
      .prepare(
        `SELECT selection_ref,path,display_name,task_id,journey_id,case_ref_json,
        origin_step_id,template_digest,volume,volume_serial,file_id,
        expires_at_unix_ms,created_at_unix_ms
       FROM folder_selection_records WHERE selection_ref=?`,
      )
      .get(selectionRef) as SelectionRow | undefined;
  }

  #verifySelectionIdentity(row: SelectionRow): boolean {
    if (row.expires_at_unix_ms <= this.#clock()) return false;
    try {
      const directory = this.#native.inspectFolder(row.path);
      return validDirectoryIdentity(directory) && sameDirectoryIdentity(row, directory);
    } catch {
      return false;
    }
  }

  async #observeRaw(): Promise<unknown> {
    const binding = this.#captureObservationBinding();
    if (!binding) return { schema: HOST_FOLDER_OBSERVATION_SCHEMA, status: 'NOT_SELECTED' };
    const row = this.#selectionRow(binding.selectionRef);
    if (
      !row ||
      !this.#rowMatchesObservationBinding(row, binding) ||
      !this.#verifySelectionIdentity(row)
    ) {
      throw new Error('FOLDER_SELECTION_IDENTITY_DRIFT');
    }
    // Use the native lease's current canonical path as a best-effort locator.
    // The subsequent metadata APIs still resolve a path string; replacement
    // between this call and any descendant open is an accepted residual risk.
    const lease = this.#observationLease;
    if (!lease) throw new Error('FOLDER_SELECTION_LEASE_UNAVAILABLE');
    let leasePath: string;
    try {
      leasePath = this.#native.directoryLeasePath(lease);
    } catch {
      throw new Error('FOLDER_SELECTION_LEASE_UNAVAILABLE');
    }
    const rootEntries = await readdir(leasePath, { withFileTypes: true });
    const rootDirectories = rootEntries.filter((entry) => entry.isDirectory()).length;
    const rootFiles = rootEntries.length - rootDirectories;
    if (rootDirectories > MAX_DIRECTORIES || rootFiles > MAX_ROOT_FILES) {
      throw new Error('FOLDER_OBSERVATION_OVERFLOW');
    }
    const scope = await this.#storage.resolveScope(row.volume, { roots: [leasePath] });
    const evidence = await this.#storage.observeStorage(scope, () =>
      new Date(this.#clock()).toISOString(),
    );
    if (
      evidence.directories.length > MAX_DIRECTORIES ||
      evidence.rootFiles.length > MAX_ROOT_FILES
    ) {
      throw new Error('FOLDER_OBSERVATION_OVERFLOW');
    }
    const rootBytes = evidence.rootFiles.reduce((sum, item) => sum + item.bytes, 0);
    if (!Number.isSafeInteger(rootBytes) || !Number.isSafeInteger(evidence.totalBytes)) {
      throw new Error('FOLDER_OBSERVATION_INVALID');
    }

    // Revalidate after the complete async walk as well as immediately before
    // recording its receipt. This rejects a step/Case switch, expiry or root
    // replacement that occurred while resolveScope/observeStorage was pending.
    const latestRow = this.#selectionRow(binding.selectionRef);
    if (
      !this.#sameObservationBinding(binding) ||
      !latestRow ||
      !this.#rowMatchesObservationBinding(latestRow, binding) ||
      !this.#verifySelectionIdentity(latestRow)
    ) {
      throw new Error('FOLDER_OBSERVATION_BINDING_CHANGED');
    }

    const observedAt = evidence.observedAt;
    const directories = evidence.directories
      .map((directory) => ({
        relativePath: win32.basename(directory.path),
        bytes: directory.bytes,
        files: directory.files,
        lastModifiedMs: directory.lastModifiedMs,
        inaccessibleCount: directory.inaccessibleEntries.length,
      }))
      .sort(
        (a, b) =>
          a.relativePath
            .toLocaleLowerCase('en-US')
            .localeCompare(b.relativePath.toLocaleLowerCase('en-US'), 'en-US') ||
          a.relativePath.localeCompare(b.relativePath, 'en-US'),
      );
    const rootFileMetadata = evidence.rootFiles
      .map((item) => ({
        name: win32.basename(item.path),
        bytes: item.bytes,
      }))
      .sort(
        (a, b) =>
          a.name
            .toLocaleLowerCase('en-US')
            .localeCompare(b.name.toLocaleLowerCase('en-US'), 'en-US') ||
          a.name.localeCompare(b.name, 'en-US'),
      );
    const revisionDigest = createHash('sha256')
      .update(
        stableJson({
          selectionRef: binding.selectionRef,
          observedAt,
          totalBytes: evidence.totalBytes,
          directories,
          rootFiles: rootFileMetadata,
        }),
        'utf8',
      )
      .digest('hex');
    return {
      schema: HOST_FOLDER_OBSERVATION_SCHEMA,
      status: 'OBSERVED_ONLY',
      rootRef: binding.selectionRef,
      scopeRevision: `folder-scope-${revisionDigest.slice(0, 32)}`,
      observedAt,
      totalBytes: evidence.totalBytes,
      directories,
      rootFiles: { count: evidence.rootFiles.length, bytes: rootBytes },
    };
  }

  #captureObservationBinding(): Readonly<{
    stepId: string;
    taskId: string;
    journeyId: string;
    caseRefJson: string;
    templateDigest: string;
    selectionRef: string;
  }> | null {
    const context = this.#guided.readTrustedContext();
    const current = this.#guided.state().currentStep;
    if (
      !context ||
      context.state !== 'CURRENT' ||
      !current ||
      current.stepId !== context.step.stepId ||
      context.step.templateRef.artifactId !== 'shun.guided.inspect-scope' ||
      !isRecord(context.observation) ||
      typeof context.observation.selectedRootRef !== 'string' ||
      !SELECTION_REF.test(context.observation.selectedRootRef)
    )
      return null;
    return {
      stepId: context.step.stepId,
      taskId: context.step.taskId,
      journeyId: context.step.journeyId,
      caseRefJson: stableJson(context.step.caseRef),
      templateDigest: context.step.templateRef.digest,
      selectionRef: context.observation.selectedRootRef,
    };
  }

  #sameObservationBinding(
    binding: Readonly<{
      stepId: string;
      taskId: string;
      journeyId: string;
      caseRefJson: string;
      templateDigest: string;
      selectionRef: string;
    }>,
  ): boolean {
    const context = this.#guided.readTrustedContext();
    const current = this.#guided.state().currentStep;
    return (
      !!context &&
      context.state === 'CURRENT' &&
      !!current &&
      context.step.templateRef.artifactId === 'shun.guided.inspect-scope' &&
      context.step.stepId === binding.stepId &&
      current.stepId === binding.stepId &&
      context.step.taskId === binding.taskId &&
      current.taskId === binding.taskId &&
      context.step.journeyId === binding.journeyId &&
      current.journeyId === binding.journeyId &&
      stableJson(context.step.caseRef) === binding.caseRefJson &&
      stableJson(current.caseRef) === binding.caseRefJson &&
      context.step.templateRef.digest === binding.templateDigest &&
      current.templateRef.digest === binding.templateDigest &&
      isRecord(context.observation) &&
      context.observation.selectedRootRef === binding.selectionRef
    );
  }

  #rowMatchesObservationBinding(
    row: SelectionRow,
    binding: Readonly<{
      taskId: string;
      journeyId: string;
      caseRefJson: string;
      selectionRef: string;
    }>,
  ): boolean {
    return (
      row.selection_ref === binding.selectionRef &&
      row.task_id === binding.taskId &&
      row.journey_id === binding.journeyId &&
      row.case_ref_json === binding.caseRefJson &&
      row.expires_at_unix_ms > this.#clock()
    );
  }

  close(): void {
    this.#db.close();
  }

  #initializeLedger(): void {
    const objects = this.#db
      .prepare("SELECT name, type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
      .all() as unknown as { name: string; type: string }[];
    if (objects.length === 0) {
      this.#db.exec(SELECTION_DDL);
      return;
    }
    if (
      objects.length !== 1 ||
      objects[0]?.name !== 'folder_selection_records' ||
      objects[0]?.type !== 'table'
    )
      throw new Error('FOLDER_SELECTION_LEDGER_SCHEMA_REFUSED');
    const columns = this.#db
      .prepare('PRAGMA table_info(folder_selection_records)')
      .all() as unknown as { name: string }[];
    const actual = columns.map((column) => column.name);
    const current = [
      'selection_ref', 'path', 'display_name', 'task_id', 'journey_id',
      'case_ref_json', 'origin_step_id', 'template_digest', 'volume',
      'volume_serial', 'file_id', 'expires_at_unix_ms', 'created_at_unix_ms',
    ];
    if (actual.join('|') === current.join('|')) return;

    const legacy = [
      'selection_ref', 'path', 'display_name', 'task_id', 'journey_id',
      'case_ref_json', 'origin_step_id', 'template_digest', 'user_sid',
      'logon_sid', 'session_id', 'volume', 'volume_serial', 'file_id',
      'expires_at_unix_ms', 'created_at_unix_ms',
    ];
    if (actual.join('|') !== legacy.join('|')) {
      throw new Error('FOLDER_SELECTION_LEDGER_SCHEMA_REFUSED');
    }

    // Remove obsolete SID/session columns without losing valid per-account
    // selections. This migration is transactional; identity authorization
    // fields are deliberately not copied into the device-scoped schema.
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#db.exec('ALTER TABLE folder_selection_records RENAME TO folder_selection_records_legacy');
      this.#db.exec(SELECTION_DDL);
      this.#db.prepare('INSERT INTO folder_selection_records (selection_ref,path,display_name,task_id,journey_id,case_ref_json,origin_step_id,template_digest,volume,volume_serial,file_id,expires_at_unix_ms,created_at_unix_ms) SELECT selection_ref,path,display_name,task_id,journey_id,case_ref_json,origin_step_id,template_digest,volume,volume_serial,file_id,expires_at_unix_ms,created_at_unix_ms FROM folder_selection_records_legacy').run();
      this.#db.exec('DROP TABLE folder_selection_records_legacy');
      this.#db.exec('COMMIT');
    } catch {
      try { this.#db.exec('ROLLBACK'); } catch { /* retain the original failure */ }
      throw new Error('FOLDER_SELECTION_LEDGER_MIGRATION_REFUSED');
    }
  }
}

/**
 * The folder-selection SQLite ledger is per-Windows-account LocalAppData
 * state. Refuse lexical escapes, pre-existing junction/symlink escapes and
 * paths whose actual filesystem target cannot be resolved. ProgramData
 * contamination is refused before LocalAppData containment checks. The
 * validation-to-SQLite-open race remains an accepted residual risk.
 */
export function folderSelectionDatabaseRefusal(databaseFile: unknown): string | null {
  if (process.platform !== 'win32') return 'FOLDER_SELECTION_DATABASE_NOT_WINDOWS';
  if (typeof databaseFile !== 'string' || databaseFile.length === 0) {
    return 'FOLDER_SELECTION_DATABASE_PATH_REQUIRED';
  }
  const localAppData = process.env.LOCALAPPDATA;
  if (typeof localAppData !== 'string' || localAppData.length === 0) {
    return 'FOLDER_SELECTION_DATABASE_LOCALAPPDATA_REQUIRED';
  }
  if (databaseFile.startsWith('\\\\') || localAppData.startsWith('\\\\')) {
    return 'FOLDER_SELECTION_DATABASE_PATH_INVALID';
  }
  const base = resolve(localAppData);
  const target = resolve(databaseFile);
  const programData = process.env.ProgramData;
  // Case-folded, trailing-separator-free lexical Windows comparison.
  const fold = (value: string): string =>
    win32
      .normalize(value)
      .replace(/[\\]+$/g, '')
      .toLowerCase();
  const within = (root: string, value: string): boolean => {
    const rootFolded = fold(root);
    const valueFolded = fold(value);
    return valueFolded === rootFolded || valueFolded.startsWith(rootFolded + '\\');
  };
  const strictlyInside = (root: string, value: string): boolean =>
    fold(value).startsWith(fold(root) + '\\');

  // ProgramData refusal comes first, both lexically and against the resolved
  // LocalAppData root: a ProgramData target (or a LocalAppData redirected
  // into ProgramData) is refused as ProgramData regardless of any other
  // boundary outcome, and no parent-resolution detail leaks first.
  if (typeof programData === 'string' && programData.length > 0) {
    const programDataRoot = resolve(programData);
    if (within(programDataRoot, base) || within(programDataRoot, target)) {
      return 'FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED';
    }
  }
  if (!strictlyInside(base, target)) {
    return 'FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA';
  }

  // Resolve the actual filesystem target, not just its spelling. The parent
  // must exist because SQLite cannot create missing parent directories.
  let realBase: string;
  let realParent: string;
  let realTarget: string;
  let realProgramData: string | null = null;
  try {
    realBase = realpathSync.native(base);
  } catch {
    return 'FOLDER_SELECTION_DATABASE_LOCALAPPDATA_UNRESOLVED';
  }
  if (typeof programData === 'string' && programData.length > 0) {
    try {
      realProgramData = realpathSync.native(resolve(programData));
    } catch {
      return 'FOLDER_SELECTION_DATABASE_PROGRAMDATA_UNVERIFIABLE';
    }
    if (within(realProgramData, realBase)) {
      return 'FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED';
    }
  }
  try {
    realParent = realpathSync.native(dirname(target));
  } catch {
    return 'FOLDER_SELECTION_DATABASE_PARENT_UNAVAILABLE';
  }
  if (!within(realBase, realParent)) {
    return 'FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA';
  }
  if (realProgramData !== null && within(realProgramData, realParent)) {
    return 'FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED';
  }
  try {
    lstatSync(target);
    try {
      realTarget = realpathSync.native(target);
    } catch {
      // A dangling link or inaccessible existing target is not equivalent
      // to a new database file; do not fall back to the lexical path.
      return 'FOLDER_SELECTION_DATABASE_PATH_UNVERIFIABLE';
    }
  } catch (error) {
    const code =
      typeof error === 'object' && error !== null && 'code' in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code !== 'ENOENT') return 'FOLDER_SELECTION_DATABASE_PATH_UNVERIFIABLE';
    realTarget = win32.join(realParent, basename(target));
  }
  if (realProgramData !== null && within(realProgramData, realTarget)) {
    return 'FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED';
  }
  if (!strictlyInside(realBase, realTarget)) {
    return 'FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA';
  }
  return null;
}

export function createProductionFolderSelectionHost(input: {
  readonly guided: HostGuidedService;
  readonly databaseFile: string;
  readonly clock?: () => number;
}): FolderSelectionHost {
  const native = loadFolderPicker();
  // Best-effort defense-in-depth: resolve the current parent through a
  // reparse-free native directory lease before checking LocalAppData
  // containment. DatabaseSync still opens by path, so this does NOT make the
  // check/open pair atomic; a replacement race remains an Owner-accepted
  // v0.3.0 residual risk.
  const resolvedDatabaseFile = resolve(input.databaseFile);
  const parentDirectory = dirname(resolvedDatabaseFile);
  let guard: NativeDirectoryLease | undefined;
  try {
    guard = native.acquireDirectoryLease(parentDirectory);
    const canonicalParent = native.directoryLeasePath(guard);
    const canonicalDatabaseFile = win32.join(canonicalParent, basename(resolvedDatabaseFile));
    const refusal = folderSelectionDatabaseRefusal(canonicalDatabaseFile);
    if (refusal) throw new Error(refusal);
    return new FolderSelectionHost({
      ...input,
      databaseFile: canonicalDatabaseFile,
      native,
    });
  } finally {
    if (guard) {
      try {
        native.releaseDirectoryLease(guard);
      } catch {
        // Cleanup is best-effort; the factory outcome is already decided.
      }
    }
  }
}

export type FolderSelectionHostPort = Pick<
  FolderSelectionHost,
  | 'selectRoot'
  | 'validateSelectionAnswer'
  | 'afterSelectionRecorded'
  | 'observeCurrentSelectedFolder'
>;
