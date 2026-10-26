// T07 F03 concrete SQLite-backed authorization boundary for ONE authorized
// file mutation (file.copy / file.move / file.rename). Private trusted-host
// seam, NOT a general Windows executor or an authority-file export: this
// class proves the durable gate only — ActionController re-entry
// (grant/plan rehydration + per-effect currentness), the same-local-store
// durable STARTED reservation re-read BEFORE any file effect, and the
// never-replay ledger. The REAL anchored OS mutation (exclusive create /
// no-replace relocation) is a separately reviewed trusted capability the
// host bootstrap injects, exactly as T04 injected the scoped search; no
// Recipe, model, HTTP or plugin code may supply or replace it here.
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { ActionController, StoredGrantRecordSchema } from '@shun/authorization';
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizedAction,
  AuthorizedActionSchema,
  canonicalJson,
  computePlanHash,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import {
  FILE_MUTATION_OPS,
  type FileMutationReconcileDisposition,
  SqliteFileMutationJournal,
} from './sqlite-file-mutation-journal.ts';

/**
 * T07 F04B2a durable-checkpoint capability the boundary hands to the
 * injected trusted mutation capability: `durablePrecommit` persists the
 * immutable pre-effect commitment write-once (with a durable readback) on
 * the SAME local store whose STARTED row is already visible. Structural
 * fail-closed mirror of vertical-files FileMutationCheckpoints — the two
 * declarations must agree.
 */
export type SqliteFileMutationCheckpoints = Readonly<{
  durablePrecommit: (commitment: unknown) => boolean;
}>;

export type SqliteFileMutationGateConfig = Readonly<{
  store: ShunStore;
  controller: ActionController;
  /** Only the trusted host resolves immutable plan bytes by expected hash. */
  loadPlanByHash: (hash: string) => Promise<unknown>;
  /** Trusted anchored mutation capability; never supplied by user/Recipe/model. */
  executeFileMutation: (
    action: AuthorizedAction,
    checkpoints: SqliteFileMutationCheckpoints,
  ) => Promise<unknown>;
}>;

export type FileMutationGateRefusalCode =
  | 'FILE_MUTATION_REFUSED'
  | 'FILE_MUTATION_RECONCILE_REQUIRED';
export type FileMutationGateResult =
  | { ok: true; receipt: ExecutionReceipt }
  | { ok: false; code: FileMutationGateRefusalCode };

function refused(code: FileMutationGateRefusalCode): FileMutationGateResult {
  return { ok: false, code };
}

function sameDir(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

function dirnameOf(path: string): string | null {
  // Canonical fixed-drive spelling ONLY, judged on the raw plan string:
  // backslash separators (a forward slash is refused, never normalized),
  // no empty component (doubled/trailing separators refuse — a collapsing
  // derivation would bind the approved scope to a DIFFERENT lexical parent
  // than the handle-anchored parent the physical bridge opens), and at
  // least one parent directory component. These rules are exactly
  // vertical-files staticPathAdmission; the two derivations must agree so
  // the approved parent and the opened parent are the same directory.
  if (path.length < 3 || path.length > 2048) return null;
  if (path.includes('\u0000') || path.includes('/')) return null;
  if (!/^[a-zA-Z]:\\/.test(path)) return null;
  const components = path.slice(3).split('\\');
  if (components.length < 2) return null;
  if (components.some((component) => component.length === 0)) return null;
  return path.slice(0, path.lastIndexOf('\\'));
}

/**
 * Exact one-mutation-plan identity (mirrors T04's exactR0Search): a single
 * action whose op is one of the three mutation ops, R2, USER, carrying
 * exactly {sourcePath, destinationPath}, whose single read scope is exactly
 * the source parent directory and whose write scope is exactly the
 * destination parent directory (plus the source parent for move/rename,
 * where the entry leaves it), with no network/registry/secret scope at all.
 */
export function exactFileMutationPlan(plan: ActionPlan, action: AuthorizedAction): boolean {
  const [one] = plan.actions;
  if (plan.actions.length !== 1 || one === undefined) return false;
  if (!(FILE_MUTATION_OPS as readonly string[]).includes(one.op)) return false;
  if (plan.capabilityId !== one.op) return false;
  if (
    action.taskId !== plan.taskId ||
    action.planHash !== plan.planHash ||
    action.actionId !== one.actionId ||
    action.policySnapshotRevision !== plan.policySnapshotRevision ||
    canonicalJson(action.action) !== canonicalJson(one)
  )
    return false;
  if (one.sideEffectClass !== 'R2' || one.requiredPrivilege !== 'USER') return false;
  const { sourcePath, destinationPath } = one.parameters as Record<string, unknown>;
  if (
    typeof sourcePath !== 'string' ||
    sourcePath.length === 0 ||
    typeof destinationPath !== 'string' ||
    destinationPath.length === 0 ||
    Object.keys(one.parameters).length !== 2
  )
    return false;
  const sourceDir = dirnameOf(sourcePath);
  const destDir = dirnameOf(destinationPath);
  if (sourceDir === null || destDir === null) return false;
  const scope = one.filesystemScope;
  if (
    scope?.read.length !== 1 ||
    typeof scope.read[0] !== 'string' ||
    !sameDir(scope.read[0], sourceDir)
  )
    return false;
  const expectedWrite =
    one.op === 'file.copy'
      ? [destDir.toLowerCase()]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  const declaredWrite = scope.write;
  if (declaredWrite.length !== expectedWrite.length) return false;
  const declaredSorted = [...declaredWrite].map((d) => d.toLowerCase()).sort();
  if (declaredSorted.some((d, i) => d !== expectedWrite[i])) return false;
  if (
    one.networkScope !== undefined ||
    one.registryScope !== undefined ||
    (one.secretRefs?.length ?? 0) !== 0
  )
    return false;
  return true;
}

/**
 * Does not trust the runner's earlier plan authorization. Rehydrates BOTH the
 * exact immutable plan and the issued HMAC grant from its own SQLite state,
 * checks their identities, re-enters the actual ActionController per-effect
 * gate, then reserves a durable STARTED row on the SAME local store and
 * RE-READS it back before the injected trusted capability may perform any
 * file effect. A second attempt with the same (task, action) identity —
 * whatever happened to the first — is refused reconcile-first; there is no
 * automatic replay path anywhere in this boundary.
 */
export class SqliteFileMutationAuthorizationBoundary {
  private readonly store: ShunStoreAuthorizationAdapter;
  private readonly controller: ActionController;
  private readonly loadPlanByHash: SqliteFileMutationGateConfig['loadPlanByHash'];
  private readonly executeFileMutation: SqliteFileMutationGateConfig['executeFileMutation'];
  private readonly journal: SqliteFileMutationJournal;

  constructor(config: SqliteFileMutationGateConfig) {
    try {
      if (
        !(config?.store instanceof ShunStore) ||
        !(config?.controller instanceof ActionController) ||
        typeof config.loadPlanByHash !== 'function' ||
        typeof config.executeFileMutation !== 'function'
      )
        throw new Error('FILE_MUTATION_BOUNDARY_CONFIGURATION_REFUSED');
      this.store = new ShunStoreAuthorizationAdapter(config.store);
      this.controller = config.controller;
      this.loadPlanByHash = config.loadPlanByHash.bind(config);
      this.executeFileMutation = config.executeFileMutation.bind(config);
      this.journal = new SqliteFileMutationJournal(config.store);
    } catch {
      // The journal's own configuration refusal propagates unchanged.
      throw new Error('FILE_MUTATION_BOUNDARY_CONFIGURATION_REFUSED');
    }
  }

  async execute(presentation: AuthorizedAction): Promise<FileMutationGateResult> {
    try {
      const parsed = AuthorizedActionSchema.safeParse(presentation);
      if (!parsed.success) return refused('FILE_MUTATION_REFUSED');
      const action = parsed.data;
      const [rawGrant, rawPlan] = await Promise.all([
        this.store.get(action.authorizationRef),
        this.loadPlanByHash(action.planHash),
      ]);
      const stored = StoredGrantRecordSchema.safeParse(rawGrant);
      const planRecord = ActionPlanSchema.safeParse(rawPlan);
      if (
        !stored.success ||
        !planRecord.success ||
        stored.data.grantId !== action.authorizationRef ||
        stored.data.grant.grantId !== action.authorizationRef ||
        stored.data.grant.taskId !== action.taskId ||
        stored.data.grant.planHash !== action.planHash ||
        computePlanHash(planRecord.data) !== planRecord.data.planHash ||
        !exactFileMutationPlan(planRecord.data, action)
      )
        return refused('FILE_MUTATION_REFUSED');
      const verdict = await this.controller.authorizeEffect({
        plan: planRecord.data,
        action,
        grant: stored.data.grant,
      });
      if (!verdict.ok) return refused('FILE_MUTATION_REFUSED');

      // Durable pre-effect reservation: refused for ANY prior attempt of this
      // (task, action) identity — reconcile first, never replay.
      const reserved = this.journal.reserve(action);
      if (!reserved.ok)
        return refused(
          reserved.code === 'RECONCILE_REQUIRED'
            ? 'FILE_MUTATION_RECONCILE_REQUIRED'
            : 'FILE_MUTATION_REFUSED',
        );
      // Durable re-read before any IO: the STARTED row must be physically
      // visible through a fresh query against the same fixed-disk store.
      const readback = this.journal.lookup(action);
      if (readback.ok !== true || readback.state !== 'STARTED')
        return refused('FILE_MUTATION_REFUSED');

      // T07 F04B2a: journal-backed durable precommit checkpoints. The
      // trusted mutation capability must persist the immutable commitment
      // (source FileId/volume/size/digest + destination-absence prestate)
      // write-once BEFORE its first create or relocate, and re-observe the
      // source from the same verified handle afterwards; a false/throwing
      // durablePrecommit refuses the effect with zero destination IO. An
      // injected capability that ignores the checkpoints keeps only the
      // F03-era un-checkpointed composition (kept admissible solely so the
      // already-reviewed F03 gate tests stay meaningful); the trusted
      // bootstrap this boundary documents must always consume them.
      const checkpoints: SqliteFileMutationCheckpoints = {
        durablePrecommit: (commitment: unknown) =>
          this.journal.writePrecommit(action, commitment).ok === true,
      };

      let outcome: unknown;
      try {
        outcome = await this.executeFileMutation(action, checkpoints);
      } catch {
        // The trusted effect started and failed mid-flight (the process did
        // not crash): classify the attempt UNKNOWN durably when possible.
        // A true crash leaves STARTED behind, which refuses replay the same
        // way — reconcile first, never auto-replay.
        this.journal.recordOutcome(
          action,
          'UNCERTAIN',
          createHash('sha256')
            .update(canonicalJson({ uncertain: true }))
            .digest('hex'),
        );
        return refused('FILE_MUTATION_REFUSED');
      }
      if (
        outcome !== null &&
        typeof outcome === 'object' &&
        (outcome as { ok?: unknown }).ok === true
      ) {
        const receipt = ExecutionReceiptSchema.safeParse(
          (outcome as { receipt?: unknown }).receipt,
        );
        if (
          receipt.success &&
          receipt.data.terminal === 'SUCCEEDED' &&
          receipt.data.sideEffectEvidence.recoveryClassification === 'COMPLETED_VERIFIED' &&
          receipt.data.sideEffectEvidence.postStateVerified === true
        ) {
          const evidence = createHash('sha256').update(canonicalJson(receipt.data)).digest('hex');
          if (this.journal.recordOutcome(action, 'COMMITTED_VERIFIED', evidence))
            return { ok: true, receipt: receipt.data };
        }
      }
      // Anything else — executor refusal, invalid receipt, journal CAS
      // failure — leaves the attempt conservatively UNKNOWN, unreplayable.
      this.journal.recordOutcome(
        action,
        'UNCERTAIN',
        createHash('sha256')
          .update(canonicalJson({ uncertain: true }))
          .digest('hex'),
      );
      return refused('FILE_MUTATION_REFUSED');
    } catch {
      // A caller cannot distinguish corrupt policy/grant, file names, secrets
      // or backend failures; conservatively refuse.
      return refused('FILE_MUTATION_REFUSED');
    }
  }
}

// ---------------------------------------------------------------------------
// T07 F04B2c trusted reconcile glue.
// ---------------------------------------------------------------------------

/** The verdict vocabulary of the independent OS poststate verifier
 * (vertical-files file-mutation-poststate.ts), mirrored fail-closed. */
export type FileMutationPoststateVerdict =
  | 'PROVEN_COMPLETED'
  | 'CONSISTENT_WITH_COMPLETION'
  | 'PROVEN_NOT_EXECUTED'
  | 'CONSISTENT_WITH_NOT_EXECUTED'
  | 'UNKNOWN';

export type FileMutationReconcileResult =
  | {
      ok: true;
      disposition: FileMutationReconcileDisposition;
      automaticRetryAllowed: false;
      evidenceSha256: string;
    }
  | { ok: false; code: 'RECONCILE_REFUSED' };

function refusedReconcile(): FileMutationReconcileResult {
  return { ok: false, code: 'RECONCILE_REFUSED' };
}

const POSTSTATE_VERDICTS: readonly FileMutationPoststateVerdict[] = [
  'PROVEN_COMPLETED',
  'CONSISTENT_WITH_COMPLETION',
  'PROVEN_NOT_EXECUTED',
  'CONSISTENT_WITH_NOT_EXECUTED',
  'UNKNOWN',
];

/**
 * T07 F04B2c: the private trusted reconciler. It JOINS facts it re-reads
 * itself — the durable journal row for the exact (task, action) identity and
 * the immutable F04B2a precommitment — with the fixed trusted OS verifier
 * the host bootstrap injects (vertical-files observeFileMutationPoststate),
 * and persists the resulting disposition atomically and idempotently.
 *
 * It NEVER accepts a caller boolean, NEVER rewrites the journal row's
 * STARTED/UNCERTAIN/COMMITTED_VERIFIED state, NEVER issues a grant, and
 * NEVER authorizes a retry: automaticRetryAllowed is structurally false for
 * every disposition (the reconcile table CHECK pins it to 0). A reconcile
 * verdict is an analysis of what the world already looks like, not an
 * execution. Caller-supplied labels (F04A advisory included) are not inputs
 * here at all.
 */
export class SqliteFileMutationReconciler {
  private readonly journal: SqliteFileMutationJournal;
  private readonly verifyPoststate: (precommit: unknown) => Promise<unknown> | unknown;

  constructor(config: {
    store: ShunStore;
    /** Trusted read-only OS verifier; never supplied by user/Recipe/model. */
    verifyPoststate: (precommit: unknown) => Promise<unknown> | unknown;
  }) {
    try {
      if (!(config?.store instanceof ShunStore) || typeof config.verifyPoststate !== 'function')
        throw new Error('FILE_MUTATION_RECONCILER_CONFIGURATION_REFUSED');
      this.journal = new SqliteFileMutationJournal(config.store);
      this.verifyPoststate = config.verifyPoststate.bind(config);
    } catch {
      throw new Error('FILE_MUTATION_RECONCILER_CONFIGURATION_REFUSED');
    }
  }

  async reconcile(presentation: AuthorizedAction): Promise<FileMutationReconcileResult> {
    try {
      const parsed = AuthorizedActionSchema.safeParse(presentation);
      if (!parsed.success) return refusedReconcile();
      const action = parsed.data;
      const row = this.journal.lookup(action);
      // Only interrupted attempts are reconcilable: STARTED (hard crash) or
      // UNCERTAIN (surviving-process failure). A COMMITTED_VERIFIED or
      // absent/corrupt row has nothing for this reconciler to add.
      if (row.ok !== true || (row.state !== 'STARTED' && row.state !== 'UNCERTAIN'))
        return refusedReconcile();
      const precommit = this.journal.readPrecommit(action);
      if (precommit.ok !== true) return refusedReconcile();

      const observed = await this.verifyPoststate(precommit.commitment);
      if (
        observed === null ||
        typeof observed !== 'object' ||
        Array.isArray(observed) ||
        types.isProxy(observed) ||
        Object.getPrototypeOf(observed) !== Object.prototype
      )
        return refusedReconcile();
      const result = observed as Record<string, unknown>;
      if (result.ok !== true) {
        // The trusted verifier could not observe (drive absent, alias,
        // bounds, malformed precommit...): persist nothing — a later
        // reconcile may succeed — and surface refusal, never a verdict.
        return refusedReconcile();
      }
      if (
        Reflect.ownKeys(result).length !== 3 ||
        !Object.hasOwn(result, 'verdict') ||
        !Object.hasOwn(result, 'evidence') ||
        typeof result.verdict !== 'string' ||
        !POSTSTATE_VERDICTS.includes(result.verdict as FileMutationPoststateVerdict) ||
        result.evidence === null ||
        typeof result.evidence !== 'object'
      )
        return refusedReconcile();
      const verdict = result.verdict as FileMutationPoststateVerdict;
      const disposition: FileMutationReconcileDisposition =
        verdict === 'PROVEN_COMPLETED'
          ? 'COMPLETED_PROVEN'
          : verdict === 'CONSISTENT_WITH_COMPLETION'
            ? 'COMPLETED_CONSISTENT'
            : verdict === 'PROVEN_NOT_EXECUTED'
              ? 'NOT_EXECUTED_PROVEN'
              : verdict === 'CONSISTENT_WITH_NOT_EXECUTED'
                ? 'NOT_EXECUTED_CONSISTENT'
                : 'MANUAL_RECONCILE_REQUIRED';
      const evidenceSha256 = createHash('sha256').update(canonicalJson(result)).digest('hex');
      if (!this.journal.recordReconcileDisposition(action, disposition, evidenceSha256))
        return refusedReconcile();
      return { ok: true, disposition, automaticRetryAllowed: false, evidenceSha256 };
    } catch {
      return refusedReconcile();
    }
  }
}
