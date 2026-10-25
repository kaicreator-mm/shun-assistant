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
import { FILE_MUTATION_OPS, SqliteFileMutationJournal } from './sqlite-file-mutation-journal.ts';

export type SqliteFileMutationGateConfig = Readonly<{
  store: ShunStore;
  controller: ActionController;
  /** Only the trusted host resolves immutable plan bytes by expected hash. */
  loadPlanByHash: (hash: string) => Promise<unknown>;
  /** Trusted anchored mutation capability; never supplied by user/Recipe/model. */
  executeFileMutation: (action: AuthorizedAction) => Promise<unknown>;
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
  const cut = path.lastIndexOf('\\');
  if (cut <= 2) return null;
  return path.slice(0, cut);
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

      let outcome: unknown;
      try {
        outcome = await this.executeFileMutation(action);
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
