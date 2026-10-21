// T04 concrete SQLite-backed authorization boundary for one R0 file.search.
// This is a private trusted-host seam, NOT a general Windows executor or an
// authority-file export. An actual host-owned read-only effect implementation
// and its Windows physical confinement evidence remain separate requirements.
import { ActionController, StoredGrantRecordSchema } from '@shun/authorization';
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizedAction,
  AuthorizedActionSchema,
  canonicalJson,
  computePlanHash,
} from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';

export type SqliteReadonlySearchGateConfig = Readonly<{
  store: ShunStore;
  controller: ActionController;
  /** Only the trusted host resolves immutable plan bytes by expected hash. */
  loadPlanByHash: (hash: string) => Promise<unknown>;
  /** Trusted effect operation; never supplied by user/Recipe/model. */
  executeScopedSearch: (action: AuthorizedAction) => Promise<unknown>;
}>;

function exactR0Search(plan: ActionPlan, action: AuthorizedAction): boolean {
  const [one] = plan.actions;
  return (
    plan.capabilityId === 'file.search' &&
    plan.actions.length === 1 &&
    one !== undefined &&
    action.taskId === plan.taskId &&
    action.planHash === plan.planHash &&
    action.actionId === one.actionId &&
    action.policySnapshotRevision === plan.policySnapshotRevision &&
    canonicalJson(action.action) === canonicalJson(one) &&
    one.op === 'file.search' &&
    one.sideEffectClass === 'R0' &&
    one.requiredPrivilege === 'USER' &&
    typeof one.parameters.root === 'string' &&
    one.parameters.root.length > 0 &&
    typeof one.parameters.query === 'string' &&
    one.parameters.query.length > 0 &&
    Object.keys(one.parameters).length === 2 &&
    one.filesystemScope?.read.length === 1 &&
    one.filesystemScope.read[0] === one.parameters.root &&
    one.filesystemScope.write.length === 0 &&
    one.networkScope === undefined &&
    one.registryScope === undefined &&
    (one.secretRefs?.length ?? 0) === 0
  );
}

/**
 * Does not trust the runner's earlier plan authorization. Rehydrates BOTH
 * exact immutable plan and issued grant from its own SQLite state, checks
 * their identities, then re-enters the actual ActionController immediately
 * before delegating a restricted read-only effect.
 *
 * This avoids copying SQLite HMAC grants to forgeable file anchors.
 * Cross-process/restart deduplication and journal remain a later T04 gate.
 */
export class SqliteReadonlySearchAuthorizationBoundary {
  private readonly store: ShunStoreAuthorizationAdapter;
  private readonly controller: ActionController;
  private readonly loadPlanByHash: SqliteReadonlySearchGateConfig['loadPlanByHash'];
  private readonly executeScopedSearch: SqliteReadonlySearchGateConfig['executeScopedSearch'];

  constructor(config: SqliteReadonlySearchGateConfig) {
    try {
      if (
        !(config?.store instanceof ShunStore) ||
        !(config?.controller instanceof ActionController) ||
        typeof config.loadPlanByHash !== 'function' ||
        typeof config.executeScopedSearch !== 'function'
      )
        throw new Error('RECIPE_BOUNDARY_CONFIGURATION_REFUSED');
      this.store = new ShunStoreAuthorizationAdapter(config.store);
      this.controller = config.controller;
      this.loadPlanByHash = config.loadPlanByHash.bind(config);
      this.executeScopedSearch = config.executeScopedSearch.bind(config);
    } catch {
      throw new Error('RECIPE_BOUNDARY_CONFIGURATION_REFUSED');
    }
  }

  async execute(presentation: AuthorizedAction): Promise<unknown> {
    try {
      const parsed = AuthorizedActionSchema.safeParse(presentation);
      if (!parsed.success) throw new Error('RECIPE_EFFECT_BOUNDARY_REFUSED');
      const action = parsed.data;
      if (action.authorizationKind === 'EXPLICIT_APPROVAL') {
        // The controller independently confirms this route's provenance.
      }
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
        !exactR0Search(planRecord.data, action)
      )
        throw new Error('RECIPE_EFFECT_BOUNDARY_REFUSED');
      const verdict = await this.controller.authorizeEffect({
        plan: planRecord.data,
        action,
        grant: stored.data.grant,
      });
      if (!verdict.ok) throw new Error('RECIPE_EFFECT_BOUNDARY_REFUSED');
      // No exposed grant, HMAC, plan cache, direct file-anchor write or shell.
      // The REAL OS read-only operation is intentionally still an injected
      // host-owned capability; this class proves the durable gate only.
      return await this.executeScopedSearch(action);
    } catch {
      // A caller cannot distinguish corrupt policy/grant, file names, secrets
      // or backend failures; the runner conservatively returns UNKNOWN.
      throw new Error('RECIPE_EFFECT_BOUNDARY_REFUSED');
    }
  }
}
