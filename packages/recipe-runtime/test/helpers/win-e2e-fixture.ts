// T04 Windows host E2E shared fixture: real file-backed ShunStore, real
// AuthorizationAuthority/ActionController with an ACTIVE single-R0 policy,
// real persisted literal Recipe candidate. Used by the E2E suite and by the
// separately spawned hard-kill child (via node --experimental-strip-types).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import {
  type ActionPlan,
  type AuthorizedAction,
  computePlanHash,
  type ExecutionReceipt,
} from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import {
  createSqliteAuthorizedRecipeEffectHost,
  createSqliteRecipeReadService,
  type SqliteAuthorizedRecipeEffectHostOptions,
  type SqliteRecipeHostOptions,
} from '../../src/index.ts';
import {
  executeTrustedWindowsR0Search,
  type R0SearchEffectEvidence,
} from '../../src/trusted-windows-r0-effect.ts';

export const FIXTURE = {
  recipeId: 'e2e-recipe-1',
  contractRevision: 'contract-1',
  verifierId: 'verifier-1',
  verifierRevision: '1',
  registryRevision: 'registry-1',
  policyRevision: 'policy-1',
  scopeRevision: 'scope-1',
  authorityId: 'auth-e2e-1',
  authorityRevision: 'rev-e2e-1',
  integritySecret: 'e2e-integrity-fixture-secret',
  issuanceSecret: 'e2e-issuance-fixture-secret',
  now: '2026-10-24T00:00:00.000Z',
} as const;

export type FixtureTree = Readonly<{ rootForward: string; rootNative: string }>;

export type HostFixtureIdentity = Readonly<{
  taskId: string;
  recipeId: string;
  revisionSha256: string;
}>;

/** A small deterministic read scope: two top-level, two nested matches. */
export function createFixtureTree(prefix: string): FixtureTree & { dispose: () => void } {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  const rootNative = join(dir, 'scope');
  mkdirSync(join(rootNative, 'notes'), { recursive: true });
  writeFileSync(join(rootNative, 'a.txt'), 'alpha\n');
  writeFileSync(join(rootNative, 'b.txt'), 'bravo\n');
  writeFileSync(join(rootNative, 'skip.log'), 'ignore\n');
  writeFileSync(join(rootNative, 'notes', 'also.txt'), 'charlie\n');
  writeFileSync(join(rootNative, 'notes', 'keep.txt'), 'delta\n');
  return {
    rootNative,
    rootForward: rootNative.split('\\').join('/'),
    dispose: () => rmSync(dir, { recursive: true, force: true }),
  };
}

export function recipeSourceFor(rootForward: string, query = '*.txt'): string {
  return `export default defineRecipe({"nodes":[{"actionId":"read","op":"file.search","parameters":{"root":"${rootForward}","query":"${query}"}}],"edges":[]});`;
}

export function expectedMatches(): string[] {
  return ['a.txt', 'b.txt', join('notes', 'also.txt'), join('notes', 'keep.txt')].sort();
}

/** REAL controller/authority stack over one store; policy must exist first. */
export function buildAuthorityStack(store: ShunStore): {
  adapter: ShunStoreAuthorizationAdapter;
  controller: ActionController;
} {
  const adapter = new ShunStoreAuthorizationAdapter(store);
  const issuer = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: FIXTURE.integritySecret,
    issuanceSecret: FIXTURE.issuanceSecret,
    clock: () => FIXTURE.now,
  });
  const controller = new ActionController({
    authority: issuer,
    policyState: adapter,
    approvals: {
      requestApproval: async () => {
        throw new Error('approval must be unreachable for the R0 USER fixture policy');
      },
    },
    issuanceSecret: FIXTURE.issuanceSecret,
    clock: () => FIXTURE.now,
  });
  return { adapter, controller };
}

/** Activates the frozen single-R0-USER file.search policy for the scope. */
export async function activatePolicy(
  adapter: ShunStoreAuthorizationAdapter,
  scopeRead: readonly string[],
): Promise<void> {
  await adapter.saveAuthorityRecord({
    authorityId: FIXTURE.authorityId,
    authorityRevision: FIXTURE.authorityRevision,
    updatedAt: FIXTURE.now,
    policyInitialized: true,
  });
  await adapter.savePolicySnapshot({
    policySnapshotRevision: FIXTURE.policyRevision,
    status: 'ACTIVE',
    authorityId: FIXTURE.authorityId,
    authorityRevision: FIXTURE.authorityRevision,
    revokedGrantIds: [],
    rules: [
      {
        ruleId: 'allow-single-R0-search',
        capabilityId: 'file.search',
        op: 'file.search',
        maxRiskClass: 'R0',
        privilegeLevel: 'USER',
        filesystem: { read: [...scopeRead], write: [] },
      },
    ],
    riskGuards: [],
    updatedAt: FIXTURE.now,
  });
}

/** Trusted-host currentness from the persisted recipe revision identity. */
export function buildCurrentness(store: ShunStore): SqliteRecipeHostOptions['currentness'] {
  return (taskId, recipeId) => {
    const rows = store.database
      .prepare('SELECT revision_sha256, payload FROM recipe_revisions_v02 WHERE recipe_id = ?')
      .all(recipeId) as Array<{ revision_sha256: string; payload: string }>;
    const row = rows.at(-1);
    if (!row) return { kind: 'UNRESOLVABLE' as const };
    const identity = (
      JSON.parse(row.payload) as {
        identity: {
          revisionSha256: string;
          actionGraphSha256: string;
          compilerRevision: string;
          contractRevision: string;
          verifierId: string;
          verifierRevision: string;
        };
      }
    ).identity;
    if (identity.revisionSha256 !== row.revision_sha256) return { kind: 'UNRESOLVABLE' as const };
    return {
      kind: 'CURRENT' as const,
      taskId,
      recipeId,
      revisionSha256: identity.revisionSha256,
      actionGraphSha256: identity.actionGraphSha256,
      compilerRevision: identity.compilerRevision,
      contractRevision: identity.contractRevision,
      verifierId: identity.verifierId,
      verifierRevision: identity.verifierRevision,
      registryRevision: FIXTURE.registryRevision,
      policyRevision: FIXTURE.policyRevision,
      scopeRevision: FIXTURE.scopeRevision,
      revocationEpoch: 0,
      capability: 'PREVIEW_RECIPE' as const,
    };
  };
}

/** Trusted host plan derivation from the exact persisted recipe revision. */
export function buildLoadExpectedPlan(
  rootForward: string,
  query = '*.txt',
): SqliteRecipeHostOptions['loadExpectedPlan'] {
  return ({ taskId, recipeId, revisionSha256 }) => {
    const plan: ActionPlan = {
      taskId,
      capabilityId: 'file.search',
      bindingRefs: ['binding-e2e-1'],
      recipeRef: `${recipeId}@${revisionSha256}`,
      rankingPolicyRevision: 'rank-e2e-1',
      policySnapshotRevision: FIXTURE.policyRevision,
      actions: [
        {
          actionId: 'read',
          bindingRef: 'binding-e2e-1',
          op: 'file.search',
          parameters: { root: rootForward, query },
          sideEffectClass: 'R0',
          requiredPrivilege: 'USER',
          filesystemScope: { read: [rootForward], write: [] },
        },
      ],
      verificationPlan: {
        verifierId: FIXTURE.verifierId,
        verifierRevision: FIXTURE.verifierRevision,
        checks: [{ checkId: 'r0-search-complete' }],
      },
      recoveryPlan: {
        classificationStrategy: 'JOURNAL_AND_POST_STATE',
        reconcileBeforeRetry: true,
        retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
      },
      planHash: 'a'.repeat(64),
    };
    plan.planHash = computePlanHash(plan);
    return plan;
  };
}

export type HostFixture = Awaited<ReturnType<typeof makeHostFixture>>;

/**
 * Full real host fixture: file-backed SQLite store, ACTIVE policy, persisted
 * literal recipe, and the trusted composition whose executeScopedSearch runs
 * the verified native effect while recording host-side evidence. `scans()`
 * counts effect dispatches; the journal never re-dispatches a reserved row.
 */
export async function makeHostFixture(prefix: string, query = '*.txt') {
  const tree = createFixtureTree(prefix);
  const dbPath = join(
    tmpdir(),
    `${prefix}-db-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`,
  );
  const store = new ShunStore({ file: dbPath });
  const { adapter, controller } = buildAuthorityStack(store);
  await activatePolicy(adapter, [tree.rootForward]);
  const source = recipeSourceFor(tree.rootForward, query);
  const recipeOptions: Omit<
    SqliteAuthorizedRecipeEffectHostOptions,
    'loadPlanByHash' | 'executeScopedSearch'
  > = {
    store,
    controller,
    currentness: buildCurrentness(store),
    loadExpectedPlan: buildLoadExpectedPlan(tree.rootForward, query),
  };
  const service = createSqliteRecipeReadService(recipeOptions);
  const saved = service.registerLiteral(source, {
    recipeId: FIXTURE.recipeId,
    contractRevision: FIXTURE.contractRevision,
    verifierId: FIXTURE.verifierId,
    verifierRevision: FIXTURE.verifierRevision,
  });
  if (!saved.ok) throw new Error(`fixture register failed: ${JSON.stringify(saved)}`);
  const identity = {
    taskId: `task-${prefix}`,
    recipeId: saved.recipeId,
    revisionSha256: saved.revisionSha256,
  };

  let scans = 0;
  let lastReceipt: ExecutionReceipt | null = null;
  let lastAction: AuthorizedAction | null = null;
  let lastEvidence: R0SearchEffectEvidence | null = null;

  const compose = () => {
    const preview = service.previewExact(identity);
    if (!preview.ok) throw new Error('fixture preview failed');
    const plan = recipeOptions.loadExpectedPlan({
      ...identity,
      actionGraphSha256: preview.actionGraphSha256,
    }) as ActionPlan;
    return {
      plan,
      host: createSqliteAuthorizedRecipeEffectHost({
        ...recipeOptions,
        loadPlanByHash: async (hash) => (hash === plan.planHash ? plan : null),
        executeScopedSearch: async (action) => {
          scans++;
          const receipt = await executeTrustedWindowsR0Search(action, (e) => {
            lastEvidence = e;
          });
          lastReceipt = receipt;
          lastAction = action;
          return receipt;
        },
      }),
    };
  };

  const dispose = async () => {
    await store.close();
    rmSync(dbPath, { force: true });
    rmSync(`${dbPath}-wal`, { force: true });
    rmSync(`${dbPath}-shm`, { force: true });
    tree.dispose();
  };

  return {
    tree,
    dbPath,
    store,
    adapter,
    service,
    identity,
    compose,
    dispose,
    scans: () => scans,
    lastReceipt: () => lastReceipt,
    lastAction: () => lastAction,
    lastEvidence: () => lastEvidence,
  };
}
