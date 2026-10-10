// Shared fixtures for the authorization-domain tests: an in-memory (explicitly
// non-durable) policy/grant state, a controllable clock, plan builders mirroring
// the frozen action-plan fixture, and fake control surfaces.
import type {
  ActionPlan,
  ApprovalDecision,
  ApprovalPort,
  ApprovalRequest,
  AuthorizationGrant,
  GrantIssueRequest,
} from '@shun/contracts';
import { computePlanHash } from '@shun/contracts';
import type { StoredGrantRecord } from '../src/authority.ts';
import type { AuthorityRecord, PolicySnapshotRecord } from '../src/policy.ts';

export const AUTHORITY: AuthorityRecord = {
  authorityId: 'shun-action-controller',
  authorityRevision: 'auth-rev-1',
  updatedAt: '2026-10-10T00:00:00.000Z',
};

export const POLICY_REVISION = 'pol-snap-1';

/** Controllable ISO clock. */
export function fixedClock(start = '2026-10-10T12:00:00.000Z') {
  let epochMs = Date.parse(start);
  return {
    now: () => new Date(epochMs).toISOString(),
    advanceMs(ms: number) {
      epochMs += ms;
    },
  };
}

/**
 * In-memory PolicyStateStore. Slots hold unknown values so tests can inject
 * corrupt/missing records and prove UNRESOLVABLE fail-closed resolution.
 */
export function memoryPolicyState(seed?: {
  authority?: AuthorityRecord;
  policy?: PolicySnapshotRecord;
}) {
  const state = {
    authoritySlot: undefined as unknown,
    policySlot: undefined as unknown,
    authorityReadsFail: false as boolean,
    policyReadsFail: false as boolean,
    async loadAuthorityRecord() {
      if (state.authorityReadsFail) throw new Error('simulated authority read failure');
      return state.authoritySlot;
    },
    async loadCurrentPolicy() {
      if (state.policyReadsFail) throw new Error('simulated policy read failure');
      return state.policySlot;
    },
    async saveAuthorityRecord(record: AuthorityRecord) {
      state.authoritySlot = structuredClone(record);
    },
    async savePolicySnapshot(snapshot: PolicySnapshotRecord) {
      state.policySlot = structuredClone(snapshot);
    },
  };
  if (seed?.authority) state.authoritySlot = structuredClone(seed.authority);
  if (seed?.policy) state.policySlot = structuredClone(seed.policy);
  return state;
}

export function memoryGrantStore() {
  const records = new Map<string, StoredGrantRecord>();
  return {
    async put(record: StoredGrantRecord) {
      records.set(record.grantId, structuredClone(record));
    },
    async get(grantId: string) {
      return records.get(grantId) ?? null;
    },
    snapshot(): StoredGrantRecord[] {
      return [...records.values()];
    },
    has(grantId: string) {
      return records.has(grantId);
    },
  };
}

/** ACTIVE policy bound to the seed authority, with optional rules/guards. */
export function activePolicy(overrides?: Partial<PolicySnapshotRecord>): PolicySnapshotRecord {
  return {
    policySnapshotRevision: POLICY_REVISION,
    status: 'ACTIVE',
    authorityId: AUTHORITY.authorityId,
    authorityRevision: AUTHORITY.authorityRevision,
    revokedGrantIds: [],
    rules: [],
    riskGuards: [],
    updatedAt: '2026-10-10T00:00:00.000Z',
    ...overrides,
  };
}

export interface PlanOverrides {
  taskId?: string;
  capabilityId?: string;
  policySnapshotRevision?: string;
  actions?: Partial<ActionPlan['actions'][number]>[];
}

type PlanAction = ActionPlan['actions'][number];

/** Build a valid ActionPlan (schema + semantics + correct hash) from defaults. */
export function buildPlan(overrides?: PlanOverrides): ActionPlan {
  const defaultAction: PlanAction = {
    actionId: 'action-001',
    bindingRef: 'binding-localwin',
    op: 'image.resize',
    parameters: { format: 'JPG', maxLongEdgePx: 1600 },
    sideEffectClass: 'R1',
    requiredPrivilege: 'NONE',
    filesystemScope: {
      read: ['C:\\fixtures\\images'],
      write: ['C:\\fixtures\\out'],
    },
    networkScope: { allowed: false },
    timeoutMs: 600000,
    cancellation: { supported: true, mode: 'COOPERATIVE' },
    expectedState: { count: 12, outputsDecode: true },
  };
  const actions: PlanAction[] = (overrides?.actions ?? [{}]).map((extra, index) => ({
    ...defaultAction,
    ...extra,
    actionId: extra.actionId ?? `action-${String(index + 1).padStart(3, '0')}`,
  }));
  const plan: Omit<ActionPlan, 'planHash'> = {
    taskId: overrides?.taskId ?? 'task-2026-10-10-001',
    capabilityId: overrides?.capabilityId ?? 'image.batch_process',
    bindingRefs: ['binding-localwin'],
    rankingPolicyRevision: 'rank-pol-v3',
    policySnapshotRevision: overrides?.policySnapshotRevision ?? POLICY_REVISION,
    actions,
    verificationPlan: {
      verifierId: 'verifier.image-ssim',
      verifierRevision: 'r2',
      checks: [{ checkId: 'count-conservation' }, { checkId: 'decode-all' }],
      oracle: {
        precommitted: true,
        spec: { metric: 'SSIM', threshold: 0.95 },
      },
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
  };
  return { ...plan, planHash: computePlanHash(plan as ActionPlan) };
}

/** Tamper helper: mutate plan content while keeping the old (now wrong) hash. */
export function tamperPlan(plan: ActionPlan, mutate: (draft: ActionPlan) => void): ActionPlan {
  const draft = structuredClone(plan);
  mutate(draft);
  return draft;
}

/** Approval control surface that approves everything presented to it. */
export function approvingSurface(options?: {
  decidedPlanHash?: string;
  decidedTaskId?: string;
  approved?: boolean;
}) {
  const requests: ApprovalRequest[] = [];
  const surface: ApprovalPort = {
    async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
      requests.push(structuredClone(request));
      return {
        approvalId: 'approval-001',
        taskId: options?.decidedTaskId ?? request.taskId,
        planHash: options?.decidedPlanHash ?? request.planHash,
        approved: options?.approved ?? true,
        approvedBy: 'USER_APPROVAL',
      };
    },
  };
  return { surface, requests };
}

export function issueRequestFor(
  plan: ActionPlan,
  extra?: Partial<GrantIssueRequest>,
): GrantIssueRequest {
  const action = plan.actions[0];
  if (!action) throw new Error('plan has no actions');
  return {
    taskId: plan.taskId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    actionScope: {
      actionIds: plan.actions.map((a) => a.actionId),
      privilegeLevel: action.requiredPrivilege,
      ...(action.filesystemScope ? { filesystem: action.filesystemScope } : {}),
      ...(action.networkScope
        ? {
            network: {
              allowed: action.networkScope.allowed,
              ...(action.networkScope.domains ? { domains: action.networkScope.domains } : {}),
            },
          }
        : {}),
      ...(action.registryScope ? { registry: action.registryScope } : {}),
    },
    authorizationKind: 'DURABLE_POLICY',
    ...extra,
  };
}

export function grantOf(
  authority: { issue(request: GrantIssueRequest): Promise<AuthorizationGrant> },
  plan: ActionPlan,
  extra?: Partial<GrantIssueRequest>,
) {
  return authority.issue(issueRequestFor(plan, extra));
}
