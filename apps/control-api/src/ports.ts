// Control-surface seams (T08, L2 §12).
//
// These are the L3 control-surface read/decide ports. They deliberately sit ON
// TOP of the frozen T00 contracts and never replace them:
//   - approval decisions are relayed as frozen `ApprovalDecision` records and
//     remain bound to the exact plan hash (L2 §4.6);
//   - grant issuance, AuthorizedAction construction and policy evaluation stay
//     inside the Action Controller — nothing in this package can create
//     authorization (L2 §9.1, Issue #19 acceptance);
//   - the surface reads progress/recovery/residue through a read model so the
//     UI stays a comprehension tool, not a diagnostics dump (L2 §12).
import type {
  ActionPlan,
  ApprovalDecision,
  GoalRequest,
  PlanAction,
  RecoveryClassification,
  RiskClass,
  TaskState,
} from '@shun/contracts';

/** Injected clock returning ISO 8601 UTC instants; keeps all state timing deterministic. */
export type Clock = () => string;

/** Current policy snapshot view as displayed by the surface. Unknown is fail-closed. */
export type PolicyState =
  | { kind: 'ACTIVE'; revision: string }
  | { kind: 'EXPIRED'; revision: string; expiredAt: string }
  | { kind: 'UNKNOWN'; reason: string };

/**
 * A pending R2/R3 approval as the surface presents it: the controller-authored
 * human summary plus the exact plan hash the user is approving. The user
 * decision must echo `planHash` (misleading-preview prevention).
 */
export interface PendingApproval {
  approvalId: string;
  taskId: string;
  planHash: string;
  summary: string;
  evidenceRefs: string[];
  riskClass: RiskClass;
  requiresExplicitApproval: boolean;
  createdAt: string;
  expiresAt?: string;
}

/** One plan action rendered as a human-comprehensible line (no raw parameter dumps). */
export interface PreviewAction {
  actionId: string;
  op: string;
  description: string;
  requiredPrivilege: PlanAction['requiredPrivilege'];
  filesystem?: { read: string[]; write: string[] };
  network: { allowed: boolean; domains?: string[] };
  cancellation?: { supported: boolean; mode: string };
}

/**
 * Human-comprehensible plan/preview with risk (L2 §12). Every sentence derives
 * deterministically from plan structure — never from free text inside the
 * plan — so a crafted action name cannot reframe what an approval means.
 */
export interface PlanPreview {
  taskId: string;
  planHash: string;
  capabilityId: string;
  riskClass: RiskClass;
  /** Fixed per-risk-class wording (L2 §9.2); independent of action names/ops. */
  riskStatement: string;
  actions: PreviewAction[];
  verification: { summary: string; checks: string[] };
  recovery: { summary: string };
  requiresExplicitApproval: boolean;
  policySnapshotRevision: string;
  generatedAt: string;
  /** Approval window; an approval after this instant is refused (fail closed). */
  expiresAt?: string;
}

/** Readable progress step derived from the task history. */
export interface ProgressStep {
  at: string;
  state: TaskState;
  note?: string;
}

/** Aggregated residue view: readable by default, itemized evidence on demand (L2 §12). */
export interface ReadableResidue {
  taskId: string;
  generatedAt: string;
  headline: string;
  groups: { label: string; count: number; readableBytes?: string }[];
  protectedUntouchedCount: number;
  detailAvailable: boolean;
}

export interface ResidueItemDetail {
  path: string;
  kind: string;
  sizeBytes?: number;
  classification: string;
  evidenceRef: string;
}

export interface ResidueDetail extends ReadableResidue {
  items: ResidueItemDetail[];
}

/** One task as the surface displays it — progress, not machine internals. */
export interface TaskSnapshot {
  taskId: string;
  title: string;
  state: TaskState;
  revision: number;
  createdAt: string;
  updatedAt: string;
  progress: ProgressStep[];
  clarification?: { question: string };
  failure?: { code: string; message: string };
  planSummary?: {
    planHash: string;
    capabilityId: string;
    riskClass: RiskClass;
    riskStatement: string;
    actionCount: number;
    policySnapshotRevision: string;
  };
  approval?: {
    approvalId: string;
    status: 'PENDING' | 'APPROVED' | 'DECLINED' | 'EXPIRED';
    summary: string;
    planHash: string;
    expiresAt?: string;
  };
  execution?: { terminal?: string; startedAt?: string; finishedAt?: string };
  verification?: { status: string; checks: { checkId: string; status: string }[] };
  recovery?: {
    classification: RecoveryClassification;
    detail: string;
    reconciled: boolean;
  };
  residueSummary?: { headline: string; groups: ReadableResidue['groups'] };
  localOnly: {
    enforced: boolean;
    externalDisclosure: 'ALLOWED' | 'FORBIDDEN' | 'POLICY_CONTROLLED';
  };
}

/** Uniform typed outcome: the surface maps `code` to its fixed HTTP status. */
export type Outcome<T> = { ok: true; value: T } | { ok: false; code: string; detail: string };

export type DecisionOutcome = Outcome<{ decision: ApprovalDecision; taskState: TaskState }>;

/**
 * The backend the surface talks to. A real deployment wires this to the T01–T03
 * packages (resolver / Action Controller / workflow kernel); T08 ships an
 * in-memory reference backend so the surface is executable and testable before
 * those land. Implementations own all authority; this interface exposes none.
 */
export interface ControlBackend {
  meta(): { policy: PolicyState; localOnly: true };
  submitGoal(request: GoalRequest): Promise<{ taskId: string }>;
  listTasks(): Promise<TaskSnapshot[]>;
  taskSnapshot(taskId: string): Promise<TaskSnapshot | undefined>;
  /** Current plan preview; undefined when no plan exists yet (typed PREVIEW_NOT_AVAILABLE at the API). */
  taskPreview(taskId: string): Promise<PlanPreview | undefined>;
  pendingApprovals(): Promise<PendingApproval[]>;
  approvalWithPreview(
    approvalId: string,
  ): Promise<{ approval: PendingApproval; preview: PlanPreview } | undefined>;
  decideApproval(input: {
    approvalId: string;
    approved: boolean;
    seenPlanHash: string;
    reason?: string;
  }): Promise<DecisionOutcome>;
  cancelTask(taskId: string): Promise<Outcome<{ state: TaskState }>>;
  answerClarification(taskId: string, answer: string): Promise<Outcome<{ state: TaskState }>>;
  /** Reconcile-first recovery (L2 §9.4): classify from journal + post-state before any retry. */
  reconcileTask(taskId: string): Promise<Outcome<{ classification: RecoveryClassification }>>;
  retryTask(taskId: string): Promise<Outcome<{ state: TaskState }>>;
  residueSummary(
    taskId: string,
    detail: boolean,
  ): Promise<ResidueDetail | ReadableResidue | undefined>;
  /** Local evidence store lookup; non-local refs are a typed violation, never a fetch. */
  evidence(ref: string): Promise<Outcome<{ ref: string; record: unknown }>>;
}

/** The plan a preview was built from — exported so tests can bind preview↔plan identity. */
export type { ActionPlan };
