// Typed ports around planning, durable workflow coordination, environment
// execution and recipe resolution (L2 §5.2, §6.1, §6.9, §8.1), plus the
// remaining frozen seams: ShunStore (§5.4/§11.1), approval control surface
// (§12), authorization authority (§4.6.1), privileged execution broker
// (§9.1/§9.3), semantic verifier (§4.7/§13) and the provider-registry read
// model (§7.1).
//
// These are interface-only contracts. Implementations/adapters live in their
// own packages (resolver, workflow, executor-windows, vertical-*); none of
// them may bypass the Capability → binding → trust/policy → risk →
// authorization → semantic verification chain (L2 §3.1 authority rule).
import { z } from 'zod';
import {
  ActionScopeSchema,
  type AuthorizationGrant,
  type CurrentAuthorityState,
  type GrantIntegrity,
} from './authorization.ts';
import type { CapabilityDefinition } from './capability.ts';
import type {
  EnvironmentFacts,
  EnvironmentRequirements,
  Feasibility,
  ProviderEnvironmentBinding,
} from './environment.ts';
import { EnvironmentRequirementsSchema } from './environment.ts';
import type { GoalContract, GoalRequest } from './goal.ts';
import { GoalContractSchema } from './goal.ts';
import { type AuthorizedAction, RecoveryPlanSchema, VerificationPlanSchema } from './plan.ts';
import type { ProviderCapabilityBinding, ProviderDefinition } from './provider.ts';
import { CapabilityRevisionRangeSchema } from './provider.ts';
import {
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type VerificationReceipt,
} from './receipts.ts';
import {
  AuthorizationKindSchema,
  RecipeCurrentnessSchema,
  RecipeLifecycleStateSchema,
  RiskClassSchema,
  Sha256HexSchema,
  TaskStateSchema,
} from './taxonomy.ts';

export const TaskWorkflowStateSchema = z.strictObject({
  taskId: z.string().min(1),
  state: TaskStateSchema,
  revision: z.number().int().nonnegative(),
});
export type TaskWorkflowState = z.infer<typeof TaskWorkflowStateSchema>;

export const WorkflowMessageSchema = z.strictObject({
  messageId: z.string().min(1),
  taskId: z.string().min(1),
  kind: z.string().min(1),
  payload: z.unknown(),
});
export type WorkflowMessage = z.infer<typeof WorkflowMessageSchema>;

export const MessageDispositionSchema = z.strictObject({
  accepted: z.boolean(),
  reason: z.string().min(1).optional(),
});
export type MessageDisposition = z.infer<typeof MessageDispositionSchema>;

export const PreparedEnvironmentSchema = z.strictObject({
  preparedEnvironmentId: z.string().min(1),
  environmentId: z.string().min(1),
});
export type PreparedEnvironment = z.infer<typeof PreparedEnvironmentSchema>;

/**
 * Durable workflow kernel seam (L2 §5.2). Shun owns Goal/Capability/Policy
 * semantics; the kernel owns durable instance mechanics only (§5.3). The
 * reference adapter uses released DomainHarness durable runtime semantics.
 */
export interface WorkflowKernelPort {
  open(task: { taskId: string; goal: GoalContract }): Promise<string>;
  send(message: WorkflowMessage): Promise<MessageDisposition>;
  query(taskId: string): Promise<TaskWorkflowState>;
  subscribe(taskId: string, callback: (state: TaskWorkflowState) => void): () => void;
  recover(taskId: string): Promise<TaskWorkflowState>;
}

/** Planner output is always proposal data; it is never authority (L2 §6.1). */
export const GoalProposalSchema = z.strictObject({
  proposalId: z.string().min(1),
  goalContract: GoalContractSchema,
  /** Set when an external model produced this proposal — an external-model disclosure (L2 §6.3). */
  plannerEvidence: z
    .strictObject({
      operationId: z.string().min(1),
      modelEvidence: z.string().min(1),
    })
    .optional(),
});
export type GoalProposal = z.infer<typeof GoalProposalSchema>;

export const UserExplanationSchema = z.strictObject({
  summary: z.string().min(1),
  details: z.array(z.string().min(1)),
});
export type UserExplanation = z.infer<typeof UserExplanationSchema>;

export interface PlannerPort {
  interpretGoal(input: GoalRequest): Promise<GoalProposal>;
  decomposeGoal?(input: GoalRequest): Promise<unknown>;
  explainResolution?(input: { taskId: string }): Promise<UserExplanation>;
}

/**
 * EnvironmentBackend seam (L2 §8.1). The P0 reference implementation is the
 * local Windows backend; runx/ECF is a P1 adapter for compatible headless
 * jobs only. execute() accepts ONLY an AuthorizedAction.
 */
export interface EnvironmentBackend {
  observe(): Promise<EnvironmentFacts>;
  canPrepare(requirements: EnvironmentRequirements): Promise<Feasibility>;
  prepare(binding: ProviderEnvironmentBinding): Promise<PreparedEnvironment>;
  execute(action: AuthorizedAction): Promise<ExecutionReceipt>;
  cancel(actionId: string): Promise<void>;
  cleanup(prepared: PreparedEnvironment): Promise<void>;
}

// P1-conditional recipe surface (L2 §6.5, §6.9): the port and its state space
// are frozen architecture; automatic promotion is P1 and NOT part of the first
// executable proof. Types only — no recipe implementation belongs in P0.

export const RecipeDefinitionSchema = z.strictObject({
  recipeId: z.string().min(1),
  revision: z.string().min(1),
  capabilityId: z.string().min(1),
  capabilityRevisionRange: CapabilityRevisionRangeSchema,
  applicabilityPredicate: z.record(z.string(), z.unknown()),
  parameterSchema: z.record(z.string(), z.unknown()),
  providerBindingConstraints: z.record(z.string(), z.unknown()),
  environmentRequirements: EnvironmentRequirementsSchema.optional(),
  policyRequirements: z.record(z.string(), z.unknown()),
  /** Lower bound captured from promotion evidence; instantiated actions may classify higher under current inputs (L2 §6.7). */
  riskFloor: RiskClassSchema,
  actionTemplate: z.record(z.string(), z.unknown()),
  verifierId: z.string().min(1),
  verifierRevision: z.string().min(1),
  recoveryTemplate: z.record(z.string(), z.unknown()),
  currentnessInputs: z.array(z.string().min(1)).min(1),
  provenance: z.record(z.string(), z.unknown()),
});
export type RecipeDefinition = z.infer<typeof RecipeDefinitionSchema>;

export const RecipeLifecycleStatusSchema = z.strictObject({
  recipeId: z.string().min(1),
  revision: z.string().min(1),
  state: RecipeLifecycleStateSchema,
});
export type RecipeLifecycleStatus = z.infer<typeof RecipeLifecycleStatusSchema>;

export const RecipeCandidatesSchema = z.strictObject({
  candidates: z.array(
    z.strictObject({
      recipe: RecipeDefinitionSchema,
      lifecycle: RecipeLifecycleStatusSchema,
    }),
  ),
});
export type RecipeCandidates = z.infer<typeof RecipeCandidatesSchema>;

export const RecipeCurrentnessResultSchema = z.strictObject({
  outcome: RecipeCurrentnessSchema,
  inputs: z.record(z.string(), z.unknown()),
  reason: z.string().min(1).optional(),
});
export type RecipeCurrentnessResult = z.infer<typeof RecipeCurrentnessResultSchema>;

/** A recipe instantiation is a plan PROPOSAL — the Action Controller owns plans (L2 §9.1). */
export const ActionPlanProposalSchema = z.strictObject({
  proposalId: z.string().min(1),
  capabilityId: z.string().min(1),
  candidateActions: z.array(z.record(z.string(), z.unknown())),
  verificationPlan: VerificationPlanSchema,
  recoveryPlan: RecoveryPlanSchema,
  recipeRef: z.string().min(1),
});
export type ActionPlanProposal = z.infer<typeof ActionPlanProposalSchema>;

/**
 * Recipe resolution seam (L2 §6.9). A Recipe hit bypasses fresh planning but
 * never the frozen Product gates; stale/unknown currentness escalates upward.
 */
export interface RecipeResolverPort {
  match(intent: {
    objective: string;
    objects: string[];
    constraints: Record<string, unknown>;
  }): Promise<RecipeCandidates>;
  checkCurrentness(
    recipe: RecipeDefinition,
    currentFacts: Record<string, unknown>,
  ): Promise<RecipeCurrentnessResult>;
  instantiate(
    recipe: RecipeDefinition,
    parameters: Record<string, unknown>,
    currentFacts: Record<string, unknown>,
  ): Promise<ActionPlanProposal>;
}

// ---- ShunStore seam (L2 §5.4 store separation, §11.1 persistence model). ----
// Business/product authority records live in ShunStore; the DomainHarness
// RuntimeStore owns orchestration mechanics only. Every workflow-triggered
// mutation goes through the idempotent application-effect protocol: a stable
// effectId is persisted with the authoritative result, and retrying the same
// effectId returns the recorded result instead of re-applying.

export const ShunStoreRecordKindSchema = z.enum([
  'task',
  'goal_contract',
  'capability_resolution',
  'provider_environment_binding',
  'policy_snapshot',
  'action_plan',
  'approval',
  'execution_receipt',
  'verification_receipt',
  'provider_installation',
  'provider_provenance',
  'lifecycle_record',
  'provider_outcome_evidence',
  'recipe_definition',
  'recipe_promotion_evidence',
  'recipe_replay_evidence',
]);
export type ShunStoreRecordKind = z.infer<typeof ShunStoreRecordKindSchema>;

/** One intended business-record mutation, addressed by its stable effectId (L2 §5.4). */
export const ShunStoreMutationSchema = z.strictObject({
  recordKind: ShunStoreRecordKindSchema,
  recordId: z.string().min(1),
  /** Record payload; the concrete shape is owned by the ShunStore schema set. */
  payload: z.record(z.string(), z.unknown()),
});
export type ShunStoreMutation = z.infer<typeof ShunStoreMutationSchema>;

export const StoreApplicationReceiptSchema = z.strictObject({
  effectId: z.string().min(1),
  /** true = applied now; false = a recorded result for this effectId was returned (idempotent replay, L2 §5.4). */
  applied: z.boolean(),
  /** Durable application receipt reference. */
  receiptRef: z.string().min(1),
});
export type StoreApplicationReceipt = z.infer<typeof StoreApplicationReceiptSchema>;

/** Durable business-authority store seam (L2 §5.4/§11.1). Interface only. */
export interface StorePort {
  apply(effectId: string, mutation: ShunStoreMutation): Promise<StoreApplicationReceipt>;
}

// ---- Approval control-surface seam (L2 §12, §9.1, §4.6). ----
// Explicit approvals are durable ShunStore records; explicit-approval grants
// reference them via approvalRef, and a rejected/expired approval is owned by
// the Action Controller (L2 §13).

export const ApprovalRequestSchema = z.strictObject({
  taskId: z.string().min(1),
  /** Exact approved plan identity — approval is bound to the plan hash (L2 §4.6). */
  planHash: Sha256HexSchema,
  /** Human-comprehensible plan/preview and risk summary (L2 §12); detailed evidence on demand. */
  summary: z.string().min(1),
  evidenceRefs: z.array(z.string().min(1)),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

export const ApprovalDecisionSchema = z.strictObject({
  approvalId: z.string().min(1),
  taskId: z.string().min(1),
  planHash: Sha256HexSchema,
  approved: z.boolean(),
  approvedBy: z.enum(['USER_APPROVAL', 'DURABLE_POLICY']),
  reason: z.string().min(1).optional(),
});
export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;

/**
 * Approval seam between the plan/preview checkpoint and grant issuance
 * (L2 §9.1 approval/durable-policy step, §12 approve/reject interaction).
 * Interface only — the durable approval record itself lives in ShunStore.
 */
export interface ApprovalPort {
  requestApproval(request: ApprovalRequest): Promise<ApprovalDecision>;
}

// ---- Authorization authority seam (L2 §4.6.1). ----
// The authority issues durable, integrity-protected AuthorizationGrant records
// in ShunStore; the privileged boundary validates presentations independently
// (validateGrantPresentation) against the CURRENT authority/policy state.

/** Everything the authority needs to issue one grant; integrity is applied by the authority, never by callers. */
export const GrantIssueRequestSchema = z.strictObject({
  taskId: z.string().min(1),
  planHash: Sha256HexSchema,
  policySnapshotRevision: z.string().min(1),
  actionScope: ActionScopeSchema,
  authorizationKind: AuthorizationKindSchema,
  /** Required for EXPLICIT_APPROVAL grants — the durable approval record reference (L2 §4.6). */
  approvalRef: z.string().min(1).optional(),
});
export type GrantIssueRequest = z.infer<typeof GrantIssueRequestSchema>;

export interface AuthorizationPort {
  issue(request: GrantIssueRequest): Promise<AuthorizationGrant>;
  /** Current authority/policy state as seen by the privileged boundary (L2 §4.6.1); UNRESOLVABLE fails closed. */
  currentAuthority(): Promise<CurrentAuthorityState>;
}

// ---- Privileged execution seam (L2 §9.1 ExecutionBroker, §9.3 privilege
// boundary). ----
// Distinct from EnvironmentBackend (§8.1, unprivileged capability execution):
// the privileged backend receives only an AuthorizedAction together with its
// grant presentation and MUST re-verify the presentation itself (§4.6.1) —
// never on the caller's say-so — before any side effect.

export interface ExecutionBackend {
  execute(
    action: AuthorizedAction,
    grant: AuthorizationGrantPresentationInput,
  ): Promise<ExecutionReceipt>;
}

/** Presented (untrusted) grant shape at the privileged boundary: integrity envelope optional. */
export type AuthorizationGrantPresentationInput = Omit<AuthorizationGrant, 'integrity'> & {
  integrity?: GrantIntegrity;
};

// ---- Semantic verifier seam (L2 §4.7, §13). ----
// Execution success without required semantic verification can never become
// Task PASS; a failed verification is owned by the Verifier and degrades task
// outcome (and, for recipes, the recipe evidence).

export const VerificationInputSchema = z.strictObject({
  taskId: z.string().min(1),
  verificationPlan: VerificationPlanSchema,
  executionReceipt: ExecutionReceiptSchema,
  /** Additional post-state inputs beyond the execution receipt (oracle inputs, evidence refs). */
  oracleInputs: z.record(z.string(), z.unknown()).optional(),
});
export type VerificationInput = z.infer<typeof VerificationInputSchema>;

export interface VerifierPort {
  verify(input: VerificationInput): Promise<VerificationReceipt>;
}

// ---- Provider registry read model (L2 §7.1). ----
// Read-only view over the registry fact classes consumed by the resolver.
// Hard gates and ranking live behind the resolver, not in the registry; the
// registry never writes outcome evidence back through this port.

export interface RegistryReadModelPort {
  listCapabilities(): Promise<CapabilityDefinition[]>;
  listProviders(): Promise<ProviderDefinition[]>;
  providerCapabilityBindings(capabilityId: string): Promise<ProviderCapabilityBinding[]>;
  providerEnvironmentBindings(providerId: string): Promise<ProviderEnvironmentBinding[]>;
  /** Observed machine facts feed feasibility/currentness checks (L2 §7.1 fact class 2). */
  observedFacts(): Promise<EnvironmentFacts>;
}
