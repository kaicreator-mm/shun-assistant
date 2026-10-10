// Typed ports around planning, durable workflow coordination, environment
// execution and recipe resolution (L2 §5.2, §6.1, §6.9, §8.1).
//
// These are interface-only contracts. Implementations/adapters live in their
// own packages (resolver, workflow, executor-windows, vertical-*); none of
// them may bypass the Capability → binding → trust/policy → risk →
// authorization → semantic verification chain (L2 §3.1 authority rule).
import { z } from 'zod';
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
import { CapabilityRevisionRangeSchema } from './provider.ts';
import type { ExecutionReceipt } from './receipts.ts';
import {
  RecipeCurrentnessSchema,
  RecipeLifecycleStateSchema,
  RiskClassSchema,
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
