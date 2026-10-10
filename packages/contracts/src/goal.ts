// Goal-side public contracts.
//
// C-000 input (docs/product/capability-contracts-v0.1.md) and the normalized
// GoalContract authority form (L2 §4.1). Field names are camelCase L3
// refinements of the frozen snake_case Product fields; the semantic boundaries
// are unchanged.
import { z } from 'zod';
import { AmbiguityDispositionSchema } from './taxonomy.ts';

/** A referenced object: files, directories, devices, applications, or system states (Product C-000 input). */
export const ObjectRefSchema = z.strictObject({
  kind: z.enum(['FILE', 'DIRECTORY', 'DEVICE', 'APPLICATION', 'SYSTEM_STATE']),
  ref: z.string().min(1),
});
export type ObjectRef = z.infer<typeof ObjectRefSchema>;

/**
 * Normalized user constraints (Product C-000: required format, privacy,
 * offline/online policy, resource/time limits, licensing preferences,
 * retain/remove policy, and other user constraints). Values stay descriptive
 * at the contract layer; the resolver interprets them against current policy.
 */
export const ConstraintsSchema = z.strictObject({
  format: z.string().min(1).optional(),
  privacy: z.string().min(1).optional(),
  executionEnvironment: z.string().min(1).optional(),
  resourceLimits: z.string().min(1).optional(),
  licensing: z.string().min(1).optional(),
  retainRemove: z.string().min(1).optional(),
  other: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
});
export type Constraints = z.infer<typeof ConstraintsSchema>;

/**
 * Privacy policy. Local collection and external disclosure are distinct
 * (Product hard boundaries); a local-only policy makes remote planners and
 * remote providers ineligible (L2 §6.3).
 */
export const PrivacyPolicySchema = z.strictObject({
  localOnly: z.boolean(),
  externalDisclosure: z.enum(['ALLOWED', 'FORBIDDEN', 'POLICY_CONTROLLED']),
});
export type PrivacyPolicy = z.infer<typeof PrivacyPolicySchema>;

/** Allowed execution environments and elevation posture for the task. */
export const EnvironmentPolicySchema = z.strictObject({
  allowedBackendKinds: z.array(z.enum(['LOCAL_WINDOWS', 'LOCAL_POSIX', 'REMOTE_ECF'])).min(1),
  allowElevation: z.boolean(),
});
export type EnvironmentPolicy = z.infer<typeof EnvironmentPolicySchema>;

/** Lifecycle retention policy, declared before acquisition/use for JIT flows (Product C-002). */
export const LifecyclePolicySchema = z.strictObject({
  retention: z.enum(['RETAIN', 'JIT_REMOVE_AFTER_VERIFIED_USE']),
});
export type LifecyclePolicy = z.infer<typeof LifecyclePolicySchema>;

/** Explicit user success conditions when supplied (Product C-000 verification_intent). */
export const VerificationIntentSchema = z.strictObject({
  successConditions: z.array(z.string().min(1)).min(1),
});
export type VerificationIntent = z.infer<typeof VerificationIntentSchema>;

/**
 * C-000 resolution request: the raw normalized intent Shun resolves. This is
 * input data, never authority; a Planner may propose it, Shun validates it.
 */
export const GoalRequestSchema = z.strictObject({
  taskId: z.string().min(1),
  goal: z.string().min(1),
  objects: z.array(ObjectRefSchema),
  constraints: ConstraintsSchema,
  policyContext: z.strictObject({
    privacyPolicy: PrivacyPolicySchema,
    environmentPolicy: EnvironmentPolicySchema,
  }),
  verificationIntent: VerificationIntentSchema.optional(),
});
export type GoalRequest = z.infer<typeof GoalRequestSchema>;

/**
 * Normalized goal authority form (L2 §4.1). Ambiguity is first-class: an AI
 * planner may propose a GoalContract, but it becomes authoritative only after
 * Shun validates it against the frozen Product contracts.
 */
export const GoalContractSchema = z.strictObject({
  taskId: z.string().min(1),
  objective: z.string().min(1),
  objects: z.array(ObjectRefSchema),
  constraints: ConstraintsSchema,
  privacyPolicy: PrivacyPolicySchema,
  environmentPolicy: EnvironmentPolicySchema,
  lifecyclePolicy: LifecyclePolicySchema.optional(),
  verificationIntent: VerificationIntentSchema.optional(),
  ambiguityDisposition: AmbiguityDispositionSchema,
});
export type GoalContract = z.infer<typeof GoalContractSchema>;
