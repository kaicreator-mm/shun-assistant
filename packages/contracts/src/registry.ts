// Contract registry: the authoritative list of public contract schemas with
// their committed JSON Schema artifacts, plus typed parsers used across Shun
// packages. Registry membership is the public schema surface of T00.
import type { z } from 'zod';
import {
  type AuthorizationAuthority,
  AuthorizationAuthoritySchema,
  type AuthorizationGrant,
  AuthorizationGrantSchema,
  type CurrentAuthorityState,
  CurrentAuthorityStateSchema,
} from './authorization.ts';
import { type ResolutionRecord, ResolutionRecordSchema } from './capabilities/c000.ts';
import {
  type ImageBatchProcessInput,
  ImageBatchProcessInputSchema,
  type ImageBatchProcessOutput,
  ImageBatchProcessOutputSchema,
} from './capabilities/c001.ts';
import {
  type JitLifecycleInput,
  JitLifecycleInputSchema,
  type JitLifecycleOutput,
  JitLifecycleOutputSchema,
} from './capabilities/c002.ts';
import {
  type StorageDiagnoseInput,
  StorageDiagnoseInputSchema,
  type StorageDiagnoseOutput,
  StorageDiagnoseOutputSchema,
} from './capabilities/c003.ts';
import { type CapabilityDefinition, CapabilityDefinitionSchema } from './capability.ts';
import {
  type EnvironmentFacts,
  EnvironmentFactsSchema,
  type ProviderEnvironmentBinding,
  ProviderEnvironmentBindingSchema,
} from './environment.ts';
import {
  type GoalContract,
  GoalContractSchema,
  type GoalRequest,
  GoalRequestSchema,
} from './goal.ts';
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizedAction,
  AuthorizedActionSchema,
} from './plan.ts';
import {
  type ProviderCapabilityBinding,
  ProviderCapabilityBindingSchema,
  type ProviderDefinition,
  ProviderDefinitionSchema,
} from './provider.ts';
import {
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type VerificationReceipt,
  VerificationReceiptSchema,
} from './receipts.ts';
import { ShunContractError } from './taxonomy.ts';

export type ContractEntry = {
  readonly name: string;
  readonly schema: z.ZodType;
};

export const CONTRACTS: readonly ContractEntry[] = [
  { name: 'goal-request', schema: GoalRequestSchema },
  { name: 'goal-contract', schema: GoalContractSchema },
  { name: 'capability-definition', schema: CapabilityDefinitionSchema },
  { name: 'provider-definition', schema: ProviderDefinitionSchema },
  { name: 'provider-capability-binding', schema: ProviderCapabilityBindingSchema },
  { name: 'environment-facts', schema: EnvironmentFactsSchema },
  { name: 'provider-environment-binding', schema: ProviderEnvironmentBindingSchema },
  { name: 'action-plan', schema: ActionPlanSchema },
  { name: 'authorized-action', schema: AuthorizedActionSchema },
  { name: 'authorization-authority', schema: AuthorizationAuthoritySchema },
  { name: 'authorization-grant', schema: AuthorizationGrantSchema },
  { name: 'current-authority-state', schema: CurrentAuthorityStateSchema },
  { name: 'execution-receipt', schema: ExecutionReceiptSchema },
  { name: 'verification-receipt', schema: VerificationReceiptSchema },
  { name: 'c000-resolution-record', schema: ResolutionRecordSchema },
  { name: 'c001-image-batch-process-input', schema: ImageBatchProcessInputSchema },
  { name: 'c001-image-batch-process-output', schema: ImageBatchProcessOutputSchema },
  { name: 'c002-jit-lifecycle-input', schema: JitLifecycleInputSchema },
  { name: 'c002-jit-lifecycle-output', schema: JitLifecycleOutputSchema },
  { name: 'c003-storage-diagnose-input', schema: StorageDiagnoseInputSchema },
  { name: 'c003-storage-diagnose-output', schema: StorageDiagnoseOutputSchema },
];

export function contractByName(name: string): ContractEntry | undefined {
  return CONTRACTS.find((entry) => entry.name === name);
}

/** Typed parse: rejects unknown/invalid structures with a ShunContractError. */
export function parseOrThrow<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new ShunContractError(
      'SCHEMA_VIOLATION',
      'value does not satisfy the frozen contract schema',
      result.error.issues,
    );
  }
  return result.data;
}

export const parseGoalRequest = (value: unknown): GoalRequest =>
  parseOrThrow(GoalRequestSchema, value);
export const parseGoalContract = (value: unknown): GoalContract =>
  parseOrThrow(GoalContractSchema, value);
export const parseCapabilityDefinition = (value: unknown): CapabilityDefinition =>
  parseOrThrow(CapabilityDefinitionSchema, value);
export const parseProviderDefinition = (value: unknown): ProviderDefinition =>
  parseOrThrow(ProviderDefinitionSchema, value);
export const parseProviderCapabilityBinding = (value: unknown): ProviderCapabilityBinding =>
  parseOrThrow(ProviderCapabilityBindingSchema, value);
export const parseEnvironmentFacts = (value: unknown): EnvironmentFacts =>
  parseOrThrow(EnvironmentFactsSchema, value);
export const parseProviderEnvironmentBinding = (value: unknown): ProviderEnvironmentBinding =>
  parseOrThrow(ProviderEnvironmentBindingSchema, value);
export const parseActionPlan = (value: unknown): ActionPlan =>
  parseOrThrow(ActionPlanSchema, value);
export const parseAuthorizedAction = (value: unknown): AuthorizedAction =>
  parseOrThrow(AuthorizedActionSchema, value);
export const parseAuthorizationAuthority = (value: unknown): AuthorizationAuthority =>
  parseOrThrow(AuthorizationAuthoritySchema, value);
export const parseAuthorizationGrant = (value: unknown): AuthorizationGrant =>
  parseOrThrow(AuthorizationGrantSchema, value);
export const parseCurrentAuthorityState = (value: unknown): CurrentAuthorityState =>
  parseOrThrow(CurrentAuthorityStateSchema, value);
export const parseExecutionReceipt = (value: unknown): ExecutionReceipt =>
  parseOrThrow(ExecutionReceiptSchema, value);
export const parseVerificationReceipt = (value: unknown): VerificationReceipt =>
  parseOrThrow(VerificationReceiptSchema, value);
export const parseResolutionRecord = (value: unknown): ResolutionRecord =>
  parseOrThrow(ResolutionRecordSchema, value);
export const parseImageBatchProcessInput = (value: unknown): ImageBatchProcessInput =>
  parseOrThrow(ImageBatchProcessInputSchema, value);
export const parseImageBatchProcessOutput = (value: unknown): ImageBatchProcessOutput =>
  parseOrThrow(ImageBatchProcessOutputSchema, value);
export const parseJitLifecycleInput = (value: unknown): JitLifecycleInput =>
  parseOrThrow(JitLifecycleInputSchema, value);
export const parseJitLifecycleOutput = (value: unknown): JitLifecycleOutput =>
  parseOrThrow(JitLifecycleOutputSchema, value);
export const parseStorageDiagnoseInput = (value: unknown): StorageDiagnoseInput =>
  parseOrThrow(StorageDiagnoseInputSchema, value);
export const parseStorageDiagnoseOutput = (value: unknown): StorageDiagnoseOutput =>
  parseOrThrow(StorageDiagnoseOutputSchema, value);
