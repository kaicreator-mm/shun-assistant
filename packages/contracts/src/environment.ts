// Environment facts, requirements and binding feasibility (L2 §4.4).
// Environment feasibility is evaluated on the binding after requirements are
// known; provider trust facts and runtime reliability evidence are separate.
import { z } from 'zod';
import { InterfaceClassSchema } from './taxonomy.ts';

export const BACKEND_KINDS = ['LOCAL_WINDOWS', 'LOCAL_POSIX', 'REMOTE_ECF'] as const;
export type BackendKind = (typeof BACKEND_KINDS)[number];
export const BackendKindSchema = z.enum(BACKEND_KINDS);

export const PrivilegeModeSchema = z.enum([
  'STANDARD_USER',
  'FILTERED_ADMIN',
  'ELEVATED_ADMIN',
  'SERVICE',
]);
export type PrivilegeMode = z.infer<typeof PrivilegeModeSchema>;

export const NetworkPolicySchema = z.enum(['OFFLINE', 'POLICY_CONTROLLED', 'OPEN']);
export type NetworkPolicy = z.infer<typeof NetworkPolicySchema>;

/** Declared requirements a binding places on an environment. */
export const EnvironmentRequirementsSchema = z.strictObject({
  backendKind: BackendKindSchema,
  os: z.enum(['WINDOWS', 'LINUX', 'MACOS']).optional(),
  arch: z.enum(['X64', 'ARM64']).optional(),
  privilegeMode: PrivilegeModeSchema.optional(),
  guiSessionRequired: z.boolean().optional(),
  networkAccess: z.enum(['REQUIRED', 'OPTIONAL', 'FORBIDDEN']).optional(),
  minFreeDiskMb: z.number().int().nonnegative().optional(),
  runtimeCapabilities: z.array(z.string().min(1)).optional(),
});
export type EnvironmentRequirements = z.infer<typeof EnvironmentRequirementsSchema>;

/** Observed machine facts about one execution environment (L2 §4.4). */
export const EnvironmentFactsSchema = z.strictObject({
  environmentId: z.string().min(1),
  backendKind: BackendKindSchema,
  os: z.string().min(1),
  arch: z.string().min(1),
  /** Observation revision: durable identity input (L2 §11.2). */
  observationRevision: z.string().min(1),
  runtimeCapabilities: z.array(z.string().min(1)),
  privilegeMode: PrivilegeModeSchema,
  guiSession: z.boolean(),
  filesystemCapabilities: z.array(z.string().min(1)),
  networkPolicy: NetworkPolicySchema,
  resources: z.strictObject({
    cpuCores: z.number().int().positive(),
    memoryMb: z.number().int().positive(),
    freeDiskMb: z.number().int().nonnegative(),
  }),
});
export type EnvironmentFacts = z.infer<typeof EnvironmentFactsSchema>;

/** Typed reasons a Provider × Environment binding may be infeasible. */
export const BINDING_REJECTION_REASONS = [
  'PLATFORM_UNSUPPORTED',
  'ARCH_UNSUPPORTED',
  'PRIVILEGE_INSUFFICIENT',
  'GUI_SESSION_UNAVAILABLE',
  'NETWORK_POLICY_FORBIDDEN',
  'RESOURCE_INSUFFICIENT',
  'RUNTIME_CAPABILITY_MISSING',
  'BACKEND_KIND_INELIGIBLE',
] as const;
export type BindingRejectionReason = (typeof BINDING_REJECTION_REASONS)[number];
export const BindingRejectionReasonSchema = z.enum(BINDING_REJECTION_REASONS);

/** ProviderEnvironmentBinding (L2 §4.4): feasibility evaluated after requirements are known. */
export const ProviderEnvironmentBindingSchema = z.strictObject({
  providerBindingId: z.string().min(1),
  environmentId: z.string().min(1),
  feasibility: z.strictObject({
    feasible: z.boolean(),
    rejectionReasons: z.array(BindingRejectionReasonSchema),
  }),
});
export type ProviderEnvironmentBinding = z.infer<typeof ProviderEnvironmentBindingSchema>;

/** Result of EnvironmentBackend.canPrepare (L2 §8.1). */
export const FeasibilitySchema = z.strictObject({
  feasible: z.boolean(),
  rejectionReasons: z.array(BindingRejectionReasonSchema),
});
export type Feasibility = z.infer<typeof FeasibilitySchema>;

/** Interface description carried by a ProviderDefinition (L2 §4.3). */
export const ProviderInterfaceSchema = z.strictObject({
  interfaceId: z.string().min(1),
  interfaceClass: InterfaceClassSchema,
  /** Stable invocation descriptor (library entry point, CLI argv shape, file contract). Never a free-form shell command. */
  invocation: z.string().min(1),
});
export type ProviderInterface = z.infer<typeof ProviderInterfaceSchema>;
