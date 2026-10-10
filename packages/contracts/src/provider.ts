// ProviderDefinition and ProviderCapabilityBinding (L2 §4.3).
// Provider trust facts and runtime reliability evidence are separate: a
// successful execution may improve reliability evidence, it MUST NOT
// automatically convert UNKNOWN provenance into trusted provenance.
import { z } from 'zod';
import { EnvironmentRequirementsSchema, ProviderInterfaceSchema } from './environment.ts';
import { InterfaceClassSchema } from './taxonomy.ts';

/** Narrow P0 software lifecycle scope (PROJECT_OVERRIDES): trusted acquisition, provenance, basic repair/reset, safe uninstall. */
export const PROVIDER_LIFECYCLE_OPERATIONS = [
  'ACQUIRE',
  'CONFIGURE',
  'REPAIR',
  'RESET',
  'UNINSTALL',
] as const;
export type ProviderLifecycleOperation = (typeof PROVIDER_LIFECYCLE_OPERATIONS)[number];
export const ProviderLifecycleOperationSchema = z.enum(PROVIDER_LIFECYCLE_OPERATIONS);

/** Curated acquisition facts; provenance is fail-closed — UNKNOWN provenance is never trusted by confirmation alone. */
export const ProviderAcquisitionSchema = z.strictObject({
  mechanism: z.enum(['PREINSTALLED', 'WINGET', 'PACKAGE_MANAGER', 'DIRECT_DOWNLOAD', 'OTHER']),
  source: z.string().min(1),
  official: z.boolean(),
  version: z.string().min(1),
  hash: z.string().min(1).optional(),
  signature: z.string().min(1).optional(),
});
export type ProviderAcquisition = z.infer<typeof ProviderAcquisitionSchema>;

export const ProviderDefinitionSchema = z.strictObject({
  providerId: z.string().min(1),
  revision: z.string().min(1),
  acquisition: ProviderAcquisitionSchema,
  provenanceFacts: z.record(z.string(), z.unknown()),
  licenseFacts: z.strictObject({
    license: z.string().min(1),
    redistributionAllowed: z.boolean().optional(),
  }),
  supportedPlatforms: z
    .array(
      z.strictObject({
        os: z.enum(['WINDOWS', 'LINUX', 'MACOS']),
        arch: z.enum(['X64', 'ARM64']).optional(),
        minVersion: z.string().min(1).optional(),
      }),
    )
    .min(1),
  lifecycle: z.strictObject({
    supportedOperations: z.array(ProviderLifecycleOperationSchema),
  }),
  interfaces: z.array(ProviderInterfaceSchema).min(1),
});
export type ProviderDefinition = z.infer<typeof ProviderDefinitionSchema>;

/** Inclusive capability revision support window of a binding. */
export const CapabilityRevisionRangeSchema = z.strictObject({
  min: z.string().min(1),
  max: z.string().min(1).optional(),
});
export type CapabilityRevisionRange = z.infer<typeof CapabilityRevisionRangeSchema>;

export const ProviderCapabilityBindingSchema = z.strictObject({
  bindingId: z.string().min(1),
  providerId: z.string().min(1),
  capabilityId: z.string().min(1),
  capabilityRevisionRange: CapabilityRevisionRangeSchema,
  adapterId: z.string().min(1),
  interfaceClass: InterfaceClassSchema,
  environmentRequirements: EnvironmentRequirementsSchema,
  verifierId: z.string().min(1),
});
export type ProviderCapabilityBinding = z.infer<typeof ProviderCapabilityBindingSchema>;
