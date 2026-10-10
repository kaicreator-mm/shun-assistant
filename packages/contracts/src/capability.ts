// CapabilityDefinition (L2 §4.2). C-000..C-003 are the frozen reference
// semantics; runtime definitions are machine-readable JSON Schema plus
// generated TypeScript types.
//
// Benchmark-fixture-only fields (synthetic growth injectors, hidden test
// truth, protected-asset canaries) MUST NOT become required production
// Capability inputs (L2 §4.2) — Product semantic fields and Validation fixture
// fields stay separated even when a fixture document presents them together.
import { z } from 'zod';
import { InterfaceClassSchema, RiskClassSchema } from './taxonomy.ts';

/** An inline JSON Schema document (draft 2020-12) carried by a contract field. */
export const JsonSchemaDocSchema = z.record(z.string(), z.unknown());
export type JsonSchemaDoc = z.infer<typeof JsonSchemaDocSchema>;

/** One declared semantic check a verifier must be able to replay. */
export const VerificationCheckSpecSchema = z.strictObject({
  checkId: z.string().min(1),
  description: z.string().min(1).optional(),
  required: z.boolean(),
});
export type VerificationCheckSpec = z.infer<typeof VerificationCheckSpecSchema>;

/**
 * Verification contract of a capability: which verifier identity and checks
 * are required so that execution success without semantic verification can
 * never become Task PASS (L2 §4.7).
 */
export const VerificationContractSchema = z.strictObject({
  verifierId: z.string().min(1),
  verifierRevision: z.string().min(1),
  checks: z.array(VerificationCheckSpecSchema).min(1),
});
export type VerificationContract = z.infer<typeof VerificationContractSchema>;

export const CapabilityDefinitionSchema = z.strictObject({
  capabilityId: z.string().min(1),
  revision: z.string().min(1),
  inputSchema: JsonSchemaDocSchema,
  outputSchema: JsonSchemaDocSchema,
  sideEffectClass: RiskClassSchema,
  allowedInterfaceClasses: z.array(InterfaceClassSchema).min(1),
  verificationContract: VerificationContractSchema,
  /** Policy fact keys that must be current before any side-effecting execution. */
  requiredPolicyFacts: z.array(z.string().min(1)),
});
export type CapabilityDefinition = z.infer<typeof CapabilityDefinitionSchema>;
