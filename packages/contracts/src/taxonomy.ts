// Frozen failure/safety taxonomy for Shun v0.1.
// Every enum here is frozen authority: L2 architecture (docs/architecture/L2-v0.1.md §4, §5.1, §9.2, §9.4)
// and Product capability contracts (docs/product/capability-contracts-v0.1.md C-000..C-003).
// Codes may only change with a deliberate Product/L2 amendment, never silently.
import { z } from 'zod';

/** Side-effect / risk classes (L2 §9.2). R2 uses the conservative interpretation for bulk move/rename and lifecycle removal. */
export const RISK_CLASSES = ['R0', 'R1', 'R2', 'R3'] as const;
export type RiskClass = (typeof RISK_CLASSES)[number];
export const RiskClassSchema = z.enum(RISK_CLASSES);

/** Provider interface classes. I0 library/API, I1 structured CLI, I2 file interface, I3 semantic UI, I4 vision fallback (Product capability contracts). */
export const INTERFACE_CLASSES = ['I0', 'I1', 'I2', 'I3', 'I4'] as const;
export type InterfaceClass = (typeof INTERFACE_CLASSES)[number];
export const InterfaceClassSchema = z.enum(INTERFACE_CLASSES);

/** Ambiguity is first-class (L2 §4.1). */
export const AMBIGUITY_DISPOSITIONS = [
  'READY',
  'NEEDS_CLARIFICATION',
  'UNRESOLVED_OBJECT',
  'UNRESOLVED_CAPABILITY',
  'VERIFICATION_UNSPECIFIABLE',
  'POLICY_BLOCKED',
] as const;
export type AmbiguityDisposition = (typeof AMBIGUITY_DISPOSITIONS)[number];
export const AmbiguityDispositionSchema = z.enum(AMBIGUITY_DISPOSITIONS);

/** Shared resolution failure taxonomy (Product C-000). */
export const RESOLUTION_FAILURES = [
  'GOAL_AMBIGUOUS',
  'OBJECT_UNRESOLVED',
  'CAPABILITY_UNRESOLVED',
  'NO_TRUSTED_PROVIDER',
  'NO_FEASIBLE_BINDING',
  'POLICY_BLOCKED',
  'VERIFICATION_UNSPECIFIABLE',
  'REGISTRY_CURRENTNESS_INSUFFICIENT',
] as const;
export type ResolutionFailure = (typeof RESOLUTION_FAILURES)[number];
export const ResolutionFailureSchema = z.enum(RESOLUTION_FAILURES);

/** C-001 image.batch_process failure taxonomy (Product C-001), plus the shared C-000 codes. */
export const IMAGE_BATCH_FAILURES = [
  'UNSUPPORTED_INPUT',
  'DECODE_FAILED',
  'OUTPUT_COLLISION',
  'METADATA_LOST',
  'QUALITY_ORACLE_FAILED',
  'OUTPUT_VERIFY_FAILED',
] as const;
export type ImageBatchFailure = (typeof IMAGE_BATCH_FAILURES)[number];
export const ImageBatchFailureSchema = z.enum(IMAGE_BATCH_FAILURES);

/** C-002 software.jit_capability_lifecycle failure taxonomy (Product C-002), plus the shared C-000 codes. */
export const JIT_LIFECYCLE_FAILURES = [
  'PROVENANCE_UNKNOWN',
  'ACQUISITION_FAILED',
  'INSTALL_FAILED',
  'TASK_FAILED',
  'TASK_VERIFY_FAILED',
  'R2_GATE_MISSING',
  'RESIDUE_UNKNOWN',
  'USER_ASSET_AT_RISK',
  'REMOVE_FAILED',
  'POST_REMOVE_VERIFY_FAILED',
] as const;
export type JitLifecycleFailure = (typeof JIT_LIFECYCLE_FAILURES)[number];
export const JitLifecycleFailureSchema = z.enum(JIT_LIFECYCLE_FAILURES);

/** C-003 system.storage.diagnose_bounded_action failure taxonomy (Product C-003), plus the shared C-000 codes. */
export const STORAGE_DIAGNOSE_FAILURES = [
  'GROWTH_NOT_ATTRIBUTED',
  'DATA_CLASSIFICATION_UNKNOWN',
  'R2_GATE_MISSING',
  'PROTECTED_ASSET_TOUCHED',
  'RECLAIM_NOT_VERIFIED',
  'ACTION_NOT_BOUNDED',
] as const;
export type StorageDiagnoseFailure = (typeof STORAGE_DIAGNOSE_FAILURES)[number];
export const StorageDiagnoseFailureSchema = z.enum(STORAGE_DIAGNOSE_FAILURES);

/** Durable side-effect recovery classification, derived ONLY from the privileged phase journal plus independent post-state verification (L2 §9.4). */
export const RECOVERY_CLASSIFICATIONS = [
  'NOT_STARTED',
  'FAILED_BEFORE_EFFECT',
  'MAY_HAVE_EXECUTED_UNCERTAIN',
  'COMPLETED_VERIFIED',
] as const;
export type RecoveryClassification = (typeof RECOVERY_CLASSIFICATIONS)[number];
export const RecoveryClassificationSchema = z.enum(RECOVERY_CLASSIFICATIONS);

/** Reference task workflow states (L2 §5.1). Finite and explicit; not an autonomous loop. */
export const TASK_STATES = [
  'RECEIVED',
  'INTERPRETING',
  'CLARIFICATION',
  'RESOLVING',
  'PLANNED',
  'AWAITING_AUTHORIZATION',
  'EXECUTING',
  'VERIFYING',
  'LIFECYCLE_RECONCILIATION',
  'SUCCEEDED',
  'FAILED',
  'CANCELLED',
  'NEEDS_INTERVENTION',
] as const;
export type TaskState = (typeof TASK_STATES)[number];
export const TaskStateSchema = z.enum(TASK_STATES);

/** Execution receipt terminal outcomes (L2 §4.7, §8.2.1). */
export const EXECUTION_TERMINALS = [
  'SUCCEEDED',
  'FAILED',
  'REFUSED',
  'CANCELLED',
  'TIMED_OUT',
  'UAC_DECLINED',
  'UNCERTAIN',
] as const;
export type ExecutionTerminal = (typeof EXECUTION_TERMINALS)[number];
export const ExecutionTerminalSchema = z.enum(EXECUTION_TERMINALS);

/** Authorization kinds (L2 §4.6). Every AuthorizedAction carries a grant regardless of kind (L2 §4.6.1). */
export const AUTHORIZATION_KINDS = ['AUTOMATIC', 'EXPLICIT_APPROVAL', 'DURABLE_POLICY'] as const;
export type AuthorizationKind = (typeof AUTHORIZATION_KINDS)[number];
export const AuthorizationKindSchema = z.enum(AUTHORIZATION_KINDS);

/** Verification receipt status (L2 §4.7): PASS | FAIL | INCOMPLETE. */
export const VERIFICATION_STATUSES = ['PASS', 'FAIL', 'INCOMPLETE'] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];
export const VerificationStatusSchema = z.enum(VERIFICATION_STATUSES);

/** Recipe currentness (L2 §6.9). UNKNOWN fails closed to the higher planning layer. */
export const RECIPE_CURRENTNESS = ['CURRENT', 'STALE', 'INAPPLICABLE', 'UNKNOWN'] as const;
export type RecipeCurrentness = (typeof RECIPE_CURRENTNESS)[number];
export const RecipeCurrentnessSchema = z.enum(RECIPE_CURRENTNESS);

/** Recipe lifecycle (L2 §6.9). P1-conditional persistence; the state space itself is frozen. */
export const RECIPE_LIFECYCLE_STATES = ['CANDIDATE', 'ACTIVE', 'QUARANTINED', 'RETIRED'] as const;
export type RecipeLifecycleState = (typeof RECIPE_LIFECYCLE_STATES)[number];
export const RecipeLifecycleStateSchema = z.enum(RECIPE_LIFECYCLE_STATES);

/** Grant validation rejection codes (L2 §4.6.1). Every code fails closed before any side effect. */
export const GRANT_REJECTION_CODES = [
  'GRANT_MALFORMED',
  'GRANT_NOT_AUTHENTIC',
  'GRANT_CURRENTNESS_UNRESOLVABLE',
  'GRANT_AUTHORITY_STALE',
  'GRANT_POLICY_STALE',
  'GRANT_POLICY_REVOKED',
  'GRANT_REVOKED',
  'GRANT_EXPIRED',
  'GRANT_PLAN_MISMATCH',
  'GRANT_SCOPE_MISMATCH',
  'GRANT_APPROVAL_REF_MISSING',
] as const;
export type GrantRejectionCode = (typeof GRANT_REJECTION_CODES)[number];
export const GrantRejectionCodeSchema = z.enum(GRANT_REJECTION_CODES);

/** All frozen failure codes that a structured Shun failure may carry. */
export const FAILURE_CODES = [
  ...RESOLUTION_FAILURES,
  ...IMAGE_BATCH_FAILURES,
  ...JIT_LIFECYCLE_FAILURES,
  ...STORAGE_DIAGNOSE_FAILURES,
] as const;
export type FailureCode = (typeof FAILURE_CODES)[number];
export const FailureCodeSchema = z.enum(FAILURE_CODES);

/** Typed error raised by contract parsers and validators. Never represents execution outcomes. */
export const CONTRACT_ERROR_CODES = ['SCHEMA_VIOLATION', ...GRANT_REJECTION_CODES] as const;
export type ContractErrorCode = (typeof CONTRACT_ERROR_CODES)[number];

export class ShunContractError extends Error {
  readonly code: ContractErrorCode;
  readonly issues?: unknown;

  constructor(code: ContractErrorCode, message: string, issues?: unknown) {
    super(message);
    this.name = 'ShunContractError';
    this.code = code;
    this.issues = issues;
  }
}

/** Shared base fields for every durable contract record. */
export const IsoDateTimeSchema = z.iso.datetime({
  error: 'must be an ISO 8601 UTC datetime string',
});
export type IsoDateTime = z.infer<typeof IsoDateTimeSchema>;

export const Sha256HexSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, 'must be a lowercase 64-char hex SHA-256 digest');
export type Sha256Hex = z.infer<typeof Sha256HexSchema>;
