// @shun/vertical-jit — Loop B trusted JIT software lifecycle (T06).
//
// The reference implementation of C-002 software.jit_capability_lifecycle:
// trusted acquisition → bounded use → semantic verification → RETAIN or
// gated R2 removal with fail-closed residue classification — all behind the
// frozen contracts ports.

export { FileJournal, NodeFilesystem, SpawnProcess } from './adapters/node.ts';
export {
  WINGET_SOURCE_NAME,
  WingetAcquisition,
  WingetPrivilegedBackend,
} from './adapters/winget.ts';
export type { FailureRecovery, JitFailureCode } from './failures.ts';
export { isJitLifecycleError, JitLifecycleError } from './failures.ts';
export type { JournalEntry, JournalPhase, JournalPort, RecoveryClassification } from './journal.ts';
export { classifyFromJournal, JOURNAL_PHASES, MemoryJournal, newJournalId } from './journal.ts';
export type { LocalAuthorityOptions } from './local-authority.ts';
export { LocalAuthority, MemoryPlanLedger } from './local-authority.ts';
export type { LocalBackendDeps, PerformOutcome, PrivilegedFault } from './local-backend.ts';
export { BackendInterruptError, LocalPrivilegedBackend } from './local-backend.ts';
export type { HarnessOptions, JitHarness, MemoryCatalogEntry } from './mocks.ts';
export {
  buildHarness,
  echoFor,
  jitCapabilityDefinition,
  MemoryFilesystem,
  MemoryStore,
  MockApproval,
  MockRegistry,
  providerIdFor,
  ScriptedProcessPort,
  trustedProviderDefinition,
  untrustedProviderDefinition,
  windowsFacts,
} from './mocks.ts';
export type {
  ImportableAuthorizationPort,
  JitLifecycleDeps,
  RemovalPreviewHints,
} from './orchestrator.ts';
export { runJitBenchmarkLifecycle, runJitLifecycle } from './orchestrator.ts';
export { buildActionPlan, installAction, taskAction, uninstallAction } from './plans.ts';
export {
  type AcquisitionCandidate,
  AcquisitionError,
  type AcquisitionFailureKind,
  type AcquisitionPort,
  type FilesystemPort,
  type JitDurablePolicy,
  type PlanLedgerPort,
  type ProcessPort,
  type ProcessResult,
  type ProcessRunSpec,
  type ProviderInstallLayout,
} from './ports.ts';
export {
  evaluateProviderProvenance,
  provenanceRecord,
  requireTrustedProvider,
} from './provenance.ts';
export type { ResidueCandidate, ResidueClassificationInput } from './residue.ts';
export {
  assertNoProtectedDeletions,
  classifyPath,
  classifyResidue,
  dispositionFor,
} from './residue.ts';
export { PatternVerifier } from './verifiers.ts';
