// @shun/executor-windows — LocalWindowsBackend (P0, L2 §8.2) and the one-shot
// privileged elevated helper (§8.2.1/§9.3). Only the frozen contracts seams
// are exported: EnvironmentBackend, ExecutionBackend, and the recovery/
// journaling machinery the §9.4 classification is built on.

export { ACTION_ID_PATTERN, ActionIdRefusedError, assertSafeActionId } from './action-id.ts';
export type { ApplyContext, ApplyResult, WriterRefusalCode } from './authority-writer/apply.ts';
export { applyWriterJob, verifyWriterIdentity } from './authority-writer/apply.ts';
export type {
  PolicyWindow,
  PolicyWindowScopeBudget,
  WriterJob,
  WriterJobInput,
} from './authority-writer/job.ts';
export {
  PolicyWindowSchema,
  PolicyWindowScopeBudgetSchema,
  signWriterJob,
  WriterJobSchema,
} from './authority-writer/job.ts';
export type {
  AnchorWriterLaunchOptions,
  AnchorWriterLaunchResult,
} from './authority-writer/launcher.ts';
export { launchAnchorWriterJob } from './authority-writer/launcher.ts';
export type { LocalWindowsBackendOptions } from './backend.ts';
export { LocalWindowsBackend, PROVIDER_ID, PROVIDER_VERSION } from './backend.ts';
export {
  INTEGRITY_HIGH_SID,
  INTEGRITY_MEDIUM_SID,
  isElevatedToken,
  isFilteredToken,
} from './elevation.ts';
export type { Envelope, EnvelopeInput, HelperReceiptFile } from './envelope.ts';
export {
  ENVELOPE_SCHEMA_VERSION,
  EnvelopeSchema,
  HELPER_EXIT_CODES,
  readEnvelopeFile,
  writeEnvelopeFile,
} from './envelope.ts';
export { observeEnvironment } from './facts.ts';
export { resolveAgainstRoot, resolveWithinScope } from './fs-safety.ts';
export type { IdentityCheck } from './helper-pinning.ts';
export { verifyPinnedHelper } from './helper-pinning.ts';
export type { InterpreterContext, InterpreterScope, StepOutcome } from './interpreter.ts';
export {
  CancelledError,
  checkGuards,
  DeadlineError,
  parseRegQueryOutput,
  runStep,
} from './interpreter.ts';
export type {
  CorruptJournalLine,
  JournalEvent,
  JournalPhase,
  ReplayEvent,
  TornJournalLine,
} from './journal.ts';
export {
  isCorrupt,
  isTorn,
  JOURNAL_PHASES,
  JOURNAL_SCHEMA_VERSION,
  JournalWriter,
  journalDigest,
  journalHasCorrupt,
  journalHasExecStart,
  journalHasReceived,
  journalPhases,
  journalStepResults,
  readJournal,
} from './journal.ts';
export type { ExecutorOp, ExecutorStep } from './ops.ts';
export {
  checkRegistryKey,
  checkStepSurface,
  checkWindowsPath,
  EXECUTOR_OPS,
  ExecutorStepSchema,
} from './ops.ts';
export { reconcileExpectedState, rerunVerifyStep } from './poststate.ts';
export type { PrivilegedBackendOptions } from './privileged-backend.ts';
export {
  PrivilegedWindowsExecutionBackend,
  readHelperReceiptFile,
} from './privileged-backend.ts';
export type { ClassificationInput, ClassificationResult, PostStateOutcome } from './recovery.ts';
export { classifyRecovery, terminalForClassification } from './recovery.ts';
export type { HelperPin, ProgramPin, SystemToolsPin, WriterPin } from './trusted-store.ts';
export {
  FileCurrentnessSource,
  FileGrantSource,
  FilePlanSource,
  generateGrantHmacKey,
  HELPER_PIN_SCHEMA_VERSION,
  HelperPinSchema,
  hmacGrantIntegrityVerifier,
  PROGRAM_PIN_SCHEMA_VERSION,
  ProgramPinSchema,
  readHelperPin,
  readProgramPin,
  readSystemToolsPin,
  readWriterPin,
  resolveGrantHmacKeyFile,
  SYSTEM_TOOLS_PIN_SCHEMA_VERSION,
  SystemToolsPinSchema,
  sha256File,
  sha256Text,
  signGrantWithHmac,
  WRITER_PIN_SCHEMA_VERSION,
  WriterPinSchema,
  writeCurrentAuthority,
  writeGrantHmacKey,
  writeGrantRecord,
  writeHelperPin,
  writePlanRecord,
  writeProgramPin,
  writeSystemToolsPin,
  writeWriterPin,
} from './trusted-store.ts';
