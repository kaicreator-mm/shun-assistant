// Loop C vertical: scoped Windows storage observation, evidence-backed
// attribution, fail-closed classification, R2-bounded cleanup with observable
// gates, and semantic verification (frozen C-003 semantics; L2 §14.3).

export { type Attribution, attributeGrowth } from './attribute.ts';
export { type BenchmarkRunOutcome, runStorageDiagnoseBenchmark } from './benchmark.ts';
export {
  type ClassificationPolicy,
  type ClassificationResult,
  type CleanupCategory,
  classifyDirectory,
  classifyLooseRootFile,
  DISPOSABLE_SEGMENT_MARKERS,
  touchesProtectedAsset,
} from './classify.ts';
export {
  runStorageDiagnose,
  type StorageDiagnosePorts,
  type StorageDiagnoseResult,
  type StorageDiagnoseRuntime,
} from './diagnose.ts';
export { StorageVerticalError } from './errors.ts';
export {
  type CleanupExecutionResult,
  executeBoundedCleanup,
  reconcileAfterInterruption,
} from './execute.ts';
export {
  classifyFromJournal,
  type JournalEntry,
  type JournalReplay,
  PhaseJournal,
  replayJournal,
} from './journal.ts';
export {
  type DirectoryStat,
  measureDirectoryNow,
  type ObservationEvidence,
  observeStorage,
} from './observe.ts';
export {
  buildCleanupPlan,
  type CleanupPlanProposal,
  type CleanupTarget,
  renderPreview,
  STORAGE_CLEAN_VERIFIER_ID,
  STORAGE_CLEAN_VERIFIER_REVISION,
} from './plan.ts';
export {
  pathOnVolume,
  type ResolvedScope,
  resolveScope,
  type StorageScope,
  withinScope,
} from './scope.ts';
export {
  fingerprintPath,
  hashFile,
  type ProtectedBaseline,
  type ProtectedVerification,
  type StorageVerifierDeps,
  VERIFIER_ID,
  VERIFIER_REVISION,
  verifyProtectedAssets,
  verifyStorageCleanup,
} from './verify.ts';
