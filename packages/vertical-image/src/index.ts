// @shun/vertical-image — T05 Loop A reference vertical: image.batch_process.
//
// Scope note: this package owns the C-001 business adapter, the precommitted
// SSIM oracle and the semantic verifier ONLY. Trust screening, goal parsing
// and the shared Provider×Environment resolver belong to other tasks; the
// vertical ranks pre-screened candidates and executes one binding.

export { type Dims, scaledDims } from './dims.ts';
export {
  type BatchRunResult,
  type BatchTaskFailure,
  type RunDeps,
  runImageBatchProcess,
} from './executor.ts';
export { readExifCaptureDate } from './exif.ts';
export {
  decodeRgbaBytes,
  inspectBytes,
  inspectFile,
  type SourceFacts,
  sha256Hex,
} from './inspect.ts';
export {
  type CommittedOracle,
  commitOracle,
  MAX_ORACLE_SAMPLES,
  ORACLE_REVISION,
  type OracleSample,
  oracleReferencePath,
  SSIM_OPTIONS,
  selectSampleEntries,
} from './oracle.ts';
export {
  type BindingView,
  type ImageFormat,
  type ImageProvider,
  ImageProviderError,
  type ResizeOutcome,
  type ResizeRequest,
} from './provider.ts';
export {
  type BindingCandidate,
  type BindingSelection,
  infeasibilityReasons,
  RANKING_POLICY_REVISION,
  type SelectionOutcome,
  selectBinding,
} from './selector.ts';
export {
  makeSharpImageProvider,
  SHARP_BINDING_ID,
  SHARP_JPEG_QUALITY,
  sharpBindingView,
} from './sharp-engine.ts';
export { type ImageContainer, sniffContainer } from './sniff.ts';
export {
  type BatchRecord,
  METRIC_IDENTITY,
  makeSsimJsMetric,
  type SsimMetric,
  VERIFIER_ID,
  VERIFIER_REVISION,
  type VerifyBatchArgs,
  verifyBatch,
} from './verifier.ts';
