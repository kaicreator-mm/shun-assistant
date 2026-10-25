// T07 F01/F02A pure preview-only public API plus the F02B trusted host
// bridge. The host bridge performs real anchored OS observation only; no
// grant, mutation or caller-supplied authority is exposed.

export {
  type DuplicateCandidateResult,
  type ReportedDuplicateCandidates,
  reportDuplicateCandidates,
} from './candidate-inventory.ts';
export {
  attestsFixedLocalVolume,
  type HostDuplicateObservation,
  type HostObservationInstrument,
  type HostObservationRefusalCode,
  type HostObservationResult,
  type HostObservationStage,
  observeVerifiedFileDuplicates,
  type VerifiedDuplicateGroup,
} from './host-observation.ts';
export {
  type FilePreview,
  type FilePreviewRequest,
  type FilePreviewResult,
  previewScopedFileOperation,
} from './preview.ts';
