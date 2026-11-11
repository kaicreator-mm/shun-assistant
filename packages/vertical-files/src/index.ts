// T07 F01/F02A pure preview-only public API plus the F02B authorized host
// bridge. The host bridge performs real anchored OS observation only behind
// the R1 authorization mediation: the sole physical entry
// (observeAuthorizedFileDuplicates) consumes an ActionController
// AuthorizedAction bound to the exact observed scope — no public
// user-supplied root and no caller callbacks. The `{scopeRoot}` test seam
// and its instrument type are package-internal (host-observation.ts) and
// deliberately NOT re-exported here, so nothing outside this package can
// initiate an unmediated scan or inject execution hooks.

export {
  type DuplicateCandidateResult,
  type ReportedDuplicateCandidates,
  reportDuplicateCandidates,
} from './candidate-inventory.ts';
export {
  attestsFixedLocalVolume,
  type HostDuplicateObservation,
  type HostObservationRefusalCode,
  type HostObservationResult,
  observeAuthorizedFileDuplicates,
  type VerifiedDuplicateGroup,
} from './host-observation.ts';
export {
  type FilePreview,
  type FilePreviewRequest,
  type FilePreviewResult,
  previewScopedFileOperation,
} from './preview.ts';
