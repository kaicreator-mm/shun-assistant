// T07 F01/F02A pure preview-only public API. No filesystem handle, grant,
// mutation, trusted inventory or verified duplicate-content claim is exposed.

export {
  type DuplicateCandidateResult,
  type ReportedDuplicateCandidates,
  reportDuplicateCandidates,
} from './candidate-inventory.ts';
export {
  type FilePreview,
  type FilePreviewRequest,
  type FilePreviewResult,
  previewScopedFileOperation,
} from './preview.ts';
