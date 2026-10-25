// T07 preview-only public API. This package DOES NOT expose a filesystem
// mutation API. A trusted Windows Host and ActionController must perform
// fresh OS/scope checks and issue durable effect journal records before I/O.
export {
  type FilePreview,
  type FilePreviewRequest,
  type FilePreviewResult,
  previewScopedFileOperation,
} from './preview.ts';
