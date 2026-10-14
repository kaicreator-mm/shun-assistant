// @shun/control-api — T08 minimal local control surface API.
//
// Authority: docs/architecture/L2-v0.1.md §12 (control surface), §9.1/§9.4
// (Action Controller / recovery — displayed, never owned). This package is
// non-authoritative: it renders typed previews, relays approval decisions
// bound to the exact plan hash, reports progress/recovery/residue readably,
// and refuses to create authorization or leave loopback.

export { type DemoBackendOptions, DemoShunBackend, summarizeResidue } from './demo/backend.ts';
export {
  buildCleanupResidue,
  buildImageBatchPlan,
  buildStorageCleanupPlan,
  type DemoResidueItem,
  demoIntentFor,
  readableBytes,
} from './demo/plans.ts';
export * from './errors.ts';
export * from './ports.ts';
export {
  previewForPlan,
  requiresExplicitApproval,
  riskStatement,
  worstRiskClass,
} from './preview.ts';
export {
  CONTROL_API_REVISION,
  type ControlServerHandle,
  type ControlServerOptions,
  createControlServer,
} from './server.ts';
