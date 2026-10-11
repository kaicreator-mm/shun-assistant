// @shun/vertical-support — frozen B-040 local support-context privacy path.
// R0 only: scoped local observation → deterministic minimization/redaction →
// local structured report. No network or remote planner dependency exists.
export { minimizeSupportContext } from './minimize.ts';
export type {
  RedactionRecord,
  SupportContextResult,
  SupportObservation,
  SupportReport,
} from './schema.ts';
export {
  RedactionRecordSchema,
  SupportContextResultSchema,
  SupportObservationSchema,
  SupportReportSchema,
} from './schema.ts';
export type { WindowsCollectorDeps } from './windows.ts';
export { collectWindowsSupportContext } from './windows.ts';
