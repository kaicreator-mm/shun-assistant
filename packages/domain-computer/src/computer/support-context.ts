/**
 * T02: B-040 read-only Computer Business adapter.
 *
 * The public @shun/vertical-support API remains the sole actual Windows
 * collector/minimizer. No second process runner, filesystem traversal, remote
 * service, provider, LLM, telemetry, or background collector exists here.
 *
 * The source package contains two different trust levels:
 * - ACTUAL_WINDOWS_HOST: a real public collector result on Windows;
 * - FIXTURE_ONLY: untrusted raw data minimized for offline negative tests.
 * A fixture MUST never be accepted as a real Host observation.
 */
import {
  collectWindowsSupportContext,
  minimizeSupportContext,
  type SupportContextResult,
  SupportContextResultSchema,
} from '@shun/vertical-support';

export const COMPUTER_SUPPORT_CONTEXT_SCHEMA = 'shun.computer.support-context.v03' as const;
export type ComputerSupportSource = 'ACTUAL_WINDOWS_HOST' | 'FIXTURE_ONLY';

export interface ComputerSupportContext {
  readonly schema: typeof COMPUTER_SUPPORT_CONTEXT_SCHEMA;
  readonly source: ComputerSupportSource;
  readonly result: SupportContextResult;
}

function deeplyFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deeplyFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

/**
 * Re-parse the final minimized report before releasing it. The result has no
 * external disclosure channel and never includes raw environment, process
 * command lines, unrelated document contents, or collected absolute paths.
 */
function sealSafeReport(source: ComputerSupportSource, value: unknown): ComputerSupportContext {
  const parsed = SupportContextResultSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error('COMPUTER_CONTEXT_INVALID: B040_MINIMIZED_REPORT_REQUIRED');
  }
  const safe = parsed.data;
  if (
    safe.localOnly !== true ||
    safe.externalDisclosures.length !== 0 ||
    safe.report.schema !== 'shun.support-context.v1'
  ) {
    throw new Error('COMPUTER_CONTEXT_INVALID: LOCAL_ONLY_BOUNDARY');
  }
  return deeplyFreeze({
    schema: COMPUTER_SUPPORT_CONTEXT_SCHEMA,
    source,
    result: safe,
  });
}

/**
 * Real Windows-only, read-only B-040 collection.
 *
 * On any other platform the frozen collector rejects. No caller-supplied
 * runner, root, command, environment, reporter, URL or raw report is accepted.
 * An OS action is not initiated by this wrapper beyond the existing trusted
 * B-040 collector's strictly read-only diagnostic invocations.
 */
export async function collectLocalComputerSupportContext(): Promise<ComputerSupportContext> {
  const minimized = await collectWindowsSupportContext();
  return sealSafeReport('ACTUAL_WINDOWS_HOST', minimized);
}

/**
 * OFFLINE TEST-ONLY minimization entry. Raw input is untrusted; returned data
 * is labeled FIXTURE_ONLY so it cannot falsely attest actual Windows Host
 * provenance. This does not invoke the Host collector or any remote channel.
 */
export function minimizeComputerSupportFixture(rawObservation: unknown): ComputerSupportContext {
  const safe = minimizeSupportContext(rawObservation);
  return sealSafeReport('FIXTURE_ONLY', safe);
}

/**
 * The trusted Host composition root must call collectLocalComputerSupportContext
 * directly. No public 'verify source label' helper is provided: source strings
 * and structural parsing cannot authenticate an arbitrary caller's Host
 * provenance.
 */
