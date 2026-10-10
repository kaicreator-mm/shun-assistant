// Typed failures for the Loop B JIT lifecycle vertical (T06).
//
// Every failure carries a code from the frozen taxonomies: the C-002 failure
// list plus the shared C-000 resolution failures (taxonomy.ts). Failures are
// values, not strings: the orchestrator and its tests match on `code`, and
// evidence records serialize them verbatim.
import {
  type JitLifecycleFailure,
  type ResolutionFailure,
  ShunContractError,
} from '@shun/contracts';

/** Codes a JIT lifecycle run can fail with (C-002 taxonomy + shared C-000 codes). */
export type JitFailureCode = JitLifecycleFailure | ResolutionFailure;

/** Recovery-terminal detail for a failed privileged action (L2 §9.4 classification). */
export type FailureRecovery = {
  actionId: string;
  recoveryClassification:
    | 'NOT_STARTED'
    | 'FAILED_BEFORE_EFFECT'
    | 'MAY_HAVE_EXECUTED_UNCERTAIN'
    | 'COMPLETED_VERIFIED';
  detail: string;
};

export class JitLifecycleError extends Error {
  readonly code: JitFailureCode;
  /** Structural failure detail; never a substitute for the frozen code. */
  readonly detail: string;
  /** Present when the failure concerns a privileged action (install/uninstall). */
  readonly recovery?: FailureRecovery;

  constructor(code: JitFailureCode, detail: string, recovery?: FailureRecovery) {
    super(`[${code}] ${detail}`);
    this.name = 'JitLifecycleError';
    this.code = code;
    this.detail = detail;
    this.recovery = recovery;
  }
}

/** Re-export so consumers of this package never parse error strings. */
export { ShunContractError };

export function isJitLifecycleError(value: unknown): value is JitLifecycleError {
  return value instanceof JitLifecycleError;
}
