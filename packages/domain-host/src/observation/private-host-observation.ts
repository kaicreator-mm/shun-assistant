/**
 * Trusted Host-only issuer adapter. This file MUST NOT be re-exported by the
 * @shun/domain-host public root, and both Shun domain packages use package
 * "exports" maps preventing deep imports from untrusted public consumers.
 *
 * The semantic selector's WeakSet registration remains in its private module
 * identity. Issuance happens only after the host observer returned a bounded
 * current observation; UI/Planner JSON never calls this function.
 */
import {
  issueHostObjectObservation,
  type HostObjectObservationEvidence,
} from '../../../domain-computer/src/semantic/goal-semantic.ts';

export interface TrustedHostObservation {
  readonly sourceRef: string;
  readonly revision: string;
  readonly taskId: string;
  readonly observedObjectRefs: readonly string[];
  readonly observedAtUnixMs: number;
  readonly expiresAtUnixMs: number;
}

export interface TrustedHostObserver {
  observe(taskId: string): Promise<TrustedHostObservation | null>;
}

export function createPrivateHostObservationIssuer(
  observer: TrustedHostObserver,
  replayFence: { accept(record: {
    taskId: string; sourceRef: string; revision: string;
    issuedAtUnixMs: number; expiresAtUnixMs: number;
  }, nowUnixMs: number): boolean },
) {
  if (!observer || typeof observer.observe !== 'function' ||
      !replayFence || typeof replayFence.accept !== 'function') {
    throw new TypeError('TRUSTED_HOST_OBSERVER_REQUIRED');
  }
  return Object.freeze({
    async issue(taskId: string, nowUnixMs: number): Promise<HostObjectObservationEvidence | null> {
      if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/.test(taskId) ||
          !Number.isSafeInteger(nowUnixMs)) return null;
      let record: TrustedHostObservation | null;
      try {
        record = await observer.observe(taskId);
      } catch {
        return null;
      }
      if (!record || record.taskId !== taskId ||
          record.observedAtUnixMs > nowUnixMs ||
          record.expiresAtUnixMs <= nowUnixMs) return null;
      // A crash/restart cannot make an old Host revision reusable. This
      // persisted fence must commit before the single-process WeakSet mark.
      if (!replayFence.accept({
        taskId, sourceRef: record.sourceRef, revision: record.revision,
        issuedAtUnixMs: record.observedAtUnixMs,
        expiresAtUnixMs: record.expiresAtUnixMs,
      }, nowUnixMs)) return null;
      return issueHostObjectObservation({
        schema: 'shun.host-object-observation.v1',
        sourceRef: record.sourceRef,
        revision: record.revision,
        taskId,
        observedObjectRefs: record.observedObjectRefs,
        issuedAtUnixMs: record.observedAtUnixMs,
        expiresAtUnixMs: record.expiresAtUnixMs,
      });
    },
  });
}
