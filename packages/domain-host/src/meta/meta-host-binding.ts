/**
 * R03-INT — trusted production install seam binding the selected K's sealed
 * Meta-feedback capability (`shun-meta-host`) to the REAL durable Shadow
 * store (OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 *
 * The composing trusted process installs ONE binding over the operator's
 * durable HostMetaShadowStore. Every submission goes through the frozen
 * MetaFeedbackAdapter contract: opt-in consent + genuine outcome receipt are
 * resolved from the durable store (never caller JSON), only a
 * FUTURE_BUILD_SHADOW inactive candidate can persist, and an unresolved Host
 * outcome stays UNKNOWN for the K journal — never a fake terminal success.
 */
import { createMetaFeedbackAdapter } from '../../../domain-computer/src/feedback/meta-feedback.ts';
import { HostMetaShadowStore } from './host-meta-shadow-store.ts';

let installed: {
  readonly store: HostMetaShadowStore;
  readonly adapter: ReturnType<typeof createMetaFeedbackAdapter>;
} | undefined;

export function installTrustedMetaBinding(config: {
  readonly store: HostMetaShadowStore;
}): void {
  if (installed !== undefined) throw new Error('META_HOST_ALREADY_INSTALLED');
  if (!config?.store || typeof config.store.runMetaFeedbackWorkflow !== 'function') {
    throw new Error('META_HOST_CONFIGURATION_REFUSED');
  }
  installed = {
    store: config.store,
    adapter: createMetaFeedbackAdapter(config.store),
  };
}

/** K→C callback: one opt-in feedback submission → durable Shadow candidate. */
export async function submitMetaFeedback(
  payload: unknown,
  _dispatchContext: unknown,
): Promise<
  | {
      readonly phase: 'terminal';
      readonly externalRef: string;
      readonly outcome:
        | { readonly ok: true; readonly output: Record<string, unknown> }
        | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };
    }
> {
  if (installed === undefined) throw new Error('META_HOST_NOT_INSTALLED');
  const result = await installed.adapter.submit(payload);
  if (result.status === 'STORED_SHADOW') {
    return {
      phase: 'terminal',
      externalRef: result.candidateRef,
      outcome: {
        ok: true,
        output: {
          status: 'STORED_SHADOW',
          candidateRef: result.candidateRef,
          candidateDigest: result.candidateDigest,
          active: false,
        },
      },
    };
  }
  if (result.status === 'NOT_SELECTED') {
    // Absolute no-op: nothing parsed, persisted or authorized.
    return {
      phase: 'terminal',
      externalRef: 'meta-feedback-not-selected',
      outcome: { ok: true, output: { status: 'NOT_SELECTED' } },
    };
  }
  if (result.status === 'UNKNOWN') {
    // The Host may have committed before losing its response: the K journal
    // owns reconciliation, never a fake terminal success or blind retry.
    const error = new Error('META_OUTCOME_UNKNOWN: meta feedback outcome requires reconciliation');
    throw error;
  }
  return {
    phase: 'terminal',
    externalRef: 'meta-feedback',
    outcome: {
      ok: false,
      error: { code: result.code, message: 'trusted Meta Host refused the feedback' },
    },
  };
}

/** Trusted-process evidence accessor. */
export function trustedMetaBindingStatus(): Readonly<{ installed: boolean }> {
  return { installed: installed !== undefined };
}
