/**
 * T01 — trusted K→C Windows Host boundary.
 *
 * This module intentionally has no SDK deep import and no public Domain App
 * export. T11 binds dispatch() only as the selected K-gated Host operation.
 * K owns the effect Permit/Journal/Replay/UNKNOWN; this adapter adds the
 * independent Shun ActionController and current OS-authority checks.
 */

export interface KernelEffectDispatchContext {
  readonly capabilityId: string;
  readonly operationId: string;
  readonly effectPermit: Readonly<{
    effectId: string;
    durableControlTurnId: string;
    attempt: number;
  }>;
}

export interface KernelEffectPermitIdentity {
  readonly effectId: string;
  readonly durableControlTurnId: string;
  readonly attempt: number;
}

export interface WindowsEffectBinding {
  readonly capabilityId: string;
  readonly operationId: string;
}

export interface WindowsEffectPayload {
  readonly actionRef: string;
  readonly planRef: string;
  readonly grantRef: string;
}

export interface ResolvedWindowsAuthorization {
  readonly effectId: string;
  readonly plan: unknown;
  readonly action: unknown;
  readonly grant: unknown;
}

export interface WindowsAuthorizationSource {
  /** Resolve only from trusted Shun authority storage; never from caller JSON. */
  resolve(input: {
    readonly effectId: string;
    readonly actionRef: string;
    readonly planRef: string;
    readonly grantRef: string;
  }): Promise<unknown>;
}

export interface ShunActionControllerPort {
  authorizeEffect(input: {
    readonly plan: unknown;
    readonly action: unknown;
    readonly grant: unknown;
  }): Promise<unknown>;
}

export interface WindowsOsAuthorityPort {
  /** Fresh OS/UAC/path/object currentness for this exact effect/action. */
  recheck(input: {
    readonly effectId: string;
    readonly action: unknown;
  }): Promise<unknown>;
}

export interface WindowsEffectPort {
  /** One effect boundary. T11 binds the existing trusted Windows executor. */
  execute(input: {
    readonly effectId: string;
    readonly action: unknown;
  }): Promise<unknown>;
}

export type WindowsHostEnvelope =
  | {
      readonly phase: 'terminal';
      readonly externalRef: string;
      readonly outcome:
        | { readonly ok: true; readonly output: unknown }
        | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };
    }
  | { readonly phase: 'running'; readonly externalRef: string };

const SAFE_ID = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length &&
    keys.every((key, index) => key === [...expected].sort()[index]);
}

function safeId(value: unknown): value is string {
  return typeof value === 'string' && SAFE_ID.test(value);
}

/**
 * Structural projection of the selected K gate's callback context.
 * It is not an authority source by itself: this callback is private Host
 * wiring, and T11 must bind it only behind the real selected K external-effect
 * gate. The K gate itself performs the durable permit/journal/fence read.
 */
export function readKernelEffectPermit(raw: unknown): KernelEffectPermitIdentity | null {
  try {
    if (!isRecord(raw) ||
        !exactKeys(raw, ['capabilityId', 'operationId', 'effectPermit']) ||
        !safeId(raw.capabilityId) ||
        !safeId(raw.operationId) ||
        !isRecord(raw.effectPermit) ||
        !exactKeys(raw.effectPermit, ['effectId', 'durableControlTurnId', 'attempt']) ||
        !safeId(raw.effectPermit.effectId) ||
        !safeId(raw.effectPermit.durableControlTurnId) ||
        !Number.isSafeInteger(raw.effectPermit.attempt) ||
        (raw.effectPermit.attempt as number) < 1) {
      return null;
    }
    return Object.freeze({
      effectId: raw.effectPermit.effectId,
      durableControlTurnId: raw.effectPermit.durableControlTurnId,
      attempt: raw.effectPermit.attempt as number,
    });
  } catch {
    return null;
  }
}

function parsePayload(raw: unknown): WindowsEffectPayload | null {
  try {
    if (!isRecord(raw) ||
        !exactKeys(raw, ['actionRef', 'planRef', 'grantRef']) ||
        !safeId(raw.actionRef) ||
        typeof raw.planRef !== 'string' ||
        !SHA256.test(raw.planRef) ||
        !safeId(raw.grantRef)) {
      return null;
    }
    return Object.freeze({
      actionRef: raw.actionRef,
      planRef: raw.planRef,
      grantRef: raw.grantRef,
    });
  } catch {
    return null;
  }
}

function identityMatches(
  resolved: unknown,
  permit: KernelEffectPermitIdentity,
  payload: WindowsEffectPayload,
): resolved is ResolvedWindowsAuthorization {
  if (!isRecord(resolved) ||
      !exactKeys(resolved, ['effectId', 'plan', 'action', 'grant']) ||
      resolved.effectId !== permit.effectId ||
      !isRecord(resolved.plan) ||
      !isRecord(resolved.action) ||
      !isRecord(resolved.grant)) return false;

  return resolved.plan.planHash === payload.planRef &&
    resolved.action.actionId === payload.actionRef &&
    resolved.action.authorizationRef === payload.grantRef &&
    resolved.action.planHash === payload.planRef &&
    resolved.action.taskId === resolved.plan.taskId &&
    resolved.grant.grantId === payload.grantRef &&
    resolved.grant.planHash === payload.planRef &&
    resolved.grant.taskId === resolved.plan.taskId;
}

function failed(effectId: string, code: string): WindowsHostEnvelope {
  return {
    phase: 'terminal',
    externalRef: effectId,
    outcome: { ok: false, error: { code, message: 'trusted Windows Host refused the effect' } },
  };
}

function completedReceipt(raw: unknown, actionId: string): boolean {
  return isRecord(raw) &&
    raw.actionId === actionId &&
    raw.terminal === 'SUCCEEDED' &&
    isRecord(raw.sideEffectEvidence) &&
    raw.sideEffectEvidence.recoveryClassification === 'COMPLETED_VERIFIED' &&
    raw.sideEffectEvidence.postStateVerified === true;
}

function failedBeforeEffect(raw: unknown, actionId: string): boolean {
  return isRecord(raw) &&
    raw.actionId === actionId &&
    raw.terminal === 'FAILED' &&
    isRecord(raw.sideEffectEvidence) &&
    raw.sideEffectEvidence.recoveryClassification === 'FAILED_BEFORE_EFFECT' &&
    raw.sideEffectEvidence.postStateVerified === false;
}

export function createWindowsEffectHost(input: {
  readonly binding: WindowsEffectBinding;
  readonly authorization: WindowsAuthorizationSource;
  readonly actionController: ShunActionControllerPort;
  readonly osAuthority: WindowsOsAuthorityPort;
  readonly windows: WindowsEffectPort;
}) {
  if (!safeId(input.binding.capabilityId) || !safeId(input.binding.operationId) ||
      typeof input.authorization?.resolve !== 'function' ||
      typeof input.actionController?.authorizeEffect !== 'function' ||
      typeof input.osAuthority?.recheck !== 'function' ||
      typeof input.windows?.execute !== 'function') {
    throw new TypeError('WINDOWS_HOST_CONFIGURATION_REFUSED');
  }

  return Object.freeze({
    /**
     * The selected K→C Host callback. No caller-supplied effectId exists:
     * effect identity comes exclusively from the K dispatch context.
     */
    async dispatch(payloadRaw: unknown, contextRaw: unknown): Promise<WindowsHostEnvelope> {
      const permit = readKernelEffectPermit(contextRaw);
      if (!permit) return failed('unbound', 'K_PERMIT_REQUIRED');

      if (!isRecord(contextRaw) ||
          contextRaw.capabilityId !== input.binding.capabilityId ||
          contextRaw.operationId !== input.binding.operationId) {
        return failed(permit.effectId, 'K_BINDING_MISMATCH');
      }

      const payload = parsePayload(payloadRaw);
      if (!payload) return failed(permit.effectId, 'WINDOWS_EFFECT_INPUT_INVALID');

      let resolved: unknown;
      try {
        resolved = await input.authorization.resolve({
          effectId: permit.effectId,
          actionRef: payload.actionRef,
          planRef: payload.planRef,
          grantRef: payload.grantRef,
        });
      } catch {
        return failed(permit.effectId, 'SHUN_AUTHORIZATION_CONTEXT_UNAVAILABLE');
      }
      if (!identityMatches(resolved, permit, payload)) {
        return failed(permit.effectId, 'SHUN_AUTHORIZATION_IDENTITY_MISMATCH');
      }

      let osCurrent: unknown;
      try {
        osCurrent = await input.osAuthority.recheck({
          effectId: permit.effectId,
          action: resolved.action,
        });
      } catch {
        return failed(permit.effectId, 'OS_AUTHORITY_UNRESOLVABLE');
      }
      if (!isRecord(osCurrent) || osCurrent.ok !== true) {
        return failed(permit.effectId, 'OS_AUTHORITY_REFUSED');
      }

      // Last Shun check. No await, mapping, logging or mutation is inserted
      // between this real ActionController call and entering the effect port.
      let shunVerdict: unknown;
      try {
        shunVerdict = await input.actionController.authorizeEffect({
          plan: resolved.plan,
          action: resolved.action,
          grant: resolved.grant,
        });
      } catch {
        return failed(permit.effectId, 'SHUN_AUTHORIZATION_UNRESOLVABLE');
      }
      if (!isRecord(shunVerdict) || shunVerdict.ok !== true) {
        return failed(permit.effectId, 'SHUN_AUTHORIZATION_REFUSED');
      }

      let receipt: unknown;
      try {
        receipt = await input.windows.execute({
          effectId: permit.effectId,
          action: resolved.action,
        });
      } catch {
        // The effect may have crossed the OS boundary before the failure.
        // Keep K's outcome non-terminal so its journal/fence owns UNKNOWN.
        return { phase: 'running', externalRef: permit.effectId };
      }

      if (completedReceipt(receipt, payload.actionRef)) {
        return {
          phase: 'terminal',
          externalRef: permit.effectId,
          outcome: {
            ok: true,
            output: {
              actionId: payload.actionRef,
              terminal: 'SUCCEEDED',
              recoveryClassification: 'COMPLETED_VERIFIED',
              postStateVerified: true,
            },
          },
        };
      }
      if (failedBeforeEffect(receipt, payload.actionRef)) {
        return failed(permit.effectId, 'WINDOWS_EFFECT_FAILED_BEFORE_EXECUTION');
      }
      // Any unverified success, timeout, cancellation or contradictory
      // receipt remains non-terminal; never let an optimistic receipt close K.
      return { phase: 'running', externalRef: permit.effectId };
    },
  });
}
