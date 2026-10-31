/**
 * Type surface of the STAGED trusted Host binding package the suite writes
 * into the consumer node_modules (see vitest.config.ts). Test instrument
 * only; the production form of this seam is the T11 composition root.
 */
export interface T11GateDispatch {
  readonly payload: unknown;
  readonly dispatchContext: {
    readonly capabilityId: string;
    readonly operationId: string;
    readonly effectPermit: {
      readonly effectId: string;
      readonly durableControlTurnId: string;
      readonly attempt: number;
    };
  };
}

export interface T11WindowsHostEvidence {
  readonly physicalEffects: { readonly effectId: string; readonly actionId: string | null }[];
  readonly gateDispatches: readonly T11GateDispatch[];
  readonly adapterOrder: readonly string[];
}

export declare function stageT11Authorization(actionRef: string, record: unknown): void;
export declare function t11WindowsHostEvidence(): T11WindowsHostEvidence;
export declare function resetT11WindowsHost(): void;
export declare function windowsExecute(
  payload: unknown,
  dispatchContext: unknown,
): Promise<unknown>;
