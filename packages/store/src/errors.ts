// Typed ShunStore failures. Every failure mode is explicit and fail-closed:
// callers can never mistake a refused or torn application for a committed one.
export type ShunStoreErrorCode =
  | 'STORE_INVALID_MUTATION'
  | 'STORE_EFFECT_CONFLICT'
  | 'STORE_WRITE_FAILED'
  | 'STORE_CLOSED';

export class ShunStoreError extends Error {
  readonly code: ShunStoreErrorCode;

  constructor(code: ShunStoreErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options ? { cause: options.cause } : undefined);
    this.name = 'ShunStoreError';
    this.code = code;
  }
}

export class ShunStoreInvalidMutationError extends ShunStoreError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('STORE_INVALID_MUTATION', message, options);
    this.name = 'ShunStoreInvalidMutationError';
  }
}

/** Same effectId presented with a different intended mutation — never re-applied, never silently accepted. */
export class ShunStoreEffectConflictError extends ShunStoreError {
  readonly effectId: string;

  constructor(effectId: string, mismatches: string[]) {
    super(
      'STORE_EFFECT_CONFLICT',
      `effect identity conflict for ${effectId}: ${mismatches.join(', ')}`,
    );
    this.name = 'ShunStoreEffectConflictError';
    this.effectId = effectId;
  }
}

export class ShunStoreWriteFailedError extends ShunStoreError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('STORE_WRITE_FAILED', message, options);
    this.name = 'ShunStoreWriteFailedError';
  }
}

export class ShunStoreClosedError extends ShunStoreError {
  constructor() {
    super('STORE_CLOSED', 'ShunStore is closed');
    this.name = 'ShunStoreClosedError';
  }
}
