// Typed workflow-kernel failures. The kernel never lets an uncertain or
// refused outcome masquerade as success: every failure mode is explicit.
export type WorkflowKernelErrorCode =
  | 'KERNEL_UNKNOWN_TASK'
  | 'KERNEL_UNKNOWN_ACTION'
  | 'KERNEL_CONFLICT'
  | 'KERNEL_MESSAGE_CONFLICT'
  | 'KERNEL_INVALID_MESSAGE'
  | 'KERNEL_INVALID_TRANSITION'
  | 'KERNEL_HANDLER_FAILED'
  | 'KERNEL_EFFECT_CONFLICT'
  | 'KERNEL_EFFECT_UNCERTAIN'
  | 'KERNEL_ACTION_UNCERTAIN'
  | 'KERNEL_ACTION_RESOLVED'
  | 'KERNEL_UNRESOLVED_DESTRUCTIVE_ACTION'
  | 'KERNEL_INVALID_RECEIPT'
  | 'KERNEL_CLOSED'
  | 'JOURNAL_INTEGRITY'
  | 'RECIPE_SEAM_UNAVAILABLE';

export class WorkflowKernelError extends Error {
  readonly code: WorkflowKernelErrorCode;

  constructor(code: WorkflowKernelErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options ? { cause: options.cause } : undefined);
    this.name = 'WorkflowKernelError';
    this.code = code;
  }
}

export class KernelUnknownTaskError extends WorkflowKernelError {
  constructor(taskId: string) {
    super('KERNEL_UNKNOWN_TASK', `unknown workflow task ${taskId}`);
    this.name = 'KernelUnknownTaskError';
  }
}

export class KernelInvalidTransitionError extends WorkflowKernelError {
  constructor(taskId: string, from: string, to: string) {
    super('KERNEL_INVALID_TRANSITION', `illegal transition for ${taskId}: ${from} -> ${to}`);
    this.name = 'KernelInvalidTransitionError';
  }
}

export class KernelMessageConflictError extends WorkflowKernelError {
  constructor(messageId: string, taskId: string) {
    super(
      'KERNEL_MESSAGE_CONFLICT',
      `message ${messageId} already accepted for ${taskId} with different content`,
    );
    this.name = 'KernelMessageConflictError';
  }
}

/** Store recorded a different mutation under the same effectId — authority contradiction, never overwritten. */
export class KernelEffectConflictError extends WorkflowKernelError {
  constructor(effectId: string, options?: { cause?: unknown }) {
    super('KERNEL_EFFECT_CONFLICT', `effect identity conflict for ${effectId}`, options);
    this.name = 'KernelEffectConflictError';
  }
}

/** The store call returned ambiguously (transport-level failure). Nothing is assumed committed. */
export class KernelEffectUncertainError extends WorkflowKernelError {
  constructor(effectId: string, options?: { cause?: unknown }) {
    super('KERNEL_EFFECT_UNCERTAIN', `effect ${effectId} application is uncertain`, options);
    this.name = 'KernelEffectUncertainError';
  }
}

export class KernelActionUncertainError extends WorkflowKernelError {
  constructor(actionId: string, options?: { cause?: unknown }) {
    super('KERNEL_ACTION_UNCERTAIN', `action ${actionId} execution outcome is uncertain`, options);
    this.name = 'KernelActionUncertainError';
  }
}

/** A resolved (receipted/reconciled-closed) action cannot be dispatched again. */
export class KernelActionResolvedError extends WorkflowKernelError {
  constructor(actionId: string) {
    super('KERNEL_ACTION_RESOLVED', `action ${actionId} is already resolved; no re-execution`);
    this.name = 'KernelActionResolvedError';
  }
}

/** L2 §9.4 stable identity rule: no fresh destructive identity while an unresolved one exists. */
export class KernelUnresolvedDestructiveActionError extends WorkflowKernelError {
  constructor(blockingActionId: string) {
    super(
      'KERNEL_UNRESOLVED_DESTRUCTIVE_ACTION',
      `destructive action ${blockingActionId} is MAY_HAVE_EXECUTED_UNCERTAIN; reconcile it or resume the SAME actionId — no fresh identity`,
    );
    this.name = 'KernelUnresolvedDestructiveActionError';
  }
}

export class KernelHandlerFailedError extends WorkflowKernelError {
  constructor(messageId: string, options?: { cause?: unknown }) {
    super(
      'KERNEL_HANDLER_FAILED',
      `handler for message ${messageId} failed; message stays pending`,
      options,
    );
    this.name = 'KernelHandlerFailedError';
  }
}

export class KernelInvalidReceiptError extends WorkflowKernelError {
  constructor(actionId: string, options?: { cause?: unknown }) {
    super(
      'KERNEL_INVALID_RECEIPT',
      `execution receipt for action ${actionId} violates the frozen schema`,
      options,
    );
    this.name = 'KernelInvalidReceiptError';
  }
}

export class JournalIntegrityError extends WorkflowKernelError {
  constructor(message: string) {
    super('JOURNAL_INTEGRITY', message);
    this.name = 'JournalIntegrityError';
  }
}

export class RecipeSeamUnavailableError extends WorkflowKernelError {
  constructor(operation: string) {
    super(
      'RECIPE_SEAM_UNAVAILABLE',
      `recipe ${operation} is not part of the P0 reference proof (RecipeResolverPort is a seam only; automatic promotion is P1)`,
    );
    this.name = 'RecipeSeamUnavailableError';
  }
}
