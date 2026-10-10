// Caller-controlled actionId hygiene (path-safety for run artifacts).
//
// contracts pins actionId as z.string().min(1) — frozen, so it deliberately
// excludes nothing else. Both backends splice the actionId into per-action run
// directory names under the workspace root, and the privileged backend hands
// helper I/O paths derived from it to an elevated process. An actionId like
// `..\..\evil` would therefore point launcher artifacts OUTSIDE the workspace.
// Refuse anything with path semantics BEFORE any artifact path is derived —
// same allowlist convention as FileGrantSource.byGrantId (fail closed, typed).
export const ACTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Upper bound keeps run-directory names well clear of path-length limits. */
export const MAX_ACTION_ID_LENGTH = 128;

/** Typed refusal: the actionId can never be used to derive artifact paths. */
export class ActionIdRefusedError extends Error {
  readonly code = 'ACTION_ID_REFUSED';
  readonly actionId: string;

  constructor(actionId: string) {
    super(
      `actionId refused (must match ${ACTION_ID_PATTERN.source}, max ${MAX_ACTION_ID_LENGTH} chars): '${actionId}'`,
    );
    this.name = 'ActionIdRefusedError';
    this.actionId = actionId;
  }
}

/**
 * Throws ActionIdRefusedError unless the actionId is a plain, path-free
 * identifier: alphanumerics plus `.`/`_`/`-`, led by an alphanumeric. This
 * excludes path separators (`/`, `\`) and `..` sequences, drive
 * specifiers/ADS (`:`), NTFS-illegal characters (`< > " | ? *`), control
 * characters and unbounded length.
 */
export function assertSafeActionId(actionId: string): void {
  if (actionId.length === 0 || actionId.length > MAX_ACTION_ID_LENGTH) {
    throw new ActionIdRefusedError(actionId);
  }
  if (!ACTION_ID_PATTERN.test(actionId) || actionId.includes('..')) {
    throw new ActionIdRefusedError(actionId);
  }
}
