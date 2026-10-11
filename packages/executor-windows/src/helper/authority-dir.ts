// The trusted authority store location, baked into the helper bundle at build
// time (never argv/env — an attacker-run launcher controls both). Kept in its
// own module so the build-define fallback is unit-testable without executing
// the one-shot helper entry point.
//
// Changing the location changes the bundle hash → the helper must be re-pinned
// → an explicit authority event (§4.6.1).

// Build-time constant injected by scripts/build-helper.ts (JSON.stringify'd,
// so a production build without SHUN_EXECUTOR_BUILD_AUTHORITY_DIR yields '').
declare const SHUN_EXECUTOR_AUTHORITY_DIR: string | undefined;

// Optional C06 externalization: the HMAC grant-integrity key path, injected
// the same way (empty/absent = key resolved inside the authority store).
declare const SHUN_EXECUTOR_HMAC_KEY_FILE: string | undefined;

/** Resolves the trusted authority store the helper re-verifies against. */
export function authorityDirectory(): string {
  const defined: string | undefined =
    typeof SHUN_EXECUTOR_AUTHORITY_DIR === 'string' ? SHUN_EXECUTOR_AUTHORITY_DIR : undefined;
  return resolveAuthorityDirectory(defined);
}

/**
 * C06: external HMAC key path baked in at build time. Empty/absent define =
 * the key stays co-located in the authority store (the residual same-user
 * risk, ESCALATED); a deployment protecting the key path via ACLs or a
 * privileged authority service sets this so store tampering cannot forge
 * grants. Same trust rules as the authority dir: a build-time constant,
 * never argv/env, and changing it changes the bundle → re-pin.
 */
export function grantHmacKeyFileOverride(): string | undefined {
  const defined: string | undefined =
    typeof SHUN_EXECUTOR_HMAC_KEY_FILE === 'string' ? SHUN_EXECUTOR_HMAC_KEY_FILE : undefined;
  const trimmed = defined?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Empty define == production build without the override env var: it means the
 * protected Windows default (C:\\ProgramData\\Shun\\authority), NOT the empty string.
 * Honoring '' would degrade every trust anchor (helper-pin.json,
 * current-authority.json, grant-hmac.key, plans/) to CWD-relative resolution —
 * and the helper CWD is inherited from the untrusted launcher, which could
 * plant a self-consistent pin + own HMAC key and "validate" self-issued
 * grants. An empty (or whitespace-only) define must therefore fall back.
 */
export function resolveAuthorityDirectory(defined: string | undefined): string {
  const trusted = defined?.trim();
  return trusted && trusted.length > 0 ? trusted : 'C:\\ProgramData\\Shun\\authority';
}
