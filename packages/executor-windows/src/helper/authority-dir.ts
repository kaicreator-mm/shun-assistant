// The trusted authority store location, baked into the helper bundle at build
// time (never argv/env — an attacker-run launcher controls both). Kept in its
// own module so the build-define fallback is unit-testable without executing
// the one-shot helper entry point.
//
// Changing the location changes the bundle hash → the helper must be re-pinned
// → an explicit authority event (§4.6.1).
import { homedir } from 'node:os';
import { join } from 'node:path';

// Build-time constant injected by scripts/build-helper.ts (JSON.stringify'd,
// so a production build without SHUN_EXECUTOR_BUILD_AUTHORITY_DIR yields '').
declare const SHUN_EXECUTOR_AUTHORITY_DIR: string | undefined;

/** Resolves the trusted authority store the helper re-verifies against. */
export function authorityDirectory(): string {
  const defined: string | undefined =
    typeof SHUN_EXECUTOR_AUTHORITY_DIR === 'string' ? SHUN_EXECUTOR_AUTHORITY_DIR : undefined;
  return resolveAuthorityDirectory(defined);
}

/**
 * Empty define == production build without the override env var: it means the
 * documented default (<USERPROFILE>\.shun\authority), NOT the empty string.
 * Honoring '' would degrade every trust anchor (helper-pin.json,
 * current-authority.json, grant-hmac.key, plans/) to CWD-relative resolution —
 * and the helper CWD is inherited from the untrusted launcher, which could
 * plant a self-consistent pin + own HMAC key and "validate" self-issued
 * grants. An empty (or whitespace-only) define must therefore fall back.
 */
export function resolveAuthorityDirectory(defined: string | undefined): string {
  const trusted = defined?.trim();
  return trusted && trusted.length > 0 ? trusted : join(homedir(), '.shun', 'authority');
}
