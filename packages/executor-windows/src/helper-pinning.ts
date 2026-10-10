// Pinned one-shot helper identity (L2 §4.6.1).
//
// "The elevated helper executable is pinned infrastructure: its identity
// (hash/signature) and revision are recorded by Shun authority, and only the
// pinned helper is launched."
//
// Implementation shape: the helper is ONE bundled .mjs (one canonicalization
// implementation — the workspace contracts sources, bundled verbatim), whose
// file content the launcher measures and checks against the authority pin
// before any process is spawned. Provider definitions, planner proposals,
// recipes and bindings cannot select, substitute or parameterize the helper
// path: the path is resolved from the backend's own package location, the op
// schemas carry no helper-shaped keys, and a substituted file simply fails
// the identity check.
import { readFileSync } from 'node:fs';
import type { HelperPin } from './trusted-store.ts';
import { sha256File } from './trusted-store.ts';

export type IdentityCheck =
  | { ok: true; helperRevision: string; measuredSha256: string; relayMeasuredSha256: string }
  | { ok: false; reason: string };

/**
 * Measure the helper bundle and relay script on disk and compare against the
 * authority pin. Refuses on: missing/corrupt pin (fail closed, never a
 * default), unreadable helper/relay, or any digest mismatch.
 */
export function verifyPinnedHelper(
  helperBundlePath: string,
  relayScriptPath: string,
  pin: HelperPin | undefined,
): IdentityCheck {
  if (!pin) {
    return {
      ok: false,
      reason: 'no helper pin in the authority store — refusing to launch (fail closed)',
    };
  }
  let helperSha256: string;
  let relaySha256: string;
  try {
    helperSha256 = sha256File(helperBundlePath);
  } catch (e) {
    return { ok: false, reason: `helper bundle unreadable: ${message(e)}` };
  }
  try {
    relaySha256 = sha256File(relayScriptPath);
  } catch (e) {
    return { ok: false, reason: `relay script unreadable: ${message(e)}` };
  }
  if (helperSha256 !== pin.helperSha256) {
    return {
      ok: false,
      reason: `helper identity mismatch: measured sha256 ${helperSha256} != pinned ${pin.helperSha256} (revision ${pin.helperRevision}) — substitution refused`,
    };
  }
  if (relaySha256 !== pin.relaySha256) {
    return {
      ok: false,
      reason: `relay identity mismatch: measured sha256 ${relaySha256} != pinned ${pin.relaySha256} (revision ${pin.helperRevision}) — substitution refused`,
    };
  }
  return {
    ok: true,
    helperRevision: pin.helperRevision,
    measuredSha256: helperSha256,
    relayMeasuredSha256: relaySha256,
  };
}

/** Helper bundle self-check (runs inside the privileged boundary at startup). */
export function selfHash(file: string): string {
  return sha256File(file);
}

export function readTextFile(file: string): string {
  return readFileSync(file, 'utf8');
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
