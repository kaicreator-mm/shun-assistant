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
//
// C12: the bundle hash alone is measured theater if the INTERPRETER running
// it is arbitrary — the launcher chooses node.exe, an attacker-run launcher
// points it at its own node, and Start-Process -Verb RunAs would elevate that
// substitute. The pin therefore also records node.exe's sha256; the launcher
// measures before the relay spawn and the helper re-measures its own process
// image inside the privileged boundary.
import { readFileSync } from 'node:fs';
import type { HelperPin } from './trusted-store.ts';
import { sha256File } from './trusted-store.ts';

export type IdentityCheck =
  | {
      ok: true;
      helperRevision: string;
      measuredSha256: string;
      relayMeasuredSha256: string;
      nodeExeSha256: string;
    }
  | { ok: false; reason: string };

/**
 * Measure the helper bundle, relay script and node.exe interpreter on disk
 * and compare against the authority pin. Refuses on: missing/corrupt pin
 * (fail closed, never a default), unreadable files, or any digest mismatch.
 */
export function verifyPinnedHelper(
  helperBundlePath: string,
  relayScriptPath: string,
  nodeExePath: string,
  pin: HelperPin | undefined,
): IdentityCheck {
  if (!pin) {
    return {
      ok: false,
      reason: 'no helper pin in the authority store — refusing to launch (fail closed)',
    };
  }
  let helperSha256: string;
  try {
    helperSha256 = sha256File(helperBundlePath);
  } catch (e) {
    return { ok: false, reason: `helper bundle unreadable: ${message(e)}` };
  }
  let relaySha256: string;
  try {
    relaySha256 = sha256File(relayScriptPath);
  } catch (e) {
    return { ok: false, reason: `relay script unreadable: ${message(e)}` };
  }
  let nodeExeSha256: string;
  try {
    nodeExeSha256 = sha256File(nodeExePath);
  } catch (e) {
    return { ok: false, reason: `node.exe unreadable: ${message(e)}` };
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
  if (nodeExeSha256 !== pin.nodeExeSha256) {
    return {
      ok: false,
      reason: `node.exe identity mismatch: measured sha256 ${nodeExeSha256} != pinned ${pin.nodeExeSha256} (revision ${pin.helperRevision}) — unpinned interpreter refused`,
    };
  }
  return {
    ok: true,
    helperRevision: pin.helperRevision,
    measuredSha256: helperSha256,
    relayMeasuredSha256: relaySha256,
    nodeExeSha256,
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
