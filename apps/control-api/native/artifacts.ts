// v0.2 T08 C02: pinned identity of the committed native artifacts. The host
// refuses to spawn a broker exe whose on-disk SHA-256 differs from the pinned
// value, and the loader refuses an addon that was tampered with — the trusted
// binary must be exactly the reviewed bytes.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Pinned to the R1-hardened rebuild squash-merged via #192: broker exe
// c85420ca… is the exact committed #192 final byte pair (verified by
// Get-FileHash on version/v0.2.0@a0a57db8, matching the #192 final report;
// the pre-rebuild pin 5f202696… had drifted and closed every native spawn
// with BROKER_EXE_SHA_MISMATCH). The addon was rebuilt once more with the
// client pipe explicitly requesting Identification-level SQOS: the R1 P2-4
// broker admission reads the CONNECTING client's impersonation token, and
// the previous addon's SQOS-less CreateFileW only ever presented an
// anonymous token, so the hardened broker refused its own host
// (CLIENT_REFUSED, proven by old/new cross-pair runs on this Build Host).
export const CONSENT_BROKER_EXE_SHA256 =
  'c85420cabd60e264e806fdfc5025287feb2f8168ce84d766b49fb2c91732c567';
export const CONSENT_HOST_ADDON_SHA256 =
  'a616ff35c0da830f1d6a3bd9e0f4df18cc2ef4deb97e565f92bbd3b53fe05f75';

const nativeDir = dirname(fileURLToPath(import.meta.url));

export function brokerExePath(): string {
  return join(nativeDir, 'broker', 'shun-consent-broker.exe');
}

export function hostAddonPath(): string {
  return join(nativeDir, 'host', 'shun_consent_host.node');
}

function sha256OfFile(path: string): string | null {
  if (!existsSync(path)) return null;
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch {
    return null;
  }
}

export type ArtifactCheck = Readonly<{
  ok: boolean;
  reason?: string;
  exeSha256?: string;
  addonSha256?: string;
}>;

/** Verify BOTH committed artifacts byte-for-byte before any trusted use. */
export function verifyArtifacts(): ArtifactCheck {
  if (process.platform !== 'win32') {
    return { ok: false, reason: 'PLATFORM_NOT_WINDOWS' };
  }
  const exeSha256 = sha256OfFile(brokerExePath());
  const addonSha256 = sha256OfFile(hostAddonPath());
  if (exeSha256 === null) return { ok: false, reason: 'BROKER_EXE_MISSING' };
  if (addonSha256 === null) return { ok: false, reason: 'HOST_ADDON_MISSING' };
  if (exeSha256 !== CONSENT_BROKER_EXE_SHA256) {
    return { ok: false, reason: 'BROKER_EXE_SHA_MISMATCH', exeSha256 };
  }
  if (addonSha256 !== CONSENT_HOST_ADDON_SHA256) {
    return { ok: false, reason: 'HOST_ADDON_SHA_MISMATCH', addonSha256 };
  }
  return { ok: true, exeSha256, addonSha256 };
}
