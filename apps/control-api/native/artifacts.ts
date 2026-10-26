// v0.2 T08 C02: pinned identity of the committed native artifacts. The host
// refuses to spawn a broker exe whose on-disk SHA-256 differs from the pinned
// value, and the loader refuses an addon that was tampered with — the trusted
// binary must be exactly the reviewed bytes.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CONSENT_BROKER_EXE_SHA256 =
  '5f202696a757e6678f849e50cfcc2bf088d31211fe0e48e8c5a889ad1b8a337a';
export const CONSENT_HOST_ADDON_SHA256 =
  'd75642429a977612c8b413c182f812ac9caeaee1b0074a5b9fa08c2382b19ffc';

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
