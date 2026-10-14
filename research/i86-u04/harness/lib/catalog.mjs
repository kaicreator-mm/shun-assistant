// catalog.mjs — curated catalog trust model for the i86-U04 pilot.
//
// Trust root: an ed25519 public-key SPKI SHA256 fingerprint pinned in the
// committed trust-root.json. The catalog (downloadable/rotatable content) is
// signed by the curator key; every digest inside it is computed by this
// tooling from real bytes — no oracle fields are ever hand-written.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

/** Deterministic JSON (sorted keys, no whitespace) — the signature input. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

export function spkiFingerprint(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

export function signCatalog(catalog, privateKeyPem) {
  const payload = { ...catalog };
  delete payload.signature;
  const digest = Buffer.from(canonicalJson(payload), 'utf8');
  const value = sign(null, digest, createPrivateKey(privateKeyPem)).toString('base64');
  return {
    ...payload,
    signature: { alg: 'ed25519', keyFingerprint: spkiFingerprint(publicKeyPemFromPrivate(privateKeyPem)), value },
  };
}

function publicKeyPemFromPrivate(privateKeyPem) {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' }).toString();
}

export function verifyCatalogSignature(catalog, trustRoot) {
  if (!catalog || typeof catalog !== 'object' || !catalog.signature) {
    return { ok: false, code: 'CATALOG_MALFORMED', detail: 'catalog carries no signature block' };
  }
  const { signature, ...payload } = catalog;
  if (signature.alg !== 'ed25519') {
    return { ok: false, code: 'CATALOG_SIGNATURE_INVALID', detail: `unsupported alg ${signature.alg}` };
  }
  if (signature.keyFingerprint !== trustRoot.publicKeyFingerprint) {
    return {
      ok: false,
      code: 'CATALOG_KEY_UNTRUSTED',
      detail: `catalog key ${signature.keyFingerprint} is not the pinned trust root ${trustRoot.publicKeyFingerprint}`,
    };
  }
  // The pinned fingerprint must match the PEM we are about to verify with.
  if (spkiFingerprint(trustRoot.publicKeyPem) !== trustRoot.publicKeyFingerprint) {
    return { ok: false, code: 'TRUST_ROOT_CORRUPT', detail: 'pinned PEM does not match pinned fingerprint' };
  }
  const ok = verify(
    null,
    Buffer.from(canonicalJson(payload), 'utf8'),
    createPublicKey(trustRoot.publicKeyPem),
    Buffer.from(signature.value, 'base64'),
  );
  return ok
    ? { ok: true }
    : { ok: false, code: 'CATALOG_SIGNATURE_INVALID', detail: 'ed25519 verification failed over the canonical catalog form' };
}

/**
 * Full fail-closed catalog validation: signature, active revision, entry
 * presence, and host requirements against the running host. Requirement
 * checks run BEFORE any network or filesystem effect.
 */
export function validateCatalogEntry(catalog, trustRoot, entryId, host = hostFacts()) {
  const signatureCheck = verifyCatalogSignature(catalog, trustRoot);
  if (!signatureCheck.ok) return signatureCheck;
  if (catalog.catalogRevision !== trustRoot.activeCatalogRevision) {
    return {
      ok: false,
      code: 'CATALOG_REVISION_REVOKED',
      detail: `catalog revision ${catalog.catalogRevision} is not the active revision ${trustRoot.activeCatalogRevision}`,
    };
  }
  const entry = catalog.entries.find((candidate) => candidate.id === entryId);
  if (!entry) {
    return { ok: false, code: 'PACKAGE_UNKNOWN', detail: `entry ${entryId} is not in the catalog` };
  }
  const req = entry.requirements ?? {};
  if (req.os && req.os !== host.os) {
    return { ok: false, code: 'OS_MISMATCH', detail: `entry requires os=${req.os}, host is ${host.os}` };
  }
  if (req.arch && req.arch !== host.arch) {
    return { ok: false, code: 'ARCH_MISMATCH', detail: `entry requires arch=${req.arch}, host is ${host.arch}` };
  }
  if (req.node) {
    if (req.node.napiVersion !== undefined && req.node.napiVersion !== host.napiVersion) {
      return {
        ok: false,
        code: 'NODE_ABI_MISMATCH',
        detail: `entry requires N-API ${req.node.napiVersion}, runtime provides ${host.napiVersion} (node ${host.nodeVersion})`,
      };
    }
    if (req.node.abi !== undefined && req.node.abi !== host.abi) {
      return {
        ok: false,
        code: 'NODE_ABI_MISMATCH',
        detail: `entry requires ABI ${req.node.abi}, runtime provides ${host.abi} (node ${host.nodeVersion})`,
      };
    }
  }
  if (!/^https?:$/.test(new URL(entry.source.url).protocol)) {
    return { ok: false, code: 'CATALOG_MALFORMED', detail: 'source URL protocol is not http(s)' };
  }
  if (!Array.isArray(entry.source.approvedHosts) || entry.source.approvedHosts.length === 0) {
    return { ok: false, code: 'CATALOG_MALFORMED', detail: 'source has no approved host allowlist' };
  }
  if (!/^[0-9a-f]{64}$/.test(entry.artifact.sha256) || !Number.isInteger(entry.artifact.sizeBytes)) {
    return { ok: false, code: 'CATALOG_MALFORMED', detail: 'artifact digest/size missing or malformed' };
  }
  return { ok: true, entry };
}

export function hostFacts() {
  return {
    os: process.platform,
    arch: process.arch,
    abi: Number(process.versions.modules),
    napiVersion: Number(process.versions.napi),
    nodeVersion: process.version,
  };
}

/** Stable per-(id,version) directory name — v0.1 managed-portable semantics. */
export function stableKey(id, version) {
  return createHash('sha256').update(`${id}\n${version}`, 'utf8').digest('hex').slice(0, 32);
}
