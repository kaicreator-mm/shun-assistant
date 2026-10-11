// Nonforgeable, SINGLE-USE, expiring controller-approval proof for grant
// issuance (P1-04, L2 §4.6.1; R1 P1-C anti-replay).
//
// `AuthorizationPort.issue` is a public seam. Without proof-of-controller it
// mints valid, correctly-signed grants for caller-chosen planHash/actionScope/
// authorizationKind with no plan intake, no durable-policy rule and no
// approval evidence — a direct call that skips the Action Controller entirely.
// The trusted composition root therefore shares an ISSUANCE SECRET (trusted
// local configuration, distinct from the grant integrity secret) between the
// Action Controller and the Authorization Authority:
//   - the controller mints one proof per EXACT issuance request, proving the
//     request passed plan intake, effective-risk routing and (where required)
//     bounded approval;
//   - the authority refuses any issuance whose proof was not minted for that
//     exact request under the shared secret — fail closed, structured.
//
// R1 (P1-C): a bare HMAC over the request is a REUSABLE bearer capability —
// any observer of one valid (request, proof) pair could re-mint grants with
// it forever, escaping revocation of earlier grants. The proof is therefore a
// portable capability carrying a fresh random nonce and a validity window:
//   shun-issuance-proof-v1.<nonce>.<expiresAt>.<mac>
// where mac = HMAC(issuanceSecret, canonicalJson([request, nonce, expiresAt])).
// The AUTHORITY enforces one-shot consumption (see AuthorizationAuthority:
// a proof presented twice refuses even for the identical request), so an
// observed pair can never authorize a second grant. Grant VERIFICATION is
// untouched: presentations still validate exactly as before.

import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { canonicalJson, type GrantIssueRequest, IsoDateTimeSchema } from '@shun/contracts';

/** Opaque per-request issuance proof minted by the Action Controller. */
export type IssuanceProof = string;

/** Default bounded proof validity, counted from the proof's mint instant. */
export const DEFAULT_ISSUANCE_PROOF_TTL_MS = 5 * 60 * 1000;

/** Envelope format tag; a proof without it (e.g. any bare request HMAC) is rejected. */
const PROOF_FORMAT = 'shun-issuance-proof-v1';

/** Options for minting a proof; the controller passes its own trusted clock. */
export interface IssuanceProofMintOptions {
  /** Mint instant (ISO 8601 UTC); defaults to the real wall clock. */
  issuedAt?: string;
  /** Validity window; defaults to DEFAULT_ISSUANCE_PROOF_TTL_MS. */
  ttlMs?: number;
  /** Nonce override (deterministic tests); a fresh random UUID when omitted. */
  nonce?: string;
}

/** The parsed claims of a proof envelope: what was authorized, until when, under which one-shot nonce. */
export interface IssuanceProofClaims {
  nonce: string;
  expiresAt: string;
  mac: string;
}

/** The exact bytes a proof MAC covers: the request, its one-shot nonce and its expiry. */
function issuanceProofMac(
  secret: string,
  request: GrantIssueRequest,
  nonce: string,
  expiresAt: string,
): string {
  return createHmac('sha256', secret)
    .update(canonicalJson([canonicalJson(request), nonce, expiresAt]), 'utf8')
    .digest('base64');
}

/**
 * Controller side: mint the per-request, single-use proof that this exact
 * request was authorized through the controller route. Every mint produces a
 * fresh nonce — two proofs for the same request are two separately consumable
 * approvals, never one reusable capability. Only trusted configuration holds
 * the issuance secret; without it no proof can be computed.
 */
export function computeIssuanceProof(
  secret: string,
  request: GrantIssueRequest,
  options?: IssuanceProofMintOptions,
): IssuanceProof {
  const nonce = options?.nonce ?? randomUUID();
  const issuedAt = options?.issuedAt ?? new Date().toISOString();
  const ttlMs = options?.ttlMs ?? DEFAULT_ISSUANCE_PROOF_TTL_MS;
  if (!Number.isFinite(ttlMs) || ttlMs < 0) {
    throw new TypeError('issuance proof ttlMs must be a non-negative finite number of ms');
  }
  const expiresAt = new Date(Date.parse(issuedAt) + ttlMs).toISOString();
  return `${PROOF_FORMAT}.${nonce}.${expiresAt}.${issuanceProofMac(secret, request, nonce, expiresAt)}`;
}

/**
 * Structural parse of a proof envelope. Anything that is not exactly the
 * versioned shape — a missing proof, a forged string, a bare request HMAC
 * from the pre-R1 format — yields undefined and fails closed. Parsing is
 * positional (format tag, first dot-delimited nonce, last dot-delimited MAC)
 * because the ISO expiry itself contains dots.
 */
export function parseIssuanceProof(proof: unknown): IssuanceProofClaims | undefined {
  if (typeof proof !== 'string') return undefined;
  const prefix = `${PROOF_FORMAT}.`;
  if (!proof.startsWith(prefix)) return undefined;
  const rest = proof.slice(prefix.length);
  const nonceEnd = rest.indexOf('.');
  if (nonceEnd <= 0) return undefined;
  const nonce = rest.slice(0, nonceEnd);
  const macStart = rest.lastIndexOf('.');
  if (macStart <= nonceEnd + 1) return undefined;
  const expiresAt = rest.slice(nonceEnd + 1, macStart);
  const mac = rest.slice(macStart + 1);
  if (mac.length === 0) return undefined;
  if (!IsoDateTimeSchema.safeParse(expiresAt).success) return undefined;
  return { nonce, expiresAt, mac };
}

/** Constant-time verification that the claims' MAC was minted for THIS request under the shared secret. */
export function verifyIssuanceProofMac(
  secret: string,
  request: GrantIssueRequest,
  claims: IssuanceProofClaims,
): boolean {
  const expected = issuanceProofMac(secret, request, claims.nonce, claims.expiresAt);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(claims.mac, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Stateless verification: structure + MAC binding + not-expired. This alone
 * does NOT authorize issuance — a valid proof must also be CONSUMED exactly
 * once by the authority (anti-replay); see AuthorizationAuthority, whose
 * synchronous check-and-consume makes double presentation impossible.
 */
export function verifyIssuanceProof(
  secret: string,
  request: GrantIssueRequest,
  proof: unknown,
  now?: string,
): boolean {
  const claims = parseIssuanceProof(proof);
  if (claims === undefined) return false;
  if (!verifyIssuanceProofMac(secret, request, claims)) return false;
  if (now !== undefined) {
    const nowMs = Date.parse(now);
    if (Number.isFinite(nowMs) && Date.parse(claims.expiresAt) < nowMs) return false;
  }
  return true;
}
