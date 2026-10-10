// Nonforgeable controller-approval proof for grant issuance (P1-04, L2 §4.6.1).
//
// `AuthorizationPort.issue` is a public seam. Without proof-of-controller it
// mints valid, correctly-signed grants for caller-chosen planHash/actionScope/
// authorizationKind with no plan intake, no durable-policy rule and no
// approval evidence — a direct call that skips the Action Controller entirely.
// The trusted composition root therefore shares an ISSUANCE SECRET (trusted
// local configuration, distinct from the grant integrity secret) between the
// Action Controller and the Authorization Authority:
//   - the controller mints one HMAC per EXACT issuance request, proving the
//     request passed plan intake, effective-risk routing and (where required)
//     bounded approval;
//   - the authority refuses any issuance whose proof was not minted for that
//     exact request under the shared secret — fail closed, structured.
// The proof is unforgeable without the secret and does not transfer across
// requests (binding over the canonical request form). Grant VERIFICATION is
// untouched: presentations still validate exactly as before.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalJson, type GrantIssueRequest } from '@shun/contracts';

/** Opaque per-request issuance proof minted by the Action Controller. */
export type IssuanceProof = string;

/** Canonical bytes a proof covers: the exact issuance request it authorizes. */
function issuanceProofPayload(request: GrantIssueRequest): string {
  return canonicalJson(request);
}

/**
 * Controller side: mint the per-request proof that this exact request was
 * authorized through the controller route. Only trusted configuration holds
 * the issuance secret; without it no proof can be computed.
 */
export function computeIssuanceProof(secret: string, request: GrantIssueRequest): IssuanceProof {
  return createHmac('sha256', secret)
    .update(issuanceProofPayload(request), 'utf8')
    .digest('base64');
}

/**
 * Authority side: constant-time verification that the caller presented a
 * proof minted for THIS request under the shared trusted secret. Anything
 * else — a missing proof, a forged string, a proof under a foreign secret, a
 * valid proof replayed against a different request — fails closed.
 */
export function verifyIssuanceProof(
  secret: string,
  request: GrantIssueRequest,
  proof: unknown,
): boolean {
  if (typeof proof !== 'string' || proof.length === 0) return false;
  const expected = computeIssuanceProof(secret, request);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(proof, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}
