// Reference integrity substrate for AuthorizationGrant envelopes
// (L2 §4.6.1 — the exact mechanism is an L3 implementation freedom).
//
// P0 ships HMAC-SHA256. The MAC covers the canonical JSON of the grant minus
// the envelope itself: representation differences (key order) never change
// validity, any content change does. Schemes without a P0 substrate
// (SIGNATURE_ED25519, TRUSTED_LOCAL_CHANNEL) fail closed in the verifier —
// an unverifiable envelope is exactly a failed verification, never a pass.
//
// The secret lives in trusted local configuration of the authority side. The
// privileged boundary receives the verifier as injected trusted code; it never
// receives the caller's claim about authenticity.
import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  type AuthorizationGrant,
  canonicalJson,
  type GrantIntegrity,
  type GrantIntegrityVerifier,
} from '@shun/contracts';

export type GrantIntegritySecret = string;

/** Canonical bytes the envelope protects: the whole grant except the envelope. */
export function grantSigningPayload(grant: AuthorizationGrant): string {
  const { integrity: _omitted, ...covered } = grant;
  return canonicalJson(covered);
}

/** Authority-side envelope application. Callers can never supply integrity; only the authority signs. */
export function signGrantIntegrity(
  secret: GrantIntegritySecret,
  grant: AuthorizationGrant,
): GrantIntegrity {
  return {
    scheme: 'HMAC_SHA256',
    value: createHmac('sha256', secret).update(grantSigningPayload(grant), 'utf8').digest('base64'),
  };
}

/**
 * Trusted verifier for the privilege boundary (P0 reference). Constant-time
 * comparison; unknown schemes fail closed. Pure and synchronous per the
 * GrantIntegrityVerifier contract.
 */
export function createHmacGrantVerifier(secret: GrantIntegritySecret): GrantIntegrityVerifier {
  return (grant, envelope) => {
    if (envelope.scheme !== 'HMAC_SHA256') return false;
    const expected = createHmac('sha256', secret)
      .update(grantSigningPayload(grant), 'utf8')
      .digest('base64');
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(envelope.value, 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
  };
}
