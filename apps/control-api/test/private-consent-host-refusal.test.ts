import { describe, expect, it } from 'vitest';
// v0.2 T08 C02 — platform boundary of the private IPC trusted consent broker.
// This file runs EVERYWHERE (Linux contract CI included): outside Windows the
// host reports typed unavailability; no mocked "Windows success" is ever
// claimed from a non-Windows platform. The real interactive-desktop journey
// lives in private-consent-host.test.ts and runs only on Windows.
import { PRIVATE_CONSENT_UNAVAILABLE, privateConsentHostAvailability } from '../native/index.ts';

describe('T08 C02 private consent broker availability boundary', () => {
  it('exposes exactly one typed refusal code with a redacted reason', () => {
    const availability = privateConsentHostAvailability();
    if (process.platform === 'win32' && availability.ok) {
      // Windows with the pinned artifacts present: availability is positive
      // and carries the exact artifact digests (asserted at length in the
      // interactive test file).
      expect(availability.exeSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(availability.addonSha256).toMatch(/^[0-9a-f]{64}$/);
      return;
    }
    // Linux CI (or Windows without the artifacts): typed refusal, never a
    // fabricated broker. The reason is a fixed code, not a raw OS error.
    expect(availability.ok).toBe(false);
    if (!availability.ok) {
      expect(availability.code).toBe(PRIVATE_CONSENT_UNAVAILABLE);
      expect(availability.reason.length).toBeGreaterThan(0);
    }
  });

  it('keeps the refusal code stable as part of the frozen public surface', () => {
    expect(PRIVATE_CONSENT_UNAVAILABLE).toBe('PRIVATE_CONSENT_BROKER_UNAVAILABLE');
  });
});
