import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CloudConsentApproval, CloudConsentCurrentness } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { DurableCloudBudgetLedger } from '../src/atomic-budget.ts';

const directories: string[] = [];
const connections: DurableCloudBudgetLedger[] = [];
const NOW = '2026-10-15T00:00:00.000Z';
const body = Buffer.from(
  '{"model":"deepseek-flash","messages":[{"role":"user","content":"Hello"}]}',
);
const projection = Buffer.from('{"provider":"deepseek","user":"Hello"}');

function sha(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function makeApproval(maxCalls = 1): CloudConsentApproval {
  return {
    consentId: 'consent-1',
    confirmationNonce: 'nonce-1',
    displayedProjectionSha256: sha(projection),
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'shun-private-broker',
      brokerRevision: 'broker-1',
      assertionId: 'assertion-1',
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: 'opaque-external-trust-proof',
    },
    scope: {
      taskId: 'task-1',
      principalId: 'principal-1',
      sessionId: 'session-1',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: 'https://api.deepseek.com/chat/completions',
      approvedProjectionSha256: sha(projection),
      scopeRevision: 'scope-1',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-1',
      policyRevision: 'policy-1',
      pricingRevision: 'pricing-1',
      revocationEpoch: 1,
      maxCalls,
      maxInputTokens: 1000,
      maxOutputTokens: 100,
      maxCostMicros: 10000,
      issuedAt: '2026-10-14T23:00:00.000Z',
      expiresAt: '2026-10-15T01:00:00.000Z',
    },
  };
}

function makeCurrent(
  approval: CloudConsentApproval,
): Extract<CloudConsentCurrentness, { kind: 'CURRENT' }> {
  const scope = approval.scope;
  return {
    kind: 'CURRENT',
    taskId: scope.taskId,
    principalId: scope.principalId,
    sessionId: scope.sessionId,
    policyRevision: scope.policyRevision,
    registryRevision: scope.registryRevision,
    pricingRevision: scope.pricingRevision,
    scopeRevision: scope.scopeRevision,
    revocationEpoch: scope.revocationEpoch,
    nonceIsUnused: true,
  };
}

function setup(verifier: (input: CloudConsentApproval) => boolean = () => true) {
  const dir = mkdtempSync(join(tmpdir(), 'shun-cloud-budget-'));
  directories.push(dir);
  const file = join(dir, 'ledger.sqlite');
  const ledger = new DurableCloudBudgetLedger({
    file,
    verifyBroker: verifier,
    pricing: { revision: 'pricing-1', inputMicrosPerToken: 1, outputMicrosPerToken: 2 },
  });
  connections.push(ledger);
  return { ledger, file };
}

function request(approval: CloudConsentApproval = makeApproval(), attemptId = 'attempt-1') {
  return {
    attemptId,
    approval,
    currentness: makeCurrent(approval),
    now: NOW,
    requestBytes: body,
    disclosureProjectionBytes: projection,
    outputTokenCeiling: 20,
  };
}

afterEach(() => {
  for (const connection of connections.splice(0)) connection.close();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('v0.2 durable DeepSeek privacy budget gate', () => {
  it('reserves at most one network slot for two concurrent maxCalls=1 attempts', async () => {
    const { ledger } = setup();
    const results = await Promise.all([
      Promise.resolve().then(() => ledger.reserve(request(makeApproval(), 'attempt-a'))),
      Promise.resolve().then(() => ledger.reserve(request(makeApproval(), 'attempt-b'))),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok)).toEqual([{ ok: false, code: 'BUDGET_EXHAUSTED' }]);
    expect(ledger.reserve(request(makeApproval(), 'attempt-a'))).toEqual({
      ok: false,
      code: 'IDEMPOTENCY_REPLAY',
    });
  });

  it('refuses nonbroker/async proof, stale policy, expiry, changed projection and pricing', () => {
    const { ledger } = setup(() => false);
    expect(ledger.reserve(request())).toEqual({ ok: false, code: 'CONSENT_REFUSED' });
    const { ledger: asyncLedger } = setup((() => Promise.resolve(true)) as unknown as (
      x: CloudConsentApproval,
    ) => boolean);
    expect(asyncLedger.reserve(request())).toEqual({ ok: false, code: 'CONSENT_REFUSED' });
    const { ledger: valid } = setup();
    expect(
      valid.reserve({
        ...request(),
        currentness: { ...makeCurrent(makeApproval()), policyRevision: 'old' },
      }),
    ).toEqual({
      ok: false,
      code: 'CONSENT_STALE',
    });
    expect(valid.reserve({ ...request(), now: '2026-10-15T01:00:00.000Z' })).toEqual({
      ok: false,
      code: 'CONSENT_EXPIRED',
    });
    expect(
      valid.reserve({ ...request(), disclosureProjectionBytes: Buffer.from('attacker') }),
    ).toEqual({
      ok: false,
      code: 'DISCLOSURE_SCOPE_DRIFT',
    });
    const changed = makeApproval();
    changed.scope.pricingRevision = 'old-pricing';
    expect(valid.reserve(request(changed))).toEqual({ ok: false, code: 'PRICING_REVISION_STALE' });
    expect(valid.inspect('attempt-1')).toBeNull();
  });

  it('reserves full approved token ceilings rather than undercounting chat-template overhead', () => {
    const { ledger } = setup();
    const approval = makeApproval();
    // Raw body is under 100 bytes but approved token maxima price at 1200
    // micro-units (1000 input + 100 output × 2), not byte length + 20 × 2.
    approval.scope.maxCostMicros = 1100;
    expect(ledger.reserve(request(approval))).toEqual({
      ok: false,
      code: 'BUDGET_EXHAUSTED',
    });
    expect(ledger.inspect('attempt-1')).toBeNull();
    const safe = makeApproval();
    safe.scope.maxCostMicros = 1200;
    const approved = ledger.reserve(request(safe));
    expect(approved).toMatchObject({ ok: true, reservedCostMicros: 1200 });
  });

  it('requires a fresh trusted broker, currentness and exact bytes at send boundary', () => {
    const { ledger } = setup();
    const approval = makeApproval();
    expect(ledger.reserve(request(approval)).ok).toBe(true);
    const input = {
      attemptId: 'attempt-1',
      actualRequestBytes: body,
      approval,
      currentness: makeCurrent(approval),
      now: NOW,
    };
    expect(ledger.markMayHaveSent({ ...input, actualRequestBytes: Buffer.from('changed') })).toBe(
      false,
    );
    expect(
      ledger.markMayHaveSent({
        ...input,
        currentness: { ...makeCurrent(approval), revocationEpoch: 2 },
      }),
    ).toBe(false);
    expect(ledger.markMayHaveSent({ ...input, now: '2026-10-15T01:00:00.000Z' })).toBe(false);
    expect(ledger.inspect('attempt-1')?.status).toBe('RESERVED');
    expect(ledger.markMayHaveSent(input)).toBe(true);
    expect(ledger.markMayHaveSent(input)).toBe(false);
    expect(ledger.markUnknownCost('attempt-1')).toBe(true);
    expect(ledger.inspect('attempt-1')?.status).toBe('UNKNOWN_COST');
    expect(ledger.markUnknownCost('attempt-1')).toBe(false);
  });

  it('holds worst-case reservations across SQLite restart and never retries UNKNOWN_COST', () => {
    const { ledger, file } = setup();
    const approval = makeApproval();
    expect(ledger.reserve(request(approval)).ok).toBe(true);
    expect(
      ledger.markMayHaveSent({
        attemptId: 'attempt-1',
        approval,
        currentness: makeCurrent(approval),
        now: NOW,
        actualRequestBytes: body,
      }),
    ).toBe(true);
    expect(ledger.markUnknownCost('attempt-1')).toBe(true);
    ledger.close();
    connections.splice(connections.indexOf(ledger), 1);
    const resumed = new DurableCloudBudgetLedger({
      file,
      verifyBroker: () => true,
      pricing: { revision: 'pricing-1', inputMicrosPerToken: 1, outputMicrosPerToken: 2 },
    });
    connections.push(resumed);
    expect(resumed.inspect('attempt-1')?.status).toBe('UNKNOWN_COST');
    expect(resumed.reserve(request(makeApproval(), 'attempt-2'))).toEqual({
      ok: false,
      code: 'BUDGET_EXHAUSTED',
    });
  });

  it('rejects broadened budget under same scope revision; no infinite cost', () => {
    const { ledger } = setup();
    const original = makeApproval(2);
    expect(ledger.reserve(request(original, 'attempt-1')).ok).toBe(true);
    const changed = makeApproval(4);
    expect(ledger.reserve(request(changed, 'attempt-2'))).toEqual({
      ok: false,
      code: 'CONSENT_STALE',
    });
    expect(ledger.reserve({ ...request(original, 'attempt-2'), outputTokenCeiling: 200 })).toEqual({
      ok: false,
      code: 'BUDGET_EXHAUSTED',
    });
  });
});
