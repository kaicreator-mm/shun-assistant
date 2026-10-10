// Hard gates: frozen order, short-circuit on first REJECT, fail-closed trust,
// explicit risk escalation (L2 §7.2, P2-02).
import { describe, expect, it } from 'vitest';
import { runHardGates } from '../src/gates.ts';
import {
  bindingDef,
  capabilityDef,
  ENV_LOCAL,
  envFacts,
  goalRequest,
  providerDef,
  requirements,
} from './scenarios.ts';

const capability = capabilityDef({ capabilityId: 'image.batch_process' });
const request = goalRequest({ goal: 'image.batch_process: resize photos' });

function gateScenario(opts: {
  binding?: Partial<ReturnType<typeof bindingDef>>;
  provider?: Partial<ReturnType<typeof providerDef>>;
  env?: ReturnType<typeof envFacts>;
  envPolicy?: {
    allowedBackendKinds: ('LOCAL_WINDOWS' | 'LOCAL_POSIX' | 'REMOTE_ECF')[];
    allowElevation: boolean;
  };
  capability?: ReturnType<typeof capabilityDef>;
  constraints?: ReturnType<typeof goalRequest>['constraints'];
}) {
  const gateCapability = opts.capability ?? capability;
  const provider = providerDef({ providerId: 'imageProvider.imagemagick', ...opts.provider });
  const binding = bindingDef({
    bindingId: 'b-1',
    providerId: provider.providerId,
    capabilityId: gateCapability.capabilityId,
    // The scenario policy is local-only/FORBIDDEN, so the default binding
    // declares its no-network posture explicitly (P1-02 disclosure evidence).
    environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
    ...opts.binding,
  });
  return runHardGates(binding, provider, {
    capability: gateCapability,
    environment: opts.env ?? ENV_LOCAL,
    privacyPolicy: request.policyContext.privacyPolicy,
    environmentPolicy: opts.envPolicy ?? request.policyContext.environmentPolicy,
    constraints: opts.constraints ?? request.constraints,
  });
}

describe('hard gates execute before ranking, in frozen order', () => {
  it('a clean binding passes all five gates in the frozen order', () => {
    const outcome = gateScenario({});
    expect(outcome.passed).toBe(true);
    expect(outcome.dispositions.map((entry) => entry.gate)).toEqual([
      'CAPABILITY_FIT',
      'TRUST_SUPPLY_CHAIN',
      'PROVIDER_ENVIRONMENT_FEASIBILITY',
      'USER_ORG_POLICY',
      'SAFETY_CONSTRAINTS',
    ]);
    expect(outcome.dispositions.every((entry) => entry.outcome === 'PASS')).toBe(true);
  });

  it('capability fit: revision outside the binding support window is rejected first', () => {
    const outcome = gateScenario({
      binding: { capabilityRevisionRange: { min: 'r2' } },
    });
    expect(outcome.passed).toBe(false);
    expect(outcome.dispositions).toHaveLength(1);
    expect(outcome.dispositions[0]).toMatchObject({
      gate: 'CAPABILITY_FIT',
      outcome: 'REJECT',
      reason: expect.stringContaining('outside supported range'),
    });
  });

  it('capability fit: interface class not allowed by the capability is a contract mismatch', () => {
    const outcome = gateScenario({ binding: { interfaceClass: 'I3' } });
    expect(outcome.dispositions[0]).toMatchObject({
      gate: 'CAPABILITY_FIT',
      outcome: 'REJECT',
      reason: expect.stringContaining('interface class I3 not allowed'),
    });
  });

  it('capability fit: a binding wired to a foreign verifier cannot pass', () => {
    const outcome = gateScenario({ binding: { verifierId: 'verifier.rogue' } });
    expect(outcome.dispositions[0]).toMatchObject({
      gate: 'CAPABILITY_FIT',
      outcome: 'REJECT',
      reason: expect.stringContaining('verifier.rogue'),
    });
  });

  it('trust: UNKNOWN provenance is fail-closed — never trusted by confirmation or outcome evidence', () => {
    const outcome = gateScenario({
      provider: { provenanceFacts: { trustState: 'UNKNOWN' } },
    });
    expect(outcome.passed).toBe(false);
    expect(outcome.dispositions.map((entry) => entry.gate)).toEqual([
      'CAPABILITY_FIT',
      'TRUST_SUPPLY_CHAIN',
    ]);
    expect(outcome.dispositions[1]).toMatchObject({
      outcome: 'REJECT',
      reason: expect.stringContaining('fail-closed'),
    });
  });

  it('trust: missing trust facts fail closed exactly like declared UNKNOWN', () => {
    const outcome = gateScenario({
      provider: { provenanceFacts: { publisher: 'some publisher' } },
    });
    expect(outcome.passed).toBe(false);
    expect(outcome.dispositions[1]).toMatchObject({
      gate: 'TRUST_SUPPLY_CHAIN',
      outcome: 'REJECT',
    });
  });

  it('feasibility gate stops a binding whose requirements do not meet the environment', () => {
    const outcome = gateScenario({
      binding: { environmentRequirements: requirements({ arch: 'ARM64' }) },
    });
    expect(outcome.passed).toBe(false);
    expect(outcome.dispositions.map((entry) => entry.gate)).toEqual([
      'CAPABILITY_FIT',
      'TRUST_SUPPLY_CHAIN',
      'PROVIDER_ENVIRONMENT_FEASIBILITY',
    ]);
  });

  it('policy: local-only privacy rejects network-transferring bindings before ranking', () => {
    const outcome = gateScenario({
      binding: { environmentRequirements: requirements({ networkAccess: 'REQUIRED' }) },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('local-only'),
    });
  });

  it('policy: externalDisclosure FORBIDDEN rejects network-transferring bindings even when localOnly is false (P1-02)', () => {
    const openRequest = goalRequest({ goal: 'image.batch_process: resize photos' });
    openRequest.policyContext.privacyPolicy = {
      localOnly: false,
      externalDisclosure: 'FORBIDDEN',
    };
    const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
    const binding = bindingDef({
      bindingId: 'b-1',
      providerId: provider.providerId,
      capabilityId: capability.capabilityId,
      environmentRequirements: requirements({ networkAccess: 'REQUIRED' }),
    });
    const outcome = runHardGates(binding, provider, {
      capability,
      environment: envFacts({ networkPolicy: 'POLICY_CONTROLLED' }),
      privacyPolicy: openRequest.policyContext.privacyPolicy,
      environmentPolicy: openRequest.policyContext.environmentPolicy,
      constraints: openRequest.constraints,
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('disclosure'),
    });
  });

  it('policy: networkAccess OPTIONAL is not a proven no-disclosure posture under a no-disclosure policy (P1-02)', () => {
    const outcome = gateScenario({
      binding: { environmentRequirements: requirements({ networkAccess: 'OPTIONAL' }) },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('OPTIONAL'),
    });
  });

  it('policy: a binding that declares no network-access posture fails closed under a no-disclosure policy (P1-02)', () => {
    const outcome = gateScenario({
      binding: { environmentRequirements: requirements({}) },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('no network-access posture'),
    });
  });

  it('policy: an explicitly no-network binding is the disclosure evidence a no-disclosure policy accepts (P1-02)', () => {
    const openRequest = goalRequest({ goal: 'image.batch_process: resize photos' });
    openRequest.policyContext.privacyPolicy = {
      localOnly: false,
      externalDisclosure: 'FORBIDDEN',
    };
    const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
    const binding = bindingDef({
      bindingId: 'b-1',
      providerId: provider.providerId,
      capabilityId: capability.capabilityId,
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
    });
    const outcome = runHardGates(binding, provider, {
      capability,
      environment: ENV_LOCAL,
      privacyPolicy: openRequest.policyContext.privacyPolicy,
      environmentPolicy: openRequest.policyContext.environmentPolicy,
      constraints: openRequest.constraints,
    });
    expect(outcome.passed).toBe(true);
    const policyRow = outcome.dispositions.find((entry) => entry.gate === 'USER_ORG_POLICY');
    expect(policyRow).toMatchObject({ outcome: 'PASS' });
  });

  it('policy: elevation forbidden by goal policy is a policy rejection, not a feasibility fact', () => {
    const outcome = gateScenario({
      binding: { environmentRequirements: requirements({ privilegeMode: 'ELEVATED_ADMIN' }) },
      env: envFacts({ privilegeMode: 'ELEVATED_ADMIN' }),
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('elevated'),
    });
  });

  it('safety: unacknowledged escalation is REJECTED with its explicit reason recorded', () => {
    const outcome = gateScenario({
      provider: {
        provenanceFacts: {
          trustState: 'TRUSTED',
          safetyProfile: {
            riskEscalationRequired: true,
            escalationReason: 'aggressive residue cleanup exceeds the capability risk envelope',
          },
        },
      },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'SAFETY_CONSTRAINTS',
      outcome: 'REJECT',
      reason: expect.stringContaining('aggressive residue cleanup'),
    });
  });

  it('policy: requested format not covered by curated provider format facts is rejected (P1-04)', () => {
    const outcome = gateScenario({
      provider: {
        provenanceFacts: { trustState: 'TRUSTED', formatSupport: ['PNG', 'WEBP'] },
      },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('format'),
    });
  });

  it('policy: requested format covered by curated format facts passes (P1-04)', () => {
    const outcome = gateScenario({
      provider: {
        provenanceFacts: { trustState: 'TRUSTED', formatSupport: ['jpg', 'PNG'] },
      },
    });
    expect(outcome.passed).toBe(true);
    const policyRow = outcome.dispositions.find((entry) => entry.gate === 'USER_ORG_POLICY');
    expect(policyRow).toMatchObject({ outcome: 'PASS' });
  });

  it('policy: a requested format with no curated format facts is explicitly deferred, never silently certified (P1-04)', () => {
    const outcome = gateScenario({});
    expect(outcome.passed).toBe(true);
    const policyRow = outcome.dispositions.find((entry) => entry.gate === 'USER_ORG_POLICY');
    expect(policyRow?.outcome).toBe('PASS');
    expect(policyRow?.reason).toContain('not gate-evaluable');
    expect(policyRow?.reason).toContain('deferred');
  });

  it('policy: a malformed curated formatSupport fact fails closed (P1-04)', () => {
    const outcome = gateScenario({
      provider: {
        provenanceFacts: {
          trustState: 'TRUSTED',
          formatSupport: ['JPG', 42],
        } as unknown as Record<string, unknown>,
      },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('formatSupport'),
    });
  });

  it('policy: a requested licensing identity that the provider license facts do not satisfy is rejected (P1-04)', () => {
    const outcome = gateScenario({
      constraints: { format: 'JPG', licensing: 'Apache-2.0' },
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('Apache-2.0'),
    });
  });

  it('policy: a requested licensing identity matching the provider license facts passes case-insensitively (P1-04)', () => {
    const outcome = gateScenario({
      constraints: { format: 'JPG', licensing: '  mit ' },
    });
    expect(outcome.passed).toBe(true);
  });

  it('policy: a capability-required policy fact missing from goal constraints fails closed (P1-04)', () => {
    const outcome = gateScenario({
      capability: capabilityDef({
        capabilityId: 'image.batch_process',
        requiredPolicyFacts: ['maxDeleteBytesPerRun'],
      }),
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('maxDeleteBytesPerRun'),
    });
  });

  it('policy: capability-required policy facts present in goal constraints pass (P1-04)', () => {
    const requestWithFact = goalRequest({ goal: 'image.batch_process: resize photos' });
    requestWithFact.constraints.other = { maxDeleteBytesPerRun: 1_000_000 };
    const outcome = gateScenario({
      capability: capabilityDef({
        capabilityId: 'image.batch_process',
        requiredPolicyFacts: ['maxDeleteBytesPerRun'],
      }),
      constraints: requestWithFact.constraints,
    });
    expect(outcome.passed).toBe(true);
  });

  it('safety: a present but malformed safetyProfile fails closed instead of counting as safety PASS (P1-03)', () => {
    const malformedProfiles: unknown[] = [
      // riskEscalationRequired: true with a missing reason
      { riskEscalationRequired: true },
      // non-string escalation reason
      { riskEscalationRequired: true, escalationReason: 42 },
      // empty-string escalation reason
      { riskEscalationRequired: true, escalationReason: '' },
      // non-object profile
      'aggressive cleanup',
      // out-of-vocabulary escalation flag (the curated fact only models true)
      { riskEscalationRequired: false, escalationReason: 'no escalation' },
    ];
    for (const [index, safetyProfile] of malformedProfiles.entries()) {
      const outcome = gateScenario({
        provider: {
          provenanceFacts: { trustState: 'TRUSTED', safetyProfile } as Record<string, unknown>,
        },
      });
      expect(outcome.passed, `malformed profile case ${index}`).toBe(false);
      const last = outcome.dispositions[outcome.dispositions.length - 1];
      expect(last, `malformed profile case ${index}`).toMatchObject({
        gate: 'SAFETY_CONSTRAINTS',
        outcome: 'REJECT',
        reason: expect.stringContaining('malformed'),
      });
    }
  });

  it('safety: an absent safetyProfile still means no escalation and passes (P1-03 absence case)', () => {
    const outcome = gateScenario({});
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({ gate: 'SAFETY_CONSTRAINTS', outcome: 'PASS' });
  });

  it('safety: acknowledged escalation stays feasible and is surfaced as ESCALATION_REQUIRED', () => {
    const requestWithAck = goalRequest({ goal: 'image.batch_process: resize photos' });
    requestWithAck.constraints.other = { riskEscalationAcknowledged: true };
    const provider = providerDef({
      providerId: 'imageProvider.imagemagick',
      provenanceFacts: {
        trustState: 'TRUSTED',
        safetyProfile: {
          riskEscalationRequired: true,
          escalationReason: 'aggressive residue cleanup exceeds the capability risk envelope',
        },
      },
    });
    const binding = bindingDef({
      bindingId: 'b-1',
      providerId: provider.providerId,
      capabilityId: capability.capabilityId,
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
    });
    const outcome = runHardGates(binding, provider, {
      capability,
      environment: ENV_LOCAL,
      privacyPolicy: requestWithAck.policyContext.privacyPolicy,
      environmentPolicy: requestWithAck.policyContext.environmentPolicy,
      constraints: requestWithAck.constraints,
    });
    expect(outcome.passed).toBe(true);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({ gate: 'SAFETY_CONSTRAINTS', outcome: 'ESCALATION_REQUIRED' });
    expect(outcome.escalation).toEqual({
      riskEscalationRequired: true,
      escalationReason: 'aggressive residue cleanup exceeds the capability risk envelope',
      acknowledged: true,
    });
  });
});
