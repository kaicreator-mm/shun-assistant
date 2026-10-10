// End-to-end resolution: C-000 ResolutionRecord over scenario registries.
//
// Required task evidence mapped to tests:
// - B-033/034/035 independent gold comparison (gold defined below from hard
//   requirements ONLY, hidden from the resolver run — never derived from the
//   score under test, per docs/validation/benchmark-v0.1.md gold procedure);
// - untrusted/missing alternatives (trust fail-closed);
// - native-only Loop C (single native binding selected directly, no
//   manufactured competition);
// - local-only privacy (remote/network providers ineligible);
// - ambiguous goals (typed normalization outcome, no record);
// - no feasible binding (explicit failureDisposition).
import { describe, expect, it } from 'vitest';
import { type BindingScoreFacts, rankFeasibleBindings } from '../src/ranking.ts';
import { type ObjectiveMatcherTable, ShunRegistry } from '../src/registry.ts';
import { resolveGoal } from '../src/resolve.ts';
import {
  bindingDef,
  capabilityDef,
  ENV_LOCAL,
  type envFacts,
  goalRequest,
  providerDef,
  requirements,
} from './scenarios.ts';

function registryOf(parts: {
  capabilities?: ReturnType<typeof capabilityDef>[];
  providers?: ReturnType<typeof providerDef>[];
  bindings?: ReturnType<typeof bindingDef>[];
  env?: ReturnType<typeof envFacts>;
  additionalObjectiveMatchers?: ObjectiveMatcherTable;
}) {
  return ShunRegistry.fromSnapshot(
    {
      capabilities: parts.capabilities ?? [],
      providers: parts.providers ?? [],
      bindings: parts.bindings ?? [],
      environment: parts.env ?? ENV_LOCAL,
    },
    { additionalObjectiveMatchers: parts.additionalObjectiveMatchers },
  );
}

function resolve(registry: ShunRegistry, scoreFacts?: BindingScoreFacts[]) {
  const request = goalRequest({ goal: 'image.batch_process: batch resize my photos offline' });
  request.constraints.other = { offline: true };
  return resolveGoal({ request, registry, scoreFacts });
}

// ---------------------------------------------------------------------------
// B-033 scenario: FFmpeg-like CLI vs HandBrake-like batch tool vs GUI
// converter under batch/low-resource/offline constraints. All three are
// offline-capable on purpose: this isolates RANKING from policy rejection.
// ---------------------------------------------------------------------------

function b033Registry() {
  // The scenario capability permits the I3 fallback class so the GUI converter
  // is a *feasible ranking candidate* — its loss must come from agent
  // usability, not from a contract mismatch (B-033 isolates ranking).
  const capability = capabilityDef({
    capabilityId: 'image.batch_process',
    allowedInterfaceClasses: ['I0', 'I1', 'I2', 'I3'],
  });
  const ff = providerDef({
    providerId: 'imageProvider.ffcli',
    interfaces: [{ interfaceId: 'ffcli', interfaceClass: 'I1', invocation: 'ffcli <typed-args>' }],
  });
  const hb = providerDef({
    providerId: 'imageProvider.hbcli',
    interfaces: [{ interfaceId: 'hbcli', interfaceClass: 'I1', invocation: 'hbcli <typed-args>' }],
  });
  const gui = providerDef({
    providerId: 'imageProvider.guipad',
    interfaces: [
      { interfaceId: 'guipad', interfaceClass: 'I3', invocation: 'guipad-ui <semantics>' },
    ],
  });
  const bindings = [
    bindingDef({
      bindingId: 'b-ff',
      providerId: ff.providerId,
      capabilityId: 'image.batch_process',
      interfaceClass: 'I1',
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN', minFreeDiskMb: 512 }),
    }),
    bindingDef({
      bindingId: 'b-hb',
      providerId: hb.providerId,
      capabilityId: 'image.batch_process',
      interfaceClass: 'I1',
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN', minFreeDiskMb: 1024 }),
    }),
    bindingDef({
      bindingId: 'b-gui',
      providerId: gui.providerId,
      capabilityId: 'image.batch_process',
      interfaceClass: 'I3',
      environmentRequirements: requirements({
        networkAccess: 'FORBIDDEN',
        guiSessionRequired: true,
        minFreeDiskMb: 2048,
      }),
    }),
  ];
  return registryOf({ capabilities: [capability], providers: [ff, hb, gui], bindings });
}

// INDEPENDENT GOLD — derived from hard requirements only (batch automation
// must be unattended, structured, headless; low resource favors small
// footprint; offline forbids network). NOT computed with the resolver score:
//   1. b-ff  — native directory/queue batch, fully headless, best structured
//              I/O, smallest footprint → satisfies every hard requirement;
//   2. b-hb  — batch possible but coarser structured I/O and heavier
//              footprint → partially satisfies automation requirements;
//   3. b-gui — interactive UI per batch fails unattended automation outright
//              → last regardless of brand or human usability.
const B033_GOLD = ['b-ff', 'b-hb', 'b-gui'] as const;

const B033_FACTS: BindingScoreFacts[] = [
  {
    bindingId: 'b-ff',
    components: {
      capabilityFit: 90,
      reliability: 85,
      agentUsability: 92,
      trust: 90,
      environmentCompatibility: 85,
      performance: 80,
      humanUsability: 60,
    },
  },
  {
    bindingId: 'b-hb',
    components: {
      capabilityFit: 85,
      reliability: 80,
      agentUsability: 68,
      trust: 88,
      environmentCompatibility: 80,
      performance: 65,
      humanUsability: 75,
    },
  },
  {
    bindingId: 'b-gui',
    components: {
      capabilityFit: 80,
      reliability: 75,
      agentUsability: 25,
      trust: 85,
      environmentCompatibility: 60,
      performance: 50,
      humanUsability: 90,
    },
  },
];

// ---------------------------------------------------------------------------
// B-034 scenario: safer uninstaller vs Revo-like aggressive uninstaller.
// ---------------------------------------------------------------------------

const UNINSTALL_MATCHERS = {
  'software.uninstall_safe': [/\bsoftware\.uninstall_safe\b/],
};

function b034Registry() {
  const capability = capabilityDef({
    capabilityId: 'software.uninstall_safe',
    sideEffectClass: 'R2',
  });
  const safer = providerDef({ providerId: 'softwareProvider.safer-uninstaller' });
  const aggressive = providerDef({
    providerId: 'softwareProvider.aggressive-uninstaller',
    provenanceFacts: {
      trustState: 'TRUSTED',
      safetyProfile: {
        riskEscalationRequired: true,
        escalationReason:
          'aggressive registry/residue cleanup exceeds the declared uninstall envelope',
      },
    },
  });
  const bindings = [
    bindingDef({
      bindingId: 'b-safer',
      providerId: safer.providerId,
      capabilityId: 'software.uninstall_safe',
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
    }),
    bindingDef({
      bindingId: 'b-aggressive',
      providerId: aggressive.providerId,
      capabilityId: 'software.uninstall_safe',
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
    }),
  ];
  return registryOf({
    capabilities: [capability],
    providers: [safer, aggressive],
    bindings,
    additionalObjectiveMatchers: UNINSTALL_MATCHERS,
  });
}

describe('resolution records over scenario registries', () => {
  it('produces a frozen-contract record with explainable selection on the happy path', () => {
    const capability = capabilityDef({ capabilityId: 'image.batch_process' });
    const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
    const registry = registryOf({
      capabilities: [capability],
      providers: [provider],
      bindings: [
        bindingDef({
          bindingId: 'b-im',
          providerId: provider.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.taskId).toBe('task-t01-001');
    expect(record.resolvedCapabilityId).toBe('image.batch_process');
    expect(record.selectedBindingId).toBe('b-im');
    expect(record.feasibleBindings).toEqual(['b-im']);
    expect(record.riskClass).toBe('R1');
    expect(record.executionPlanClass).toBe('KNOWN_CAPABILITY_DETERMINISTIC');
    expect(record.verificationPlan.verifierId).toBe('verifier.generic');
    expect(record.privacyDisclosurePlan.externalDisclosure).toBe('FORBIDDEN');
    expect(record.privacyDisclosurePlan.notes.join(' ')).toContain('local-only');
    expect(record.failureDisposition).toBeNull();
    expect(record.selectionReasons.join(' ')).toContain('single trusted binding');
  });

  it('B-033: top-1 matches the independent gold ranking under batch/offline constraints', () => {
    const result = resolve(b033Registry(), B033_FACTS);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    // All three are feasible — this is a pure ranking comparison, not a policy filter.
    expect(record.feasibleBindings).toEqual(['b-ff', 'b-hb', 'b-gui']);
    expect(record.selectedBindingId).toBe(B033_GOLD[0]);
    expect(record.selectionReasons.join(' ')).toContain('ranked #1 of 3');
  });

  it('B-033: full resolver order agrees with the hidden gold order (top-k agreement)', () => {
    const registry = b033Registry();
    const bindings = registry.bindingsForCapability('image.batch_process');
    const ranked = rankFeasibleBindings({
      bindings: bindings.map((binding) => ({ ...binding })),
      scoreFacts: B033_FACTS,
    });
    expect(ranked.map((entry) => entry.bindingId)).toEqual([...B033_GOLD]);
  });

  it('B-034: default policy selects the safer uninstaller and records the explicit escalation reason', () => {
    const request = goalRequest({
      goal: 'software.uninstall_safe: uninstall a normal desktop app',
    });
    const result = resolveGoal({ request, registry: b034Registry() });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.selectedBindingId).toBe('b-safer');
    expect(record.feasibleBindings).toEqual(['b-safer']);
    expect(record.riskClass).toBe('R2');
    const aggressiveDisposition = record.hardGateDispositions
      .filter((entry) => entry.bindingId === 'b-aggressive')
      .pop();
    expect(aggressiveDisposition).toMatchObject({
      gate: 'SAFETY_CONSTRAINTS',
      outcome: 'REJECT',
      reason: expect.stringContaining('aggressive registry/residue cleanup'),
    });
  });

  it('B-034: with explicitly acknowledged escalation the stronger tool may win — but only with its upgrade reason surfaced', () => {
    const request = goalRequest({
      goal: 'software.uninstall_safe: uninstall a normal desktop app',
    });
    request.constraints.other = { riskEscalationAcknowledged: true };
    const facts: BindingScoreFacts[] = [
      {
        bindingId: 'b-safer',
        components: {
          capabilityFit: 85,
          reliability: 85,
          agentUsability: 60,
          trust: 90,
          environmentCompatibility: 85,
          performance: 70,
          humanUsability: 80,
        },
      },
      {
        bindingId: 'b-aggressive',
        components: {
          capabilityFit: 95,
          reliability: 85,
          agentUsability: 90,
          trust: 90,
          environmentCompatibility: 85,
          performance: 85,
          humanUsability: 60,
        },
      },
    ];
    const result = resolveGoal({ request, registry: b034Registry(), scoreFacts: facts });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.feasibleBindings).toEqual(['b-safer', 'b-aggressive']);
    expect(record.selectedBindingId).toBe('b-aggressive');
    expect(record.selectionReasons.join(' ')).toContain(
      'acknowledged safety escalation: aggressive registry/residue cleanup',
    );
  });

  it('B-035: a structured CLI provider beats a pretty GUI despite the GUI being more human-friendly', () => {
    const capability = capabilityDef({
      capabilityId: 'image.batch_process',
      allowedInterfaceClasses: ['I0', 'I1', 'I2', 'I3'],
    });
    const cli = providerDef({ providerId: 'imageProvider.mpvcli' });
    const pretty = providerDef({
      providerId: 'imageProvider.prettygui',
      interfaces: [
        { interfaceId: 'prettygui-ui', interfaceClass: 'I3', invocation: 'prettygui semantic-ui' },
      ],
    });
    const registry = registryOf({
      capabilities: [capability],
      providers: [cli, pretty],
      bindings: [
        bindingDef({
          bindingId: 'b-cli',
          providerId: cli.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
        }),
        bindingDef({
          bindingId: 'b-pretty',
          providerId: pretty.providerId,
          capabilityId: 'image.batch_process',
          interfaceClass: 'I3',
          environmentRequirements: requirements({
            networkAccess: 'FORBIDDEN',
            guiSessionRequired: true,
          }),
        }),
      ],
    });
    // GUI is the more popular, more human-usable product — the gold rule for
    // batch automation is agent usability: structured CLI wins (hard
    // requirement: unattended structured execution).
    const facts: BindingScoreFacts[] = [
      {
        bindingId: 'b-cli',
        components: {
          capabilityFit: 88,
          reliability: 85,
          agentUsability: 90,
          trust: 85,
          environmentCompatibility: 85,
          performance: 80,
          humanUsability: 55,
        },
      },
      {
        bindingId: 'b-pretty',
        components: {
          capabilityFit: 88,
          reliability: 88,
          agentUsability: 22,
          trust: 92,
          environmentCompatibility: 80,
          performance: 60,
          humanUsability: 97,
        },
      },
    ];
    const result = resolve(registry, facts);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe('b-cli');
    expect(result.record.feasibleBindings).toContain('b-pretty');
  });

  it('native-only Loop C: a single trusted native binding is selected directly, without manufactured competition', () => {
    const capability = capabilityDef({
      capabilityId: 'system.storage.diagnose_bounded_action',
      sideEffectClass: 'R0',
      allowedInterfaceClasses: ['I0', 'I1', 'I2'],
    });
    const native = providerDef({
      providerId: 'systemProvider.windows-observation',
      interfaces: [
        { interfaceId: 'win-obs', interfaceClass: 'I0', invocation: 'Win32 StorageRelocationAPI' },
      ],
    });
    const registry = registryOf({
      capabilities: [capability],
      providers: [native],
      bindings: [
        bindingDef({
          bindingId: 'b-native',
          providerId: native.providerId,
          capabilityId: 'system.storage.diagnose_bounded_action',
          interfaceClass: 'I0',
          environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
        }),
      ],
      additionalObjectiveMatchers: {
        'system.storage.diagnose_bounded_action': [/\bsystem\.storage\.diagnose_bounded_action\b/],
      },
    });
    const request = goalRequest({
      goal: 'system.storage.diagnose_bounded_action: explain C: usage',
    });
    const result = resolveGoal({ request, registry });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.candidates).toHaveLength(1);
    expect(record.feasibleBindings).toEqual(['b-native']);
    expect(record.selectedBindingId).toBe('b-native');
    expect(record.selectionReasons[0]).toContain('without manufactured competition');
    expect(record.riskClass).toBe('R0');
  });

  it('local-only privacy makes the network-transferring alternative ineligible while the local one resolves', () => {
    const capability = capabilityDef({ capabilityId: 'image.batch_process' });
    const local = providerDef({ providerId: 'imageProvider.localcli' });
    const cloud = providerDef({ providerId: 'imageProvider.cloudsvc' });
    const registry = registryOf({
      capabilities: [capability],
      providers: [local, cloud],
      bindings: [
        bindingDef({
          bindingId: 'b-local',
          providerId: local.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
        }),
        bindingDef({
          bindingId: 'b-cloud',
          providerId: cloud.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'REQUIRED' }),
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.selectedBindingId).toBe('b-local');
    expect(record.feasibleBindings).toEqual(['b-local']);
    const cloudDisposition = record.hardGateDispositions
      .filter((entry) => entry.bindingId === 'b-cloud')
      .pop();
    expect(cloudDisposition).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('local-only'),
    });
    expect(record.privacyDisclosurePlan.externalDisclosure).toBe('FORBIDDEN');
  });

  it('no feasible binding yields an explicit NO_FEASIBLE_BINDING failure disposition', () => {
    const capability = capabilityDef({ capabilityId: 'image.batch_process' });
    const provider = providerDef({ providerId: 'imageProvider.armonly' });
    const registry = registryOf({
      capabilities: [capability],
      providers: [provider],
      bindings: [
        bindingDef({
          bindingId: 'b-arm',
          providerId: provider.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ arch: 'ARM64' }),
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.selectedBindingId).toBeNull();
    expect(record.feasibleBindings).toEqual([]);
    expect(record.failureDisposition).toEqual({
      failureCode: 'NO_FEASIBLE_BINDING',
      detail: expect.stringContaining('no Provider × Environment binding is feasible'),
    });
  });

  it('an all-UNKNOWN candidate set fails closed with NO_TRUSTED_PROVIDER', () => {
    const capability = capabilityDef({ capabilityId: 'image.batch_process' });
    const shady = providerDef({
      providerId: 'imageProvider.shady',
      provenanceFacts: { trustState: 'UNKNOWN' },
    });
    const registry = registryOf({
      capabilities: [capability],
      providers: [shady],
      bindings: [
        bindingDef({
          bindingId: 'b-shady',
          providerId: shady.providerId,
          capabilityId: 'image.batch_process',
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBeNull();
    expect(result.record.failureDisposition?.failureCode).toBe('NO_TRUSTED_PROVIDER');
  });

  it('untrusted alternatives are rejected while the trusted one resolves (missing alternatives)', () => {
    const capability = capabilityDef({ capabilityId: 'image.batch_process' });
    const trusted = providerDef({ providerId: 'imageProvider.trusted' });
    const untrusted = providerDef({
      providerId: 'imageProvider.untrusted',
      provenanceFacts: { trustState: 'UNTRUSTED' },
    });
    const registry = registryOf({
      capabilities: [capability],
      providers: [trusted, untrusted],
      bindings: [
        bindingDef({
          bindingId: 'b-trusted',
          providerId: trusted.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
        }),
        bindingDef({
          bindingId: 'b-untrusted',
          providerId: untrusted.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe('b-trusted');
    expect(result.record.feasibleBindings).toEqual(['b-trusted']);
    const trustRow = result.record.hardGateDispositions.find(
      (entry) => entry.bindingId === 'b-untrusted' && entry.gate === 'TRUST_SUPPLY_CHAIN',
    );
    expect(trustRow?.outcome).toBe('REJECT');
  });

  it('a capability with zero discovered providers fails with NO_TRUSTED_PROVIDER', () => {
    const registry = registryOf({
      capabilities: [capabilityDef({ capabilityId: 'image.batch_process' })],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.failureDisposition?.failureCode).toBe('NO_TRUSTED_PROVIDER');
    expect(result.record.failureDisposition?.detail).toContain('no discovered provider');
  });

  it('a binding referencing a missing provider fails closed with REGISTRY_CURRENTNESS_INSUFFICIENT', () => {
    const registry = registryOf({
      capabilities: [capabilityDef({ capabilityId: 'image.batch_process' })],
      bindings: [
        bindingDef({
          bindingId: 'b-dangling',
          providerId: 'imageProvider.evaporated',
          capabilityId: 'image.batch_process',
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.selectedBindingId).toBeNull();
    expect(record.candidates).toEqual([]);
    expect(record.failureDisposition?.failureCode).toBe('REGISTRY_CURRENTNESS_INSUFFICIENT');
    expect(record.failureDisposition?.detail).toContain('imageProvider.evaporated');
  });

  it('a policy-blocked candidate set yields POLICY_BLOCKED, not a generic infeasible', () => {
    const capability = capabilityDef({ capabilityId: 'image.batch_process' });
    const cloud = providerDef({ providerId: 'imageProvider.cloudonly' });
    const registry = registryOf({
      capabilities: [capability],
      providers: [cloud],
      bindings: [
        bindingDef({
          bindingId: 'b-cloudonly',
          providerId: cloud.providerId,
          capabilityId: 'image.batch_process',
          environmentRequirements: requirements({ networkAccess: 'REQUIRED' }),
        }),
      ],
    });
    const result = resolve(registry);
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.failureDisposition?.failureCode).toBe('POLICY_BLOCKED');
  });

  it('resolution is deterministic: identical input produces an identical record', () => {
    const once = resolve(b033Registry(), B033_FACTS);
    const twice = resolve(b033Registry(), B033_FACTS);
    expect(once).toEqual(twice);
  });

  it('an ambiguous goal surfaces the typed normalization outcome, never a record', () => {
    const registry = registryOf({
      capabilities: [
        capabilityDef({ capabilityId: 'image.batch_process' }),
        capabilityDef({ capabilityId: 'system.storage.diagnose_bounded_action' }),
      ],
      additionalObjectiveMatchers: {
        'system.storage.diagnose_bounded_action': [/\bsystem\.storage\.diagnose_bounded_action\b/],
      },
    });
    const request = goalRequest({
      goal: 'image.batch_process and system.storage.diagnose_bounded_action please',
    });
    const result = resolveGoal({ request, registry });
    expect(result.stage).toBe('GOAL_NOT_READY');
    if (result.stage !== 'GOAL_NOT_READY') return;
    expect(result.normalization).toEqual({
      status: 'NOT_READY',
      disposition: 'NEEDS_CLARIFICATION',
      failureCode: 'GOAL_AMBIGUOUS',
      detail: expect.any(String),
    });
  });
});
