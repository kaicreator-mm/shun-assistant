// Frozen scenario inputs for the provider-ranking unit benchmarks
// B-033/B-034/B-035 (docs/validation/benchmark-v0.1.md).
//
// These builders are the FROZEN INPUT side of the comparison. The gold
// dispositions live separately in evidence/gold-ranking-evidence.ts and are
// derived from the hard requirements listed there — never from the resolver
// score under test. Changing a fixture here invalidates the corresponding
// gold record and requires an evidence revision bump.
import type { BindingScoreFacts } from '../src/ranking.ts';
import { type ObjectiveMatcherTable, ShunRegistry } from '../src/registry.ts';
import { bindingDef, capabilityDef, ENV_LOCAL, providerDef, requirements } from './scenarios.ts';

function registryOf(parts: {
  capabilities?: ReturnType<typeof capabilityDef>[];
  providers?: ReturnType<typeof providerDef>[];
  bindings?: ReturnType<typeof bindingDef>[];
  env?: typeof ENV_LOCAL;
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

// ---------------------------------------------------------------------------
// B-033 scenario: FFmpeg-like CLI vs HandBrake-like batch tool vs GUI
// converter under batch/low-resource/offline constraints. All three are
// offline-capable on purpose: this isolates RANKING from policy rejection.
// ---------------------------------------------------------------------------

export function b033Registry() {
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

export const B033_FACTS: BindingScoreFacts[] = [
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

export const UNINSTALL_MATCHERS: ObjectiveMatcherTable = {
  'software.uninstall_safe': [/\bsoftware\.uninstall_safe\b/],
};

export function b034Registry() {
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

// ---------------------------------------------------------------------------
// B-035 scenario: structured CLI provider vs pretty GUI converter.
// ---------------------------------------------------------------------------

export function b035Registry() {
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
  const bindings = [
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
  ];
  return registryOf({ capabilities: [capability], providers: [cli, pretty], bindings });
}

export const B035_FACTS: BindingScoreFacts[] = [
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

export const B034_ACKNOWLEDGED_FACTS: BindingScoreFacts[] = [
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
