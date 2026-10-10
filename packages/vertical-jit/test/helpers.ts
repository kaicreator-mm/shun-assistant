// Shared test world for the Loop B vertical: a fixture-like trusted winget
// package (ExampleSoft.PdfTool 2.4.1, mirroring the C-002 contract fixtures)
// wired into the memory harness, plus input factories.
import {
  JitLifecycleOutputSchema,
  type ProviderCapabilityBinding,
  type ProviderEnvironmentBinding,
} from '@shun/contracts';
import {
  type JitHarness,
  jitCapabilityDefinition,
  type MemoryCatalogEntry,
  MockRegistry,
  providerIdFor,
  trustedProviderDefinition,
  untrustedProviderDefinition,
} from '../src/mocks.ts';
import { type JitLifecycleDeps, runJitLifecycle } from '../src/orchestrator.ts';

export const PACKAGE_ID = 'ExampleSoft.PdfTool';
export const PROVIDER_ID = providerIdFor(PACKAGE_ID);
export const VERSION = '2.4.1';
export const CAPABILITY_ID = 'pdf.convert';
export const BINDING_ID = 'binding-pdftool-localwin';

export const INSTALL_DIR = 'C:\\Program Files\\ExampleSoftware\\PdfTool';
export const CACHE_DIR = 'C:\\ProgramData\\ExampleSoftware\\PdfTool\\cache';
export const CONFIG_DIR = 'C:\\Users\\dev\\AppData\\Roaming\\ExampleSoftware';
export const EXECUTABLE = `${INSTALL_DIR}\\pdftool.exe`;
const INSTALLER_SHA256 = 'b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1';

export function catalogEntry(): MemoryCatalogEntry {
  return {
    version: VERSION,
    license: 'MIT',
    publisher: 'ExampleSoftware',
    installerSha256: INSTALLER_SHA256,
    installDir: INSTALL_DIR,
    cacheDir: CACHE_DIR,
    configDir: CONFIG_DIR,
    executableName: 'pdftool.exe',
  };
}

/** Register the trusted provider world (optionally with an untrusted rival binding). */
export function installWorld(harness: JitHarness, options: { untrustedOnly?: boolean } = {}): void {
  const entry = catalogEntry();
  harness.acquisition.register(PACKAGE_ID, entry);
  const bindings: ProviderCapabilityBinding[] = [
    {
      bindingId: BINDING_ID,
      providerId: PROVIDER_ID,
      capabilityId: CAPABILITY_ID,
      capabilityRevisionRange: { min: 'r1' },
      adapterId: 'adapter.jit-cli',
      interfaceClass: 'I1',
      environmentRequirements: { backendKind: 'LOCAL_WINDOWS', os: 'WINDOWS' },
      verifierId: 'verifier.jit-cli',
    },
  ];
  const envBindings: ProviderEnvironmentBinding[] = [
    {
      providerBindingId: `${PROVIDER_ID}@local-windows-1`,
      environmentId: 'local-windows-1',
      feasibility: { feasible: true, rejectionReasons: [] },
    },
  ];
  let providers = [trustedProviderDefinition(PACKAGE_ID, entry)];
  if (options.untrustedOnly) {
    providers = [untrustedProviderDefinition('tool.sketchy', '9.9.9')];
    const [trustedBinding] = bindings.splice(0, 1, {
      bindingId: 'binding-sketchy',
      providerId: 'tool.sketchy',
      capabilityId: CAPABILITY_ID,
      capabilityRevisionRange: { min: 'r1' },
      adapterId: 'adapter.jit-cli',
      interfaceClass: 'I1',
      environmentRequirements: { backendKind: 'LOCAL_WINDOWS', os: 'WINDOWS' },
      verifierId: 'verifier.jit-cli',
    });
    void trustedBinding;
    const [trustedEnv] = envBindings.splice(0, 1, {
      providerBindingId: 'tool.sketchy@local-windows-1',
      environmentId: 'local-windows-1',
      feasibility: { feasible: true, rejectionReasons: [] },
    });
    void trustedEnv;
  }
  const world = new MockRegistry({
    capabilities: [jitCapabilityDefinition(CAPABILITY_ID)],
    providers,
    bindings,
    envBindings,
  });
  (harness.deps as { registry: unknown }).registry = world;
}

export function jitInput(
  overrides: {
    taskId?: string;
    retention?: 'RETAIN' | 'JIT_REMOVE_AFTER_VERIFIED_USE';
    argv?: string[];
  } = {},
) {
  return {
    taskId: overrides.taskId ?? 'task-2026-10-10-002',
    capabilityRequirement: { capabilityId: CAPABILITY_ID, revision: 'r1' },
    providerConstraints: { trustedProvenanceRequired: true, supportedPlatform: 'WINDOWS' },
    lifecyclePolicy: { retention: overrides.retention ?? 'RETAIN' },
    targetTask: {
      fixtureRef: 'fixture://pdf-convert/sample-invoice',
      ...(overrides.argv ? { parameters: { argv: overrides.argv } } : {}),
    },
  };
}

/** Clone deps with overrides — JitLifecycleDeps fields are readonly to consumers. */
export function withDeps(
  harness: JitHarness,
  overrides: Partial<JitLifecycleDeps> | Record<string, unknown> = {},
): JitLifecycleDeps {
  return { ...harness.deps, ...overrides } as JitLifecycleDeps;
}

export async function run(harness: JitHarness, input: unknown): Promise<unknown> {
  return runJitLifecycle(input, harness.deps);
}

export { JitLifecycleOutputSchema };
