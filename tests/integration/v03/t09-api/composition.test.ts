// T09 BUILD composition suite: the controlled Shun K/S/B/C whitelist maps to
// plain-data BUILD input for the REAL public DomainHarness buildV10App SDK
// (offline consumer over the frozen t00 fixture tarballs). The adapter never
// imports the SDK; the public SDK is the independent admission authority.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type ComposedDomainBuild,
  composeDomainBuild,
  V03_BUSINESS_PACKAGE_ID,
  V03_CAPABILITY_PACKAGE_ID,
  V03_CLOUD_IMPORT_SPECIFIER,
  V03_EXTERNAL_IMPORT_BINDINGS,
  V03_INTENT_ID,
  V03_KERNEL_PACKAGE_ID,
  V03_OPERATION_ID,
  V03_SEMANTIC_PACKAGE_ID,
  V03_TARGET_PROFILE,
  V03_TRUSTED_CLOUD_INTERPRETER_PORT,
} from '../../../../packages/domain-app/src/build/composition.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '../../../..');
const fixturesDir = join(here, '../t00-scaffold/fixtures');
const SDK_TARBALLS = [
  'kaicreator-domain-harness-contracts-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-microkernel-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-host-node-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-build-0.10.2-rc.0.tgz',
];
const VALID_SELECTION = [
  { kind: 'kernel' as const },
  { kind: 'semantic' as const },
  { kind: 'business' as const },
  { kind: 'capability-llm-openai-compatible' as const },
];

function composed(input?: {
  appId?: unknown;
  audience?: unknown;
  buildId?: unknown;
  selectedModules?: unknown;
}): ComposedDomainBuild {
  const result = composeDomainBuild({
    appId: input?.appId ?? 'shun-v03-domain-app',
    audience: input?.audience ?? 'operator-local',
    buildId: input?.buildId,
    selectedModules: input?.selectedModules ?? VALID_SELECTION,
  });
  expect('status' in result && result.status === 'REFUSED').toBe(false);
  return result as ComposedDomainBuild;
}

function refused(input?: {
  appId?: unknown;
  audience?: unknown;
  buildId?: unknown;
  selectedModules?: unknown;
}): { code: string; detail: string } {
  const result = composeDomainBuild({
    appId: input?.appId ?? 'shun-v03-domain-app',
    audience: input?.audience ?? 'operator-local',
    buildId: input?.buildId,
    selectedModules: input?.selectedModules ?? VALID_SELECTION,
  });
  expect('status' in result && result.status === 'REFUSED').toBe(true);
  const rejection = result as { status: 'REFUSED'; code: string; detail: string };
  expect(rejection.code).toBe('BUILD_INPUT_INVALID');
  return rejection;
}

// ---- Adapter-level composition (pure, deterministic) ----

describe('composeDomainBuild adapter', () => {
  it('composes the selected K/S/B/C onto SDK-ready plain data', () => {
    const build = composed();
    const { options } = build;
    expect(options.appId).toBe('shun-v03-domain-app');
    expect(options.audience).toBe('operator-local');
    expect(options.buildId).toBe('shun-v0.3-t09');
    expect(options.targetProfile).toBe(V03_TARGET_PROFILE);
    expect(options.hardBudget).toEqual({ maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 });
    expect(options.modules.map((module) => module.packageId)).toEqual([
      V03_KERNEL_PACKAGE_ID,
      V03_SEMANTIC_PACKAGE_ID,
      V03_BUSINESS_PACKAGE_ID,
      V03_CAPABILITY_PACKAGE_ID,
    ]);
    const roles = options.modules.map((module) => module.role);
    expect(roles).toEqual(['kernel-primary', 'standard-primary', 'business', 'capability']);
    const kernel = options.modules[0];
    expect(kernel?.abiVersion).toBe('v08-kernel-abi/1');
    const capability = options.modules[3];
    expect(capability?.abiVersion).toBe('v08-capability-abi/1');
    expect(capability?.capabilityId).toBe(V03_TRUSTED_CLOUD_INTERPRETER_PORT);
    expect(capability?.handlers).toEqual([
      { operationId: V03_OPERATION_ID, handler: V03_OPERATION_ID },
    ]);
    // The selected C's single ordinary import is the trusted interpreter seam.
    expect(capability?.externalImports).toEqual({
      node: [],
      npm: [V03_CLOUD_IMPORT_SPECIFIER],
      native: [],
    });
    // Closed feature/intent graph: B requires the S feature and owns the intent.
    const business = options.modules[2];
    expect(business?.provides).toEqual([`intent:${V03_INTENT_ID}`]);
    expect(business?.requires).toEqual(['standard:goal-semantic/1']);
    expect(business?.dependencies).toEqual([V03_SEMANTIC_PACKAGE_ID]);
    expect(options.routes).toEqual([
      {
        intentId: V03_INTENT_ID,
        operationId: V03_OPERATION_ID,
        capabilityId: V03_TRUSTED_CLOUD_INTERPRETER_PORT,
        handlerId: V03_OPERATION_ID,
      },
    ]);
    expect(build.externalImportBindings).toEqual(V03_EXTERNAL_IMPORT_BINDINGS);
    expect(build.externalImportBindings).toEqual({
      'domain-harness-openai-host': 'shun.trusted-cloud-interpreter.v03',
    });
  });

  it('seals byte-identical deterministic bytes (sha256 pin) and freezes the output', () => {
    const build = composed();
    for (const module of build.options.modules) {
      expect(typeof module.moduleSource).toBe('string');
      expect(
        createHash('sha256')
          .update(module.moduleSource ?? '', 'utf8')
          .digest('hex'),
      ).toBe(module.moduleSha256);
    }
    expect(Object.isFrozen(build)).toBe(true);
    expect(Object.isFrozen(build.options)).toBe(true);
    expect(Object.isFrozen(build.options.modules)).toBe(true);
    expect(Object.isFrozen(build.options.modules[0])).toBe(true);
    const again = composed();
    expect(JSON.stringify(again)).toBe(JSON.stringify(build));
  });

  it('refuses unknown, duplicate, missing and malformed declarations', () => {
    expect(refused({ selectedModules: VALID_SELECTION.slice(0, 3) }).detail).toMatch(/missing/);
    expect(refused({ selectedModules: [...VALID_SELECTION, { kind: 'kernel' }] }).detail).toMatch(
      /duplicate/,
    );
    expect(
      refused({ selectedModules: [...VALID_SELECTION, { kind: 'kernel-extension' }] }).detail,
    ).toMatch(/unknown selected module role/);
    expect(
      refused({ selectedModules: [...VALID_SELECTION, { kind: 'business', extra: 1 }] }).detail,
    ).toMatch(/exactly one field/);
    expect(refused({ selectedModules: [] }).detail).toMatch(/non-empty array/);
    expect(refused({ selectedModules: 'kernel' }).detail).toMatch(/non-empty array/);
    expect(refused({ selectedModules: [{ kind: 42 }] }).detail).toMatch(
      /unknown selected module role/,
    );
  });

  it('refuses malformed identity fields and unknown top-level fields', () => {
    expect(refused({ appId: '' }).detail).toMatch(/appId/);
    expect(refused({ appId: '9starts-with-digit' }).detail).toMatch(/appId/);
    expect(refused({ appId: 123 }).detail).toMatch(/appId/);
    expect(refused({ audience: 'has space' }).detail).toMatch(/audience/);
    expect(refused({ buildId: 'bad id!' }).detail).toMatch(/buildId/);
    const result = composeDomainBuild({
      appId: 'shun-v03-domain-app',
      audience: 'operator-local',
      selectedModules: VALID_SELECTION,
      buildTarget: 'extra',
    } as unknown as Parameters<typeof composeDomainBuild>[0]);
    expect('status' in result && result.status === 'REFUSED').toBe(true);
    expect((result as { detail: string }).detail).toMatch(/unknown composition field/);
  });
});

// ---- Real public SDK verification (offline consumer over frozen tarballs) ----

const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
let consumerDir: string | null = null;

async function installConsumer(): Promise<string> {
  if (consumerDir) return consumerDir;
  const consumer = mkdtempSync(join(tmpdir(), 't09-build-consumer-'));
  writeFileSync(
    join(consumer, 'package.json'),
    JSON.stringify({ name: 't09-build-consumer', version: '0.0.0', private: true }, null, 2),
  );
  const tarPaths = SDK_TARBALLS.map((name) => join(fixturesDir, name));
  const command = `${npmBin} install --offline --legacy-peer-deps --no-audit --no-fund ${tarPaths
    .map((tarball) => `"${tarball}"`)
    .join(' ')}`;
  const install = spawnSync(command, { cwd: consumer, encoding: 'utf8', shell: true });
  expect(install.status).toBe(0);
  expect(readdirSync(join(consumer, 'node_modules', '@kaicreator')).sort()).toEqual([
    'domain-harness-build',
    'domain-harness-contracts',
    'domain-harness-host-node',
    'domain-harness-microkernel',
  ]);
  consumerDir = consumer;
  return consumer;
}

const POSITIVE_PROBE = `
const fs = await import('node:fs');
const { buildV10App } = await import('@kaicreator/domain-harness-build');
const options = JSON.parse(fs.readFileSync('options.json', 'utf8'));
const app = buildV10App(options);
const capability = app.modules.find((m) => m.packageId === '${V03_CAPABILITY_PACKAGE_ID}');
console.log(JSON.stringify({
  formatVersion: app.formatVersion,
  subjectDigest: app.subjectDigest,
  appId: app.appId,
  buildId: app.buildId,
  targetProfile: app.targetProfile,
  hardBudget: app.hardBudget,
  moduleCount: app.modules.length,
  modules: app.modules.map((m) => ({
    packageId: m.packageId,
    role: m.role,
    abiVersion: m.abiVersion,
    sealed: typeof m.moduleSource === 'string' && m.moduleSource.length > 0,
    sha256: m.moduleSha256,
    dependencies: m.dependencies,
    provides: m.provides,
    requires: m.requires,
  })),
  loadOrder: app.loadOrder,
  routes: app.routes,
  capability: capability === undefined ? null : {
    capabilityId: capability.capabilityId,
    externalImports: capability.externalImports,
    handlers: capability.handlers,
  },
}));
`;

const NEGATIVE_PROBE = `
const fs = await import('node:fs');
const { buildV10App } = await import('@kaicreator/domain-harness-build');
const cases = JSON.parse(fs.readFileSync('negatives.json', 'utf8'));
const observed = [];
for (const item of cases) {
  try {
    buildV10App(item.options);
    observed.push({ label: item.label, refused: false, code: null });
  } catch (error) {
    observed.push({ label: item.label, refused: true, code: error.code ?? null });
  }
}
console.log(JSON.stringify(observed));
`;

function runProbe(consumer: string, scriptName: string): Record<string, unknown> {
  const run = spawnSync(`"${process.execPath}" ${scriptName}`, {
    cwd: consumer,
    encoding: 'utf8',
    shell: true,
  });
  expect(run.status).toBe(0);
  return JSON.parse(run.stdout) as Record<string, unknown>;
}

describe('real public SDK buildV10App over the composed selection', () => {
  let consumer: string;

  beforeAll(async () => {
    consumer = await installConsumer();
  });

  afterAll(() => {
    if (consumerDir) {
      try {
        rmSync(consumerDir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup of the temporary consumer
      }
    }
  });

  it('builds the composed selected K,S,B,C app and seals the trusted C import mapping', () => {
    const build = composed({ buildId: 'shun-v0.3-t09' });
    writeFileSync(join(consumer, 'options.json'), JSON.stringify(build.options));
    writeFileSync(join(consumer, 'positive-probe.mjs'), POSITIVE_PROBE);
    const observed = runProbe(consumer, 'positive-probe.mjs');
    expect(observed.formatVersion).toBe('dh.v10.build/1');
    expect(observed.appId).toBe('shun-v03-domain-app');
    expect(observed.buildId).toBe('shun-v0.3-t09');
    expect(observed.targetProfile).toBe(V03_TARGET_PROFILE);
    expect(observed.hardBudget).toEqual({ maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 });
    expect(observed.moduleCount).toBe(4);
    expect(observed.subjectDigest).toMatch(/^[0-9a-f]{64}$/);
    const modules = observed.modules as {
      packageId: string;
      role: string;
      abiVersion: string;
      sealed: boolean;
      sha256: string;
      provides: string[];
      requires: string[];
      dependencies: string[];
    }[];
    expect(modules.map((module) => module.packageId)).toEqual([
      V03_KERNEL_PACKAGE_ID,
      V03_SEMANTIC_PACKAGE_ID,
      V03_BUSINESS_PACKAGE_ID,
      V03_CAPABILITY_PACKAGE_ID,
    ]);
    expect(modules.map((module) => module.role)).toEqual([
      'kernel-primary',
      'standard-primary',
      'business',
      'capability',
    ]);
    expect(modules.every((module) => module.sealed)).toBe(true);
    for (const module of modules) {
      const composedModule = build.options.modules.find(
        (candidate) => candidate.packageId === module.packageId,
      );
      expect(module.sha256).toBe(composedModule?.moduleSha256);
    }
    expect(observed.loadOrder).toContain(V03_KERNEL_PACKAGE_ID);
    expect(observed.routes).toEqual([
      {
        intentId: V03_INTENT_ID,
        operationId: V03_OPERATION_ID,
        capabilityId: V03_TRUSTED_CLOUD_INTERPRETER_PORT,
        handlerId: V03_OPERATION_ID,
      },
    ]);
    expect(observed.capability).toEqual({
      capabilityId: V03_TRUSTED_CLOUD_INTERPRETER_PORT,
      externalImports: { node: [], npm: [V03_CLOUD_IMPORT_SPECIFIER], native: [] },
      handlers: [{ operationId: V03_OPERATION_ID, handler: V03_OPERATION_ID }],
    });
    // The real SDK enforced the sealed import policy itself: a successful
    // build proves the C module's single 'domain-harness-openai-host' edge is
    // sealed by its allowance (and that no undeclared edge slipped in).
    expect(
      modules.every((module) => /^[0-9a-f]{64}$/.test(module.sha256) && module.sealed),
      'real SDK byte-pinning must hold for every sealed module',
    ).toBe(true);
  });

  it('real SDK independently refuses malformed selections (missing S, tampered bytes)', () => {
    const build = composed();
    const withoutSemantic = {
      ...build.options,
      modules: build.options.modules.filter((module) => module.role !== 'standard-primary'),
    };
    const tamperedBytes = {
      ...build.options,
      modules: build.options.modules.map((module) =>
        module.packageId === V03_BUSINESS_PACKAGE_ID
          ? { ...module, moduleSha256: '0'.repeat(64) }
          : module,
      ),
    };
    writeFileSync(
      join(consumer, 'negatives.json'),
      JSON.stringify([
        {
          label: 'missing-standard-primary',
          expectedCode: 'V10_ROLE_CARDINALITY',
          options: withoutSemantic,
        },
        { label: 'tampered-bytes', expectedCode: 'V10_DIGEST_MISMATCH', options: tamperedBytes },
      ]),
    );
    writeFileSync(join(consumer, 'negative-probe.mjs'), NEGATIVE_PROBE);
    const observed = runProbe(consumer, 'negative-probe.mjs') as unknown as {
      label: string;
      refused: boolean;
      code: string | null;
    }[];
    expect(observed).toEqual([
      { label: 'missing-standard-primary', refused: true, code: 'V10_ROLE_CARDINALITY' },
      { label: 'tampered-bytes', refused: true, code: 'V10_DIGEST_MISMATCH' },
    ]);
  });
});

// ---- Source identity: the adapter never imports the SDK privately ----

/** Import positions only: static/dynamic import specifiers in a TS source. */
function importSpecifiers(content: string): string[] {
  const specifiers: string[] = [];
  const patterns = [
    /from\s+['"]([^'"]+)['"]/g,
    /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /import\s+['"]([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier !== undefined) specifiers.push(specifier);
    }
  }
  return specifiers;
}

describe('source identity', () => {
  it('domain-app never imports the SDK: no @kaicreator specifier anywhere', () => {
    const srcRoot = join(repoRoot, 'packages', 'domain-app', 'src');
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const child = join(dir, entry.name);
        if (entry.isDirectory()) walk(child);
        else if (entry.name.endsWith('.ts')) files.push(child);
      }
    };
    walk(srcRoot);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const content = readFileSync(file, 'utf8');
      // No public or private SDK package specifier may resolve from domain-app.
      expect(content.includes('@kaicreator')).toBe(false);
      for (const specifier of importSpecifiers(content)) {
        expect(specifier.startsWith('domain-harness')).toBe(false);
      }
    }
  });

  it('the v03 route imports only the gateway, never interpreter or server wiring', () => {
    const route = readFileSync(
      join(repoRoot, 'apps', 'control-api', 'src', 'v03', 'gateway-route.ts'),
      'utf8',
    );
    const specifiers = importSpecifiers(route);
    expect(specifiers).toEqual(['../../../../packages/domain-app/src/api/gateway.ts']);
    expect(route.includes('TrustedCloudInterpreter(')).toBe(false);
    expect(route.includes('cloudInterpreterFromEnvironment(')).toBe(false);
  });
});
