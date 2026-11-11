import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(root, '../../../..');

/**
 * V01 qualification — the frozen DomainHarness SDK tarball consumer is SHARED
 * with T11 (the same `node_modules/.t11-dh-consumer` layout). Whichever of
 * T11/T12 loads first pays the one offline `npm install` from the four local
 * file: tarballs (t00 fixtures); the other reuses it. The staged trusted Host
 * package binding the REAL T01 Windows adapter is staged here too, so the
 * in-process consumer composition re-proof below activates the same public
 * SDK surface T11 proves end-to-end (zero real OS effects, zero paid calls).
 */
const SDK_TARBALLS = [
  'kaicreator-domain-harness-contracts-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-microkernel-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-host-node-0.10.2-rc.0.tgz',
  'kaicreator-domain-harness-build-0.10.2-rc.0.tgz',
];
const consumerDir = resolve(repoRoot, 'node_modules/.t11-dh-consumer');

function ensureSdkConsumer(): void {
  const installedMarker = join(
    consumerDir,
    'node_modules/@kaicreator/domain-harness-build/package.json',
  );
  if (existsSync(installedMarker)) return;
  mkdirSync(consumerDir, { recursive: true });
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify({ name: 't11-dh-consumer', version: '0.0.0', private: true }, null, 2),
  );
  const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const tarPaths = SDK_TARBALLS.map((name) =>
    join(repoRoot, 'tests/integration/v03/t00-scaffold/fixtures', name),
  );
  const command = `${npmBin} install --offline --legacy-peer-deps --no-audit --no-fund ${tarPaths
    .map((tarball) => `"${tarball}"`)
    .join(' ')}`;
  const install = spawnSync(command, { cwd: consumerDir, encoding: 'utf8', shell: true });
  if (install.status !== 0) {
    throw new Error(`t12 SDK consumer install failed: ${install.stderr?.slice(-2000)}`);
  }
}

function stageWindowsHostPackage(): void {
  const hostDir = join(consumerDir, 'node_modules/shun-windows-effect-host');
  const adapterUrl = pathToFileURL(
    join(repoRoot, 'packages/domain-host/src/windows/effect-host.ts'),
  ).href;
  const hostMarker = join(hostDir, 'index.mjs');
  if (existsSync(hostMarker) && readFileSync(hostMarker, 'utf8').includes(adapterUrl)) return;
  mkdirSync(hostDir, { recursive: true });
  writeFileSync(
    join(hostDir, 'package.json'),
    JSON.stringify(
      {
        name: 'shun-windows-effect-host',
        version: '0.3.0',
        private: true,
        type: 'module',
        main: './index.mjs',
      },
      null,
      2,
    ),
  );
  // IMPORTANT: this staged binding is SHARED with T11 and must stay
  // byte-identical to t11-runtime/vitest.config.ts stageWindowsHostPackage()
  // (the marker check skips re-staging on content match, so whichever of the
  // two suites stages first decides the bytes; divergent content would break
  // the other suite's real-K journey).
  writeFileSync(
    hostMarker,
    `// T11 staged trusted Host binding (test instrument, consumer node_modules).
// Binds the REAL Shun T01 Windows effect Host adapter; every authority port
// below is a trusted-host fake with ZERO physical OS effects.
import { createWindowsEffectHost } from '${adapterUrl}';

const physicalEffects = [];
const gateDispatches = [];
const adapterOrder = [];
const authorizations = new Map();

const host = createWindowsEffectHost({
  binding: { capabilityId: 'windows', operationId: 'windows.execute' },
  authorization: {
    async resolve(input) {
      adapterOrder.push('resolve');
      const record = authorizations.get(input.actionRef);
      if (record === undefined) return null;
      return {
        effectId: input.effectId,
        plan: { taskId: record.taskId, planHash: input.planRef },
        action: {
          taskId: record.taskId,
          actionId: input.actionRef,
          planHash: input.planRef,
          authorizationRef: input.grantRef,
        },
        grant: record.grant,
      };
    },
  },
  actionController: {
    async authorizeEffect(input) {
      adapterOrder.push('action-controller');
      const grant = input.grant ?? {};
      if (grant.expired === true) return { ok: false, code: 'GRANT_EXPIRED' };
      return { ok: true };
    },
  },
  osAuthority: {
    async recheck() {
      adapterOrder.push('os-authority');
      return { ok: true };
    },
  },
  windows: {
    async execute(input) {
      adapterOrder.push('windows-execute');
      physicalEffects.push({ effectId: input.effectId, actionId: input.action?.actionId ?? null });
      return {
        actionId: input.action?.actionId ?? null,
        terminal: 'SUCCEEDED',
        sideEffectEvidence: { recoveryClassification: 'COMPLETED_VERIFIED', postStateVerified: true },
      };
    },
  },
});

export async function windowsExecute(payload, dispatchContext) {
  gateDispatches.push({ payload, dispatchContext });
  return host.dispatch(payload, dispatchContext);
}

export function stageT11Authorization(actionRef, record) {
  authorizations.set(actionRef, record);
}

export function t11WindowsHostEvidence() {
  return structuredClone({
    physicalEffects,
    gateDispatches,
    adapterOrder,
  });
}

export function resetT11WindowsHost() {
  physicalEffects.length = 0;
  gateDispatches.length = 0;
  adapterOrder.length = 0;
  authorizations.clear();
}
`,
  );
}

ensureSdkConsumer();
stageWindowsHostPackage();

const sdk = (name: string, sub: string) =>
  resolve(consumerDir, 'node_modules/@kaicreator', name, sub);

export default {
  root,
  resolve: {
    alias: {
      // Order matters: the host-seam subpath must win over the bare package.
      '@kaicreator/domain-harness-microkernel/host-seam': sdk(
        'domain-harness-microkernel',
        'dist/host-seam.js',
      ),
      '@kaicreator/domain-harness-microkernel': sdk('domain-harness-microkernel', 'dist/index.js'),
      '@kaicreator/domain-harness-build': sdk('domain-harness-build', 'dist/index.js'),
      '@kaicreator/domain-harness-host-node': sdk('domain-harness-host-node', 'dist/index.js'),
      '@kaicreator/domain-harness-contracts': sdk('domain-harness-contracts', 'dist/index.js'),
      'shun-windows-effect-host': resolve(
        consumerDir,
        'node_modules/shun-windows-effect-host/index.mjs',
      ),
      '@shun/vertical-support': resolve(root, '../../../../packages/vertical-support/src/index.ts'),
      vitest: resolve(repoRoot, 'packages/vertical-support/node_modules/vitest'),
    },
  },
  test: {
    include: ['*.test.ts'],
    environment: 'node',
    // The composition sweep runs the ELEVEN nested task suites as real
    // subprocesses; each nested suite gets its own 300s wall clock and the
    // whole qualification must stay under the 900s CI gate.
    testTimeout: 300_000,
    hookTimeout: 300_000,
    // The sweep spawns heavyweight subprocesses; nested suites are
    // load-sensitive, so the qualification runs strictly single-threaded.
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    fileParallelism: false,
  },
};
