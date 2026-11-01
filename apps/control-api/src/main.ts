// CLI entry: run the local control surface on loopback.
//   node src/main.ts            → http://127.0.0.1:7788
// Env:
//   SHUN_CONTROL_PORT           — port (default 7788)
//   SHUN_CONTROL_UI_DIR         — static UI directory (default ../control-ui/public)
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HostGuidedService } from '../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostMetaShadowStore } from '../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';
import { cloudInterpreterFromEnvironment } from './cloud-interpret.ts';
import { DemoShunBackend } from './demo/backend.ts';
import { RealStorageControlBackend } from './real-storage/backend.ts';
import { createControlServer } from './server.ts';
import { provisionGuidedCaseFromHostFile } from './v03/composition-guided.ts';
import type { JourneyBindingsConfig } from './v03/composition-journeys.ts';
import { createProductionV03Gateway } from './v03/composition-production.ts';

const here = dirname(fileURLToPath(import.meta.url));
const port = Number.parseInt(process.env.SHUN_CONTROL_PORT ?? '7788', 10);
const uiDir = process.env.SHUN_CONTROL_UI_DIR ?? resolve(here, '../../control-ui/public');

// A production mode is an explicit operator decision, never HTTP input.
const mode = process.env.SHUN_CONTROL_MODE ?? 'demo';
if (mode !== 'demo' && mode !== 'real-storage') {
  throw new Error('Unknown SHUN_CONTROL_MODE: refusing to start');
}
const backend =
  mode === 'real-storage'
    ? await RealStorageControlBackend.create({
        workspace: requiredEnv('SHUN_REAL_STORAGE_ROOT'),
        protectedAssets: JSON.parse(requiredEnv('SHUN_REAL_STORAGE_PROTECTED')) as string[],
        databaseFile: requiredEnv('SHUN_REAL_STORAGE_DATABASE'),
        registryRevisionFile: requiredEnv('SHUN_REGISTRY_CURRENTNESS_FILE'),
        registryPublicKeyFile: requiredEnv('SHUN_REGISTRY_PUBLIC_KEY_FILE'),
        registryPublicKeySha256: requiredEnv('SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256'),
        evidenceDir: requiredEnv('SHUN_REAL_STORAGE_EVIDENCE_DIR'),
        issuanceSecret: requiredEnv('SHUN_CONTROLLER_ISSUANCE_SECRET'),
        integritySecret: requiredEnv('SHUN_GRANT_INTEGRITY_SECRET'),
      })
    : new DemoShunBackend();

// The fixed Recipe candidate may be persisted only by the actual
// operator-configured SQLite host. Demo mode never claims durable storage.
const saveBuiltinInventoryCandidate =
  backend instanceof RealStorageControlBackend
    ? () => backend.saveBuiltinInventoryCandidate()
    : undefined;
// Remote mode is a separate opt-in trusted-host feature. Demo Goal tasks
// remain visibly simulated; a cloud interpretation is labeled as an untrusted
// remote proposal and can never be used as an ActionController execution grant.
const readBuiltinInventoryCandidate =
  backend instanceof RealStorageControlBackend
    ? () => backend.readBuiltinInventoryCandidate()
    : undefined;
const executeBuiltinInventoryRecipe =
  backend instanceof RealStorageControlBackend
    ? () => backend.executeBuiltinInventoryRecipe()
    : undefined;
// Guided state is a real, operator-owned local SQLite store. A selected
// StepSpec may be staged ONLY by trusted Host composition, not by the browser;
// absence of that binding exposes UNKNOWN, not a fabricated seeded journey.
const guidedDb = process.env.SHUN_V03_GUIDED_DATABASE;
if (guidedDb && mode !== 'real-storage') {
  throw new Error('V03_GUIDED_REQUIRES_REAL_STORAGE_MODE');
}
const guided =
  guidedDb && mode === 'real-storage' ? new HostGuidedService(resolve(guidedDb)) : undefined;

// Restore or stage only operator-pinned Host observations. A browser cannot
// supply an authority-bearing semantic selection or a selected root.
if (guided && process.env.SHUN_V03_GUIDED_CASE_FILE) {
  provisionGuidedCaseFromHostFile({
    service: guided,
    file: process.env.SHUN_V03_GUIDED_CASE_FILE,
    sha256: requiredEnv('SHUN_V03_GUIDED_CASE_SHA256'),
  });
}

// R03-INT journey bindings (all optional; a manifest declaring the matching
// routes makes them mandatory — the composition refuses to boot otherwise).
// Every value is trusted operator-local configuration, never HTTP input.
const windowsJourney =
  process.env.SHUN_V03_WINDOWS_EFFECT_AUTHORITY_DIR && process.env.SHUN_V03_WINDOWS_EFFECT_WORKSPACE
    ? {
        authorityDir: requiredEnv('SHUN_V03_WINDOWS_EFFECT_AUTHORITY_DIR'),
        workspaceRoot: requiredEnv('SHUN_V03_WINDOWS_EFFECT_WORKSPACE'),
      }
    : undefined;
const providerJourney = process.env.SHUN_V03_PROVIDER_CONFIG
  ? loadProviderJourneyConfig(requiredEnv('SHUN_V03_PROVIDER_CONFIG'))
  : undefined;
const metaStore = process.env.SHUN_V03_META_DATABASE
  ? new HostMetaShadowStore(resolve(requiredEnv('SHUN_V03_META_DATABASE')))
  : undefined;
if (metaStore && process.env.SHUN_V03_META_CASE_FILE) {
  provisionMetaFromHostFile({
    store: metaStore,
    file: process.env.SHUN_V03_META_CASE_FILE,
    sha256: requiredEnv('SHUN_V03_META_CASE_SHA256'),
  });
}
const journeys: JourneyBindingsConfig | undefined =
  windowsJourney || providerJourney || metaStore
    ? {
        windows: windowsJourney,
        provider: providerJourney,
        meta: metaStore ? { store: metaStore } : undefined,
      }
    : undefined;

// Production v0.3 is an explicit, operator-pinned mode. Missing genuine
// SDK/BUILD/Host state fails before an HTTP listener is opened; no demo
// fallback is ever mislabeled as a real v0.3 DomainApp.
const productionBuild = process.env.SHUN_V03_BUILD_FILE;
if (productionBuild && (!guided || mode !== 'real-storage')) {
  throw new Error('V03_PRODUCTION_REQUIRES_GUIDED_TRUSTED_REAL_STORAGE');
}
// The T04 trusted cloud host binding is installed by the production
// composition through the consumer's domain-harness-openai-host package.
// Without a configured real interpreter the port stays disabled and every
// LLM effect fails closed (CLOUD_UNAVAILABLE), never silently succeeds.
const cloud = cloudInterpreterFromEnvironment();
const disabledCloudInterpreter = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};
const production =
  productionBuild && guided
    ? await createProductionV03Gateway({
        buildFile: productionBuild,
        buildFileSha256: requiredEnv('SHUN_V03_BUILD_SHA256'),
        sdkConsumerDir: requiredEnv('SHUN_V03_SDK_CONSUMER_DIR'),
        kDocDatabaseFile: requiredEnv('SHUN_V03_KERNEL_DOC_DATABASE'),
        deploymentRoot: requiredEnv('SHUN_V03_DEPLOYMENT_ROOT'),
        tenantId: requiredEnv('SHUN_V03_TENANT_ID'),
        deployedAppId: requiredEnv('SHUN_V03_DEPLOYED_APP_ID'),
        selectedCase: guided,
        llm: {
          interpreter: cloud ?? disabledCloudInterpreter,
          journalFile: requiredEnv('SHUN_V03_CLOUD_JOURNAL'),
          configuredMaxOutputTokens: Number.parseInt(
            process.env.SHUN_V03_LLM_MAX_OUTPUT_TOKENS ?? '256',
            10,
          ),
        },
        // The durable Host submit-reference ledger is mandatory: without a
        // Host-issued record every gateway submit reference would be an
        // unauthenticated browser-controlled string. Boot fails closed.
        approvalLedgerFile: requiredEnv('SHUN_V03_APPROVAL_LEDGER'),
        journeys,
      })
    : undefined;
// Issuance is trusted-process-only (never an HTTP route). The operator reads
// the issued pair from this local console to submit; without a live staged
// Case no references exist and every gateway submit refuses pre-Kernel.
if (production) {
  const issued = production.issueSubmitReferences();
  if (issued.status === 'ISSUED') {
    console.log(
      `v0.3 submit references issued (case ${issued.caseId}, step ${issued.stepId}, ` +
        `valid until ${new Date(issued.validUntilUnixMs).toISOString()}): ` +
        `currentnessRef=${issued.currentnessRef} approvalRef=${issued.approvalRef}`,
    );
  } else {
    console.log(
      `v0.3 submit references NOT issued (${issued.code}); ` +
        '/api/v03/gateway/submit will refuse every send until a Guided Case is staged.',
    );
  }
}
const handle = createControlServer({
  backend,
  uiDir,
  port,
  saveBuiltinInventoryCandidate,
  readBuiltinInventoryCandidate,
  executeBuiltinInventoryRecipe,
  cloud,
  v03Guided: guided,
  v03Gateway: production?.gateway,
  v03Journeys: production?.journeys,
});
const bound = await handle.start();
console.log(
  `Shun control surface (${mode === 'demo' ? 'T08 DEMO ONLY' : 'REAL bounded C-003'}) on http://127.0.0.1:${bound}`,
);
console.log('Local only: the surface refuses non-loopback binds and non-loopback Host headers.');
if (production) {
  console.log(`v0.3 public DomainHarness activated: subjectDigest=${production.subjectDigest}`);
} else {
  console.log('v0.3 production BUILD inactive; /api/v03/gateway/submit remains unavailable.');
}
// Release trusted durable K/Host handles only when the server terminates.
// This is cleanup, not an effect or a replacement authorization path.
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    if (closing) return;
    closing = true;
    void handle.close().finally(() => {
      try {
        production?.dispose();
      } finally {
        try {
          metaStore?.close();
        } finally {
          guided?.close();
        }
      }
    });
  });
}

function requiredEnv(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing trusted local configuration ${key}; refusing real mode`);
  return value;
}

/** Operator-pinned CuratedProvider journey config (trusted local file). */
function loadProviderJourneyConfig(file: string): JourneyBindingsConfig['provider'] {
  const raw = JSON.parse(readFileSync(resolve(file), 'utf8')) as Record<string, unknown>;
  if (
    typeof raw.cacheRoot !== 'string' ||
    !Array.isArray(raw.roots) ||
    !Array.isArray(raw.scopes) ||
    typeof raw.descriptor !== 'object' ||
    raw.descriptor === null ||
    typeof raw.taskId !== 'string' ||
    !Number.isSafeInteger(raw.revocationEpoch)
  ) {
    throw new Error('V03_PROVIDER_JOURNEY_CONFIG_INVALID');
  }
  return {
    cacheRoot: raw.cacheRoot,
    roots: raw.roots as { keyId: string; publicKeyPem: string }[],
    scopes: raw.scopes as unknown[],
    descriptor: raw.descriptor,
    taskId: raw.taskId,
    revocationEpoch: raw.revocationEpoch as number,
  };
}

/**
 * Operator-pinned meta provisioning: record the genuine outcome receipt and
 * the explicit opt-in consent for ONE Case at boot (trusted process only).
 */
function provisionMetaFromHostFile(input: {
  store: HostMetaShadowStore;
  file: string;
  sha256: string;
}): void {
  const bytes = readFileSync(resolve(input.file));
  if (createHash('sha256').update(bytes).digest('hex') !== input.sha256) {
    throw new Error('V03_META_CASE_DIGEST_REFUSED');
  }
  const raw = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
  const receipt = raw.receipt as Record<string, unknown> | undefined;
  const consent = raw.consent as Record<string, unknown> | undefined;
  if (
    !receipt ||
    !consent ||
    typeof receipt.caseRef !== 'string' ||
    typeof receipt.revision !== 'string' ||
    typeof receipt.sha256 !== 'string' ||
    typeof consent.consentRef !== 'string'
  ) {
    throw new Error('V03_META_CASE_INVALID');
  }
  input.store.recordOutcomeReceipt({
    caseRef: receipt.caseRef,
    revision: receipt.revision,
    sha256: receipt.sha256,
  });
  input.store.recordOptInConsent(consent as never);
}
