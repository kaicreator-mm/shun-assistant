/** R02-E trusted production composition. No SDK-private import or fake K. */
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { activatePublicShunDomainApp } from '../../../../packages/domain-app/src/activation/public-sdk.ts';
import {
  composeTrustedRuntimeBuild,
  type TrustedModuleSource,
} from '../../../../packages/domain-app/src/activation/trusted-build.ts';
import type { SendReceipt } from '../../../../packages/domain-app/src/api/gateway.ts';
import {
  type ControlApiGateway,
  createControlApiGateway,
} from '../../../../packages/domain-app/src/api/gateway.ts';
import { buildNeutralGoalRequest } from '../../../../packages/domain-computer/src/cloud/goal-request.ts';
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { SqliteKernelDocStore } from '../../../../packages/domain-host/src/state/kernel-doc-store.ts';
import {
  resolveGrantHmacKeyFile,
  writeCurrentAuthority,
  writeGrantRecord,
  writePlanRecord,
} from '../../../../packages/executor-windows/src/trusted-store.ts';
import {
  type HostSubmitReferenceIssueReceipt,
  SqliteHostSubmitReferenceLedger,
} from './composition-approval.ts';
import {
  classifyJourneyKernelResult,
  createJourneySubmits,
  installJourneyBindings,
  type JourneyBindingsConfig,
  type JourneySubmits,
  loadStagedBindingModule,
} from './composition-journeys.ts';
import type { SelectedRootEffectHostPort } from './folder-selection-host.ts';
import {
  createGuidedReviewApprovalPort,
  createSelectedRootEffectSubmit,
  type SelectedRootEffectSubmitReceipt,
} from './selected-root-effect-flow.ts';

/** The frozen T04 interpreter port the trusted binding consumes. */
export interface TrustedLlmInterpreterPort {
  status(): { enabled: boolean; provider: 'deepseek'; model: string; osConsentRequired: boolean };
  interpretGoal(input: unknown): Promise<unknown>;
}

export interface ProductionLlmConfig {
  /** Real trusted interpreter (the T11-realized cloud port); never HTTP data. */
  readonly interpreter: TrustedLlmInterpreterPort;
  /** Absolute path of the durable cloud request journal database file. */
  readonly journalFile: string;
  /** Single fixed output ceiling; must equal the authority-signed ceiling. */
  readonly configuredMaxOutputTokens: number;
}

export interface ProductionV03Config {
  readonly buildFile: string;
  readonly buildFileSha256: string;
  readonly sdkConsumerDir: string;
  readonly kDocDatabaseFile: string;
  readonly deploymentRoot: string;
  readonly tenantId: string;
  readonly deployedAppId: string;
  readonly selectedCase: Pick<HostGuidedService, 'state' | 'readTrustedContext'>;
  readonly llm: ProductionLlmConfig;
  /**
   * Durable SQLite file of the Host-issued submit-reference ledger. The
   * production composition refuses to boot without it: caller-supplied
   * approval/currentness references are never trusted without a matching
   * Host-issued record.
   */
  readonly approvalLedgerFile: string;
  /**
   * R03-INT: trusted Host bindings for the windows/provider/meta journey
   * intents. A manifest that declares those routes REQUIRES the matching
   * real binding configuration here — the boot fails closed otherwise.
   */
  readonly journeys?: JourneyBindingsConfig;
  /**
   * U05-B2 — the trusted selected-root Host for the one-slice effect flow.
   * Present only with the folder-selection composition; the flow is otherwise
   * unavailable and its route answers 503, never a fabricated success.
   */
  readonly folderSelection?: SelectedRootEffectHostPort;
  /**
   * U05-B2 — operator-pinned executor authority store + durable ShunStore
   * policy database + separated secrets for the REAL ActionController R2
   * stack. Absent = no selected-root effect admission; never a fallback.
   */
  readonly selectedRootEffect?: {
    readonly authorityDir: string;
    readonly policyDatabaseFile: string;
    readonly issuanceSecret: string;
    readonly integritySecret: string;
  };
  /** Trusted clock override (tests); admission decisions never use HTTP time. */
  readonly now?: () => number;
}

/**
 * Durable SQLite cloud request journal (physical owner of the T04 request
 * CAS). reserve/complete mirror the frozen DurableCloudRequestJournal port;
 * after a restart the same request id can only replay its committed result
 * or conflict — never re-send silently.
 */
export class SqliteCloudRequestJournal {
  readonly durability = 'DURABLE_SHUN_STORE' as const;
  readonly #db: DatabaseSync;

  constructor(file: string) {
    if (typeof file !== 'string' || !isAbsolute(file) || file.endsWith(':memory:')) {
      throw new TypeError('CLOUD_JOURNAL_DURABLE_FILE_REQUIRED');
    }
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS cloud_request_journal (
      request_id TEXT PRIMARY KEY,
      request_sha256 TEXT NOT NULL,
      result_json TEXT,
      created_at_unix_ms INTEGER NOT NULL
    )`);
  }

  async reserve(input: {
    readonly requestId: string;
    readonly requestSha256: string;
    readonly createdAtUnixMs: number;
  }): Promise<
    | { readonly status: 'RESERVED' }
    | { readonly status: 'IN_FLIGHT' | 'CONFLICT' }
    | { readonly status: 'REPLAY'; readonly result: unknown }
  > {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db
        .prepare('SELECT request_sha256, result_json FROM cloud_request_journal WHERE request_id=?')
        .get(input.requestId) as { request_sha256: string; result_json: string | null } | undefined;
      if (row === undefined) {
        this.#db
          .prepare(
            'INSERT INTO cloud_request_journal(request_id,request_sha256,result_json,created_at_unix_ms) VALUES(?,?,NULL,?)',
          )
          .run(input.requestId, input.requestSha256, input.createdAtUnixMs);
        this.#db.exec('COMMIT');
        return { status: 'RESERVED' };
      }
      this.#db.exec('COMMIT');
      if (row.request_sha256 !== input.requestSha256) return { status: 'CONFLICT' };
      if (row.result_json === null) return { status: 'IN_FLIGHT' };
      return { status: 'REPLAY', result: JSON.parse(row.result_json) as unknown };
    } catch {
      this.#rollback();
      return { status: 'CONFLICT' };
    }
  }

  async complete(input: {
    readonly requestId: string;
    readonly requestSha256: string;
    readonly result: unknown;
  }): Promise<boolean> {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db
        .prepare('SELECT request_sha256, result_json FROM cloud_request_journal WHERE request_id=?')
        .get(input.requestId) as { request_sha256: string; result_json: string | null } | undefined;
      if (
        row === undefined ||
        row.request_sha256 !== input.requestSha256 ||
        row.result_json !== null
      ) {
        this.#db.exec('COMMIT');
        return false;
      }
      const text = JSON.stringify(input.result);
      if (typeof text !== 'string') {
        this.#db.exec('COMMIT');
        return false;
      }
      this.#db
        .prepare(
          'UPDATE cloud_request_journal SET result_json=? WHERE request_id=? AND result_json IS NULL',
        )
        .run(text, input.requestId);
      this.#db.exec('COMMIT');
      return true;
    } catch {
      this.#rollback();
      return false;
    }
  }

  close(): void {
    this.#db.close();
  }

  #rollback(): void {
    try {
      this.#db.exec('ROLLBACK');
    } catch {
      /* retain unknown, no false receipt */
    }
  }
}

/**
 * Submit references live strictly inside the Guided step window (steps cap
 * at 5 minutes): references never outlive the Case selection, and an
 * expired pair is re-issued as a fresh pair by the trusted Host.
 */
const SUBMIT_REFERENCE_MAX_TTL_MS = 270_000;

function hash(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The Kernel envelope proves only that the effect executed terminally. The
 * trusted LLM result inside carries its own terminal status: only
 * `completed` may surface as success; a trusted `refused` downgrades to the
 * refused Kernel vocabulary; anything unresolved stays unknown. This is the
 * F04 truth separation applied at the production seam — HTTP never reports
 * success for a non-completed outcome.
 */
function truthfulKernelResult(raw: unknown): unknown {
  if (!isRecord(raw) || raw.status !== 'admitted' || !isRecord(raw.admitted)) return raw;
  const effects = raw.admitted.effects;
  if (!Array.isArray(effects) || effects.length === 0) return raw;
  const effect = effects[0];
  if (
    !isRecord(effect) ||
    effect.disposition !== 'executed' ||
    !isRecord(effect.output) ||
    effect.output.phase !== 'terminal' ||
    !isRecord(effect.output.outcome) ||
    effect.output.outcome.ok !== true ||
    !isRecord(effect.output.outcome.output)
  ) {
    return raw;
  }
  const llm = effect.output.outcome.output;
  if (llm.status === 'completed') return raw;
  if (llm.status === 'refused') return { status: 'refused' };
  return { status: 'unknown' };
}

function trustedManifest(config: ProductionV03Config) {
  const path = resolve(config.buildFile);
  if (
    !isAbsolute(config.buildFile) ||
    !/^[0-9a-f]{64}$/.test(config.buildFileSha256) ||
    !lstatSync(path).isFile() ||
    lstatSync(path).isSymbolicLink() ||
    realpathSync(path) !== path
  )
    throw new Error('V03_MANIFEST_UNTRUSTED');
  const bytes = readFileSync(path);
  if (bytes.length > 4_194_304 || hash(bytes) !== config.buildFileSha256) {
    throw new Error('V03_MANIFEST_DIGEST_REFUSED');
  }
  return JSON.parse(bytes.toString('utf8')) as {
    appId: string;
    audience: string;
    buildId: string;
    targetProfile: string;
    modules: TrustedModuleSource[];
    routes: { intentId: string; operationId: string; capabilityId: string; handlerId: string }[];
    hardBudget: { maxStepsPerTurn: number; maxWorkUnitsPerTurn: number };
  };
}

/** Resolve the consumer's trusted T04 binding package (identity-checked). */
function resolveOpenAiHostBinding(consumerRoot: string): string {
  const pkgDir = join(consumerRoot, 'node_modules', 'domain-harness-openai-host');
  const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')) as {
    name?: string;
    main?: string;
  };
  if (manifest.name !== 'domain-harness-openai-host' || manifest.main !== './index.mjs') {
    throw new Error('V03_OPENAI_HOST_BINDING_REFUSED');
  }
  const file = join(pkgDir, manifest.main);
  if (!existsSync(file) || realpathSync(file) !== file) {
    throw new Error('V03_OPENAI_HOST_BINDING_FILE_REFUSED');
  }
  return file;
}

export async function createProductionV03Gateway(config: ProductionV03Config): Promise<{
  gateway: ControlApiGateway;
  journeys?: JourneySubmits;
  /**
   * R03C (#288): Host-global Provider first-use operations. prepare() needs
   * no Guided Case and no reference pair; confirm() consumes the one-time
   * Host-issued requestRef and then submits the fixed Provider Business
   * Intent through the selected V10 facade (instanceKey provider-global,
   * payload exactly {requestRef}). Present only when the hash-pinned
   * manifest declares the provider route with its real binding.
   */
  providerGlobal?: {
    prepare(): Promise<
      | {
          readonly ok: true;
          readonly requestRef: string;
          readonly preview: unknown;
          readonly expiresAtUnixMs: number;
        }
      | { readonly ok: false; readonly code: string }
    >;
    confirm(raw: unknown): Promise<SendReceipt>;
  };
  subjectDigest: string;
  /**
   * U05-B2 — the trusted one-shot selected-root effect admission over the
   * REAL ActionController R2 stack and the selected K. Present only with the
   * explicit operator authority-store configuration; never HTTP-configurable.
   */
  selectedRootEffect?: (raw: unknown) => Promise<SelectedRootEffectSubmitReceipt>;
  /**
   * Trusted process-side issuance of the submit-reference pair for the one
   * live Guided Case step. Never exposed through HTTP: an API client can
   * submit WITH issued references but can never mint one.
   */
  issueSubmitReferences(): HostSubmitReferenceIssueReceipt;
  dispose(): void;
}> {
  if (
    !isAbsolute(config.approvalLedgerFile) ||
    (config.now !== undefined && typeof config.now !== 'function')
  ) {
    throw new Error('V03_PRODUCTION_COMPOSITION_REFUSED');
  }
  const now = config.now ?? Date.now;
  const prepared = composeTrustedRuntimeBuild(trustedManifest(config));
  // R03-INT: goal-interpret stays mandatory; the windows/provider/meta
  // journey intents may compose alongside it, each fail-closed on its real
  // trusted Host binding configuration. R03C (#288): the read-only Meta
  // shared-experience query intent joins the frozen allowlist.
  const JOURNEY_INTENTS = new Set([
    'submitWindowsAction',
    'submitUnpermittedWindowsProbe',
    'submitProviderFirstUse',
    'submitMetaFeedback',
    'querySharedExperiences',
  ]);
  const declaredRoutes =
    prepared.status === 'READY_FOR_PUBLIC_SDK_BUILD' ? prepared.options.routes : [];
  const unknownIntent = declaredRoutes.some(
    (route) => route.intentId !== 'goal-interpret' && !JOURNEY_INTENTS.has(route.intentId),
  );
  const needsWindows = declaredRoutes.some(
    (route) =>
      route.intentId === 'submitWindowsAction' ||
      route.intentId === 'submitUnpermittedWindowsProbe',
  );
  const needsProvider = declaredRoutes.some((route) => route.intentId === 'submitProviderFirstUse');
  const needsMeta = declaredRoutes.some((route) => route.intentId === 'submitMetaFeedback');
  const needsMetaShared = declaredRoutes.some(
    (route) => route.intentId === 'querySharedExperiences',
  );
  // R03C authority pinning: a journey route may only bind its frozen
  // capability family; a manifest trying to point the provider intent or the
  // meta-shared read at another capability refuses at boot.
  const routeCapabilityForged =
    declaredRoutes.some(
      (route) => route.intentId === 'submitProviderFirstUse' && route.capabilityId !== 'provider',
    ) ||
    declaredRoutes.some(
      (route) => route.intentId === 'submitMetaFeedback' && route.capabilityId !== 'meta',
    ) ||
    declaredRoutes.some(
      (route) =>
        route.intentId === 'querySharedExperiences' && route.capabilityId !== 'meta-memory',
    ) ||
    declaredRoutes.some(
      (route) =>
        (route.intentId === 'submitWindowsAction' ||
          route.intentId === 'submitUnpermittedWindowsProbe') &&
        route.capabilityId !== 'windows',
    );
  const journeyRoutesUnbacked =
    (needsWindows && !config.journeys?.windows) ||
    (needsProvider && !config.journeys?.provider) ||
    ((needsMeta || needsMetaShared) && !config.journeys?.meta);
  if (
    prepared.status !== 'READY_FOR_PUBLIC_SDK_BUILD' ||
    unknownIntent ||
    routeCapabilityForged ||
    journeyRoutesUnbacked ||
    !declaredRoutes.some((route) => route.intentId === 'goal-interpret') ||
    !isAbsolute(config.kDocDatabaseFile) ||
    !isAbsolute(config.deploymentRoot) ||
    !config.selectedCase ||
    typeof config.selectedCase.state !== 'function' ||
    !config.llm ||
    !config.llm.interpreter ||
    typeof config.llm.interpreter.status !== 'function' ||
    typeof config.llm.interpreter.interpretGoal !== 'function' ||
    !isAbsolute(config.llm.journalFile) ||
    !Number.isSafeInteger(config.llm.configuredMaxOutputTokens) ||
    config.llm.configuredMaxOutputTokens < 1 ||
    config.llm.configuredMaxOutputTokens > 8192
  ) {
    throw new Error('V03_PRODUCTION_COMPOSITION_REFUSED');
  }
  // R03-INT: install the REAL Host bindings before activation so every
  // declared journey route has its trusted authority chain in place.
  if (config.journeys) await installJourneyBindings(config.journeys, config.sdkConsumerDir);
  // Public package export resolution from an isolated, installed SDK consumer.
  const consumerRoot = realpathSync(config.sdkConsumerDir);
  if (consumerRoot !== resolve(config.sdkConsumerDir))
    throw new Error('V03_CONSUMER_ALIAS_REFUSED');
  // The public SDK exports maps expose only the ESM `import` condition, so
  // require-style resolution cannot be used. Resolve the installed package
  // manifest explicitly and follow exactly its pinned dist entry (fail-closed
  // on any identity, exports-shape or file mismatch).
  const resolveInstalledSdk = (id: string): string => {
    const [scope = '', pkgName = '', ...subpathParts] = id.split('/');
    if (scope === '' || pkgName === '') throw new Error('V03_CONSUMER_SDK_ID_INVALID');
    const pkgDir = join(consumerRoot, 'node_modules', scope, pkgName);
    const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')) as {
      name?: string;
      exports?: Record<string, { import?: string }>;
    };
    if (manifest.name !== `${scope}/${pkgName}`) {
      throw new Error('V03_CONSUMER_PACKAGE_IDENTITY_REFUSED');
    }
    const subpath = subpathParts.length > 0 ? `./${subpathParts.join('/')}` : '.';
    const entry = manifest.exports?.[subpath]?.import;
    if (typeof entry !== 'string' || !entry.startsWith('./dist/')) {
      throw new Error('V03_CONSUMER_EXPORTS_REFUSED');
    }
    const file = join(pkgDir, entry);
    if (!existsSync(file) || realpathSync(file) !== file) {
      throw new Error('V03_CONSUMER_SDK_FILE_REFUSED');
    }
    return file;
  };
  const buildPath = resolveInstalledSdk('@kaicreator/domain-harness-build');
  const kernelPath = resolveInstalledSdk('@kaicreator/domain-harness-microkernel/host-seam');
  const [buildSdk, kernelSdk, hostBinding] = await Promise.all([
    import(pathToFileURL(buildPath).href),
    import(pathToFileURL(kernelPath).href),
    // The trusted T04 host binding installs through the SAME consumer module
    // instance the sealed capability's single import resolves to.
    import(pathToFileURL(resolveOpenAiHostBinding(consumerRoot)).href) as Promise<{
      installTrustedCloudHostBinding: (config: unknown) => void;
    }>,
  ]);
  if (
    typeof buildSdk.buildV10App !== 'function' ||
    typeof kernelSdk.activateV10App !== 'function' ||
    typeof hostBinding.installTrustedCloudHostBinding !== 'function'
  ) {
    throw new Error('V03_PUBLIC_SDK_MISSING');
  }
  const journal = new SqliteCloudRequestJournal(config.llm.journalFile);
  try {
    hostBinding.installTrustedCloudHostBinding({
      interpreter: config.llm.interpreter,
      journal,
      configuredMaxOutputTokens: config.llm.configuredMaxOutputTokens,
      now: Date.now,
    });
  } catch (error) {
    journal.close();
    if (error instanceof Error && error.message === 'CLOUD_HOST_ALREADY_INSTALLED') {
      throw new Error('V03_CLOUD_HOST_ALREADY_INSTALLED');
    }
    throw new Error('V03_CLOUD_HOST_CONFIGURATION_REFUSED');
  }
  // The ledger shares the composition clock so issuance validity and every
  // per-submit verification observe the same trusted time.
  const references = new SqliteHostSubmitReferenceLedger(config.approvalLedgerFile, now);
  const store = new SqliteKernelDocStore(config.kDocDatabaseFile);
  let attemptCounter = 0;
  // Declared before the try so both the dispose path and the activation
  // failure path close the authority store deterministically.
  let selectedRootEffect: SelectedRootEffectAdmission | undefined;
  try {
    const activated = await activatePublicShunDomainApp({
      sdk: { buildV10App: buildSdk.buildV10App, activateV10App: kernelSdk.activateV10App },
      buildOptions: prepared.options,
      host: {
        store,
        tenantId: config.tenantId,
        now: Date.now,
        deploymentIdentity: {
          deployedAppId: config.deployedAppId,
          tenantId: config.tenantId,
          appId: prepared.options.appId,
        },
        deploymentRoot: config.deploymentRoot,
        queryAuthority: {
          principal: Object.freeze({ role: 'local-host', tenant: config.tenantId }),
          authorize: (
            _principal: unknown,
            target: {
              deployedAppId: string;
              tenantId: string;
              appId: string;
              instanceKey: string;
              businessPackageId: string;
            },
          ) => {
            const current = config.selectedCase.state().currentStep;
            return (
              !!current &&
              current.taskId === target.instanceKey &&
              target.deployedAppId === config.deployedAppId &&
              target.tenantId === config.tenantId &&
              target.appId === prepared.options.appId &&
              prepared.options.modules.some(
                (m) => m.role === 'business' && m.packageId === target.businessPackageId,
              )
            );
          },
        },
      },
    });
    // U05-B2: the REAL ActionController R2 stack over the operator's durable
    // ShunStore + executor authority store, built after activation so the K
    // facade is the only send path. Configured only as an explicit operator
    // decision; absent = the selected-root effect route answers 503.
    selectedRootEffect = await buildSelectedRootEffectAdmission(
      config,
      now,
      references,
      (payload) => activated.facade.send(payload),
    );
    return {
      subjectDigest: activated.subjectDigest,
      journeys: createJourneySubmits({
        facade: activated.facade,
        selectedCase: config.selectedCase,
        references,
        now,
      }),
      selectedRootEffect: selectedRootEffect?.submit,
      providerGlobal: needsProvider
        ? await (async () => {
            // The SAME staged consumer module instance the sealed capability
            // imports: the module-global installed binding is coherent for
            // the composition-side Host surfaces and the K→C callback.
            const providerHost = await loadStagedBindingModule(consumerRoot, 'shun-provider-host');
            const statusOf = (): { installed: boolean } => {
              const status = providerHost.trustedProviderBindingStatus as
                | (() => { installed: boolean })
                | undefined;
              return typeof status === 'function' ? status() : { installed: false };
            };
            let providerAttempt = 0;
            const providerRefused = (code: string, detail: string): SendReceipt => ({
              status: 'REFUSED',
              code: code as never,
              detail,
              sendCalls: 0,
              journalEntries: 0,
              refusedAtUnixMs: now(),
            });
            return {
              async prepare() {
                if (!config.journeys?.provider || !statusOf().installed) {
                  return { ok: false as const, code: 'PROVIDER_HOST_NOT_INSTALLED' };
                }
                const prepareFn = providerHost.prepareProviderFirstUse as
                  | (() => Promise<
                      | { ok: true; requestRef: string; preview: unknown; expiresAtUnixMs: number }
                      | { ok: false; code: string }
                    >)
                  | undefined;
                if (typeof prepareFn !== 'function') {
                  return { ok: false as const, code: 'V03_PROVIDER_SEAM_REFUSED' };
                }
                return prepareFn();
              },
              async confirm(raw: unknown): Promise<SendReceipt> {
                if (!config.journeys?.provider || !statusOf().installed) {
                  return providerRefused(
                    'PROVIDER_HOST_NOT_INSTALLED',
                    'trusted provider binding is not installed',
                  );
                }
                // The confirm body is EXACTLY {requestRef}: no intentType,
                // instanceKey, taskId, path, args or privilege is accepted
                // from any caller; every value the K send uses is fixed here.
                if (
                  !isRecord(raw) ||
                  Object.keys(raw).sort().join('|') !== 'requestRef' ||
                  typeof raw.requestRef !== 'string' ||
                  !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(raw.requestRef)
                ) {
                  return providerRefused(
                    'GATEWAY_INPUT_INVALID',
                    'confirm body must be exactly one bounded requestRef',
                  );
                }
                const confirmFn = providerHost.confirmProviderFirstUse as
                  | ((requestRef: string) => { ok: true } | { ok: false; code: string })
                  | undefined;
                if (typeof confirmFn !== 'function') {
                  return providerRefused('V03_PROVIDER_SEAM_REFUSED', 'confirm seam unavailable');
                }
                // PREPARED → APPROVED exactly once in the durable Host ledger;
                // a wrong/expired/replayed requestRef refuses with zero K
                // sends and zero provider activation.
                const confirmed = confirmFn(raw.requestRef);
                if (!confirmed.ok) {
                  return providerRefused(confirmed.code, 'Host requestRef refused');
                }
                const kernelReceipt = await activated.facade.send({
                  intentType: 'submitProviderFirstUse',
                  instanceKey: 'provider-global',
                  messageId: `msg-pg-${++providerAttempt}`,
                  input: { requestRef: raw.requestRef },
                });
                return classifyJourneyKernelResult(kernelReceipt);
              },
            };
          })()
        : undefined,
      issueSubmitReferences(): HostSubmitReferenceIssueReceipt {
        // Issuance reads only the trusted Host-staged live step; references
        // never outlive the Case selection (validity capped at both the step
        // window and a bounded reference TTL).
        const liveStep = config.selectedCase.state().currentStep;
        if (!liveStep) return { status: 'REFUSED', code: 'HOST_CASE_NOT_CURRENT' };
        const issuedAt = now();
        const validUntil = Math.min(
          liveStep.validUntilUnixMs,
          issuedAt + SUBMIT_REFERENCE_MAX_TTL_MS,
        );
        if (validUntil <= issuedAt) {
          return { status: 'REFUSED', code: 'HOST_CASE_NOT_CURRENT' };
        }
        return references.issue({
          caseId: liveStep.taskId,
          stepId: liveStep.stepId,
          validUntilUnixMs: validUntil,
        });
      },
      gateway: createControlApiGateway({
        domainApp: {
          send: async (raw) => {
            const candidate = raw as {
              caseId: string;
              request: { goal?: unknown };
              currentnessRef: string;
              approvalRef: string;
            };
            // Production Case scope must be issued by the trusted Host, not
            // inferred from a correctly formatted browser-controlled string.
            // Absent/stale/foreign selections cannot even reach Kernel send.
            const liveStep = config.selectedCase.state().currentStep;
            if (
              !liveStep ||
              liveStep.taskId !== candidate.caseId ||
              liveStep.validUntilUnixMs <= now()
            ) {
              return { status: 'refused', code: 'HOST_CASE_NOT_CURRENT' };
            }
            // The submitted reference pair must authenticate against the
            // durable Host-issued record for THIS live Case step. Valid-shaped
            // but forged, pair-spliced, cross-Case, superseded-step, revoked
            // or expired references refuse here — before the LLM request is
            // minted and before the Kernel facade is entered: zero K sends,
            // zero T04 calls, zero egress for unauthenticated submissions.
            const verified = references.verify({
              caseId: candidate.caseId,
              stepId: liveStep.stepId,
              currentnessRef: candidate.currentnessRef,
              approvalRef: candidate.approvalRef,
            });
            if (verified.status !== 'VALID') {
              return { status: 'refused', code: verified.code };
            }
            // The exact dh.llm.generate/1 request is minted HERE by the
            // trusted Host from the gateway-validated GoalRequest — the
            // caller never supplies LLM request bytes.
            const requestId = `v03${hash(JSON.stringify(candidate)).slice(0, 40)}`;
            const llmRequest = buildNeutralGoalRequest({
              requestId,
              goalText: typeof candidate.request?.goal === 'string' ? candidate.request.goal : '',
              deadlineUnixMs: now() + 600_000,
              maxOutputTokens: config.llm.configuredMaxOutputTokens,
            });
            if (!llmRequest) return { status: 'refused', code: 'HOST_LLM_REQUEST_REFUSED' };
            // A message id names ONE submission attempt; the logical request
            // idempotency key stays content-derived so a re-submit replays
            // the journaled T04 result instead of re-entering the same turn.
            const messageId = `msg-${hash(JSON.stringify(candidate)).slice(0, 24)}-${++attemptCounter}`;
            const kernelReceipt = await activated.facade.send({
              intentType: 'goal-interpret',
              instanceKey: candidate.caseId,
              messageId,
              input: {
                llmRequest,
                idempotencyToken: requestId,
                currentnessRef: candidate.currentnessRef,
                approvalRef: candidate.approvalRef,
              },
            });
            return truthfulKernelResult(kernelReceipt);
          },
        },
      }),
      dispose() {
        activated.dispose();
        store.close();
        references.close();
        selectedRootEffect?.close();
      },
    };
  } catch {
    store.close();
    references.close();
    selectedRootEffect?.close();
    throw new Error('V03_PRODUCTION_ACTIVATION_REFUSED');
  }
}

/** U05-B2 policy identity of the selected-root R2 authority stack. */
const SELECTED_ROOT_EFFECT_POLICY = 'shun.selected-root-effect.policy-v1';
const SELECTED_ROOT_EFFECT_AUTHORITY_ID = 'shun.local.selected-root-effect';

interface SelectedRootEffectAdmission {
  readonly submit: (raw: unknown) => Promise<SelectedRootEffectSubmitReceipt>;
  close(): void;
}

/**
 * Assemble the REAL independent R2 stack for the selected-root effect flow:
 * the existing ShunStore-backed AuthorizationAuthority + ActionController
 * (bootstrap idempotently mirrors RealStorageControlBackend), the existing
 * executor-windows trusted-store writers for the FilePlanSource /
 * FileGrantSource / FileCurrentnessSource records the Windows effect Host
 * binding reads at effect time, and the durable Guided approval adapter.
 * The HMAC coherence check fails closed BEFORE any admission: the executor
 * store's grant key must be the exact secret this stack signs with, so a
 * mismatched/foreign authority store can never validate the issued grant.
 */
async function buildSelectedRootEffectAdmission(
  config: ProductionV03Config,
  now: () => number,
  references: SqliteHostSubmitReferenceLedger,
  facadeSend: (payload: unknown) => Promise<unknown>,
): Promise<SelectedRootEffectAdmission | undefined> {
  const effect = config.selectedRootEffect;
  if (effect === undefined) return undefined;
  if (
    !config.folderSelection ||
    !isAbsolute(effect.authorityDir) ||
    !isAbsolute(effect.policyDatabaseFile) ||
    !effect.issuanceSecret ||
    !effect.integritySecret ||
    effect.issuanceSecret === effect.integritySecret
  ) {
    throw new Error('V03_SELECTED_ROOT_EFFECT_CONFIG_REFUSED');
  }
  const clock = (): string => new Date(now()).toISOString();
  const store = new ShunStore({ file: effect.policyDatabaseFile });
  const adapter = new ShunStoreAuthorizationAdapter(store);
  const authority = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: effect.integritySecret,
    issuanceSecret: effect.issuanceSecret,
    clock,
    // The frozen K→C effect payload grammar (t11/effect-host SAFE_ID) and
    // the executor FileGrantSource lookup both require a letter-first
    // bounded grant identity; the authority's default randomUUID() can
    // start with a digit and would be structurally refused at the effect
    // boundary. Mint grammar-coherent grant ids here.
    newGrantId: () => `grant-${randomUUID()}`,
  });
  try {
    const oldAuthority = await adapter.loadAuthorityRecord();
    const oldPolicy = await adapter.loadCurrentPolicy();
    if (oldAuthority === null && oldPolicy === null && !(await adapter.hasAnyGrant())) {
      const inserted = await adapter.compareAndSaveAuthorityRecord(
        {
          authorityId: SELECTED_ROOT_EFFECT_AUTHORITY_ID,
          authorityRevision: 'r1',
          updatedAt: clock(),
          policyInitialized: true,
          priorAuthorityRevisions: [],
        },
        null,
      );
      if (!inserted) throw new Error('SELECTED_ROOT_EFFECT_AUTHORITY_INIT_RACE');
      const policyInserted = await adapter.compareAndSavePolicySnapshot(
        {
          policySnapshotRevision: SELECTED_ROOT_EFFECT_POLICY,
          status: 'ACTIVE',
          authorityId: SELECTED_ROOT_EFFECT_AUTHORITY_ID,
          authorityRevision: 'r1',
          revokedGrantIds: [],
          priorRevisions: [],
          rules: [],
          riskGuards: [],
          updatedAt: clock(),
        },
        null,
      );
      if (!policyInserted) throw new Error('SELECTED_ROOT_EFFECT_POLICY_INIT_RACE');
    } else if (oldAuthority === null || oldPolicy === null) {
      throw new Error('SELECTED_ROOT_EFFECT_PARTIAL_AUTHORITY_REFUSED');
    }
    const current = await authority.currentAuthority();
    if (current.kind !== 'CURRENT' || current.policyStatus !== 'ACTIVE') {
      throw new Error('SELECTED_ROOT_EFFECT_CURRENT_AUTHORITY_UNRESOLVABLE');
    }
  } catch (error) {
    store.close();
    throw error instanceof Error ? error : new Error('SELECTED_ROOT_EFFECT_AUTHORITY_REFUSED');
  }
  const plansDir = join(effect.authorityDir, 'plans');
  const grantsDir = join(effect.authorityDir, 'grants');
  const hmacKeyFile = resolveGrantHmacKeyFile(effect.authorityDir);
  // The authority signs with the RAW integrity secret as the HMAC key; the
  // executor store's verifier decodes the key file as BASE64 key material —
  // so the provisioned file must be exactly base64(integritySecret). A
  // foreign/rewritten/mismatched key file refuses every admission BEFORE any
  // R2 route runs (the effect boundary would otherwise reject the grant).
  const expectedKeyFileContent = Buffer.from(effect.integritySecret, 'utf8').toString('base64');
  let hmacKeyCoherent = false;
  try {
    hmacKeyCoherent = readFileSync(hmacKeyFile, 'utf8').trim() === expectedKeyFileContent;
  } catch {
    hmacKeyCoherent = false;
  }
  const admission = createSelectedRootEffectSubmit({
    host: config.folderSelection,
    references,
    facade: { send: facadeSend },
    classifyJourneyKernelResult,
    now,
    authority: {
      async authorizePlan({ plan, expect }) {
        // The R2 approval adapter over the durable Guided ledger is bound
        // per-admission to the exact Host-verified step facts; the
        // ActionController itself remains the only R2 authority.
        const controller = new ActionController({
          authority,
          policyState: adapter,
          approvals: createGuidedReviewApprovalPort({
            guided: config.selectedCase,
            expect,
          }),
          issuanceSecret: effect.issuanceSecret,
          clock,
        });
        const authorized = await controller.authorizePlan({ plan });
        if (!authorized.ok) return authorized;
        return {
          ok: true,
          plan: authorized.authorization.plan,
          grants: authorized.authorization.grants,
        };
      },
      async readCurrentAuthority() {
        const state = await authority.currentAuthority();
        if (state.kind !== 'CURRENT') {
          throw new Error('SELECTED_ROOT_EFFECT_CURRENT_AUTHORITY_UNRESOLVABLE');
        }
        return state;
      },
      // Plans are formed under the bootstrapped ACTIVE policy revision; if
      // the durable policy ever moves, the real controller refuses the
      // admission (stale-policy re-plan) — never a silent downgrade.
      policySnapshotRevision: () => SELECTED_ROOT_EFFECT_POLICY,
      writePlanRecord: (plan) => writePlanRecord(plansDir, plan),
      writeGrantRecord: (grant) => writeGrantRecord(grantsDir, grant),
      writeCurrentAuthority: (state) => writeCurrentAuthority(effect.authorityDir, state),
      hasPlanRecord: (planHash) =>
        existsSync(join(plansDir, `${planHash}.json`)) &&
        !lstatSync(join(plansDir, `${planHash}.json`)).isSymbolicLink(),
      hmacKeyCoherent: () => hmacKeyCoherent,
    },
  });
  return {
    submit: admission,
    close: () => store.close(),
  };
}
