/** R02-E trusted production composition. No SDK-private import or fake K. */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { activatePublicShunDomainApp } from '../../../../packages/domain-app/src/activation/public-sdk.ts';
import {
  composeTrustedRuntimeBuild,
  type TrustedModuleSource,
} from '../../../../packages/domain-app/src/activation/trusted-build.ts';
import {
  type ControlApiGateway,
  createControlApiGateway,
} from '../../../../packages/domain-app/src/api/gateway.ts';
import { buildNeutralGoalRequest } from '../../../../packages/domain-computer/src/cloud/goal-request.ts';
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { SqliteKernelDocStore } from '../../../../packages/domain-host/src/state/kernel-doc-store.ts';

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
  readonly selectedCase: Pick<HostGuidedService, 'state'>;
  readonly llm: ProductionLlmConfig;
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
  subjectDigest: string;
  dispose(): void;
}> {
  const prepared = composeTrustedRuntimeBuild(trustedManifest(config));
  if (
    prepared.status !== 'READY_FOR_PUBLIC_SDK_BUILD' ||
    prepared.options.routes.length !== 1 ||
    prepared.options.routes[0]?.intentId !== 'goal-interpret' ||
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
  const store = new SqliteKernelDocStore(config.kDocDatabaseFile);
  let attemptCounter = 0;
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
    return {
      subjectDigest: activated.subjectDigest,
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
              liveStep.validUntilUnixMs <= Date.now()
            ) {
              return { status: 'refused', code: 'HOST_CASE_NOT_CURRENT' };
            }
            // The exact dh.llm.generate/1 request is minted HERE by the
            // trusted Host from the gateway-validated GoalRequest — the
            // caller never supplies LLM request bytes.
            const requestId = `v03${hash(JSON.stringify(candidate)).slice(0, 40)}`;
            const llmRequest = buildNeutralGoalRequest({
              requestId,
              goalText: typeof candidate.request?.goal === 'string' ? candidate.request.goal : '',
              deadlineUnixMs: Date.now() + 600_000,
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
      },
    };
  } catch {
    store.close();
    throw new Error('V03_PRODUCTION_ACTIVATION_REFUSED');
  }
}
