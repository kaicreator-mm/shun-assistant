/** R02-E trusted production composition. No SDK-private import or fake K. */
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { isAbsolute, join, resolve } from 'node:path';
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
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { SqliteKernelDocStore } from '../../../../packages/domain-host/src/state/kernel-doc-store.ts';

export interface ProductionV03Config {
  readonly buildFile: string;
  readonly buildFileSha256: string;
  readonly sdkConsumerDir: string;
  readonly kDocDatabaseFile: string;
  readonly deploymentRoot: string;
  readonly tenantId: string;
  readonly deployedAppId: string;
  readonly selectedCase: Pick<HostGuidedService, 'state'>;
}

function hash(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
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
    typeof config.selectedCase.state !== 'function'
  ) {
    throw new Error('V03_PRODUCTION_COMPOSITION_REFUSED');
  }
  // Public package export resolution from an isolated, installed SDK consumer.
  const consumerRoot = realpathSync(config.sdkConsumerDir);
  if (consumerRoot !== resolve(config.sdkConsumerDir))
    throw new Error('V03_CONSUMER_ALIAS_REFUSED');
  const requirePublic = createRequire(join(consumerRoot, 'package.json'));
  const buildPath = requirePublic.resolve('@kaicreator/domain-harness-build');
  const kernelPath = requirePublic.resolve('@kaicreator/domain-harness-microkernel/host-seam');
  const [buildSdk, kernelSdk] = await Promise.all([
    import(pathToFileURL(buildPath).href),
    import(pathToFileURL(kernelPath).href),
  ]);
  if (
    typeof buildSdk.buildV10App !== 'function' ||
    typeof kernelSdk.activateV10App !== 'function'
  ) {
    throw new Error('V03_PUBLIC_SDK_MISSING');
  }
  const store = new SqliteKernelDocStore(config.kDocDatabaseFile);
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
          send: (raw) => {
            const candidate = raw as {
              caseId: string;
              request: unknown;
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
              return Promise.resolve({ status: 'refused', code: 'HOST_CASE_NOT_CURRENT' });
            }
            const messageId = 'msg-' + hash(JSON.stringify(candidate)).slice(0, 32);
            return activated.facade.send({
              intentType: 'goal-interpret',
              instanceKey: candidate.caseId,
              messageId,
              input: {
                request: candidate.request,
                currentnessRef: candidate.currentnessRef,
                approvalRef: candidate.approvalRef,
              },
            });
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
