/**
 * R02-A: production BUILD admission boundary. Unlike T09's historical
 * declaration-only preview, this accepts REAL immutable Domain Package bytes
 * from a Host-provisioned, independently verified source manifest.
 *
 * No test fixture BUILD, local ABI placeholder, private SDK import or
 * additional Kernel is created here. buildV10App (the public SDK authority)
 * must still accept these exact bytes during production activation.
 */
import { createHash } from 'node:crypto';
import type { BuildV10AppOptions, V10ModuleInput } from '../build/composition.ts';

export interface TrustedModuleSource {
  readonly module: V10ModuleInput;
  /** Operator-verified digest bound to the installed immutable Domain Package. */
  readonly approvedSha256: string;
}

export type TrustedBuildResult =
  | { readonly status: 'REFUSED'; readonly code: 'TRUSTED_MODULE_INVALID' }
  | { readonly status: 'READY_FOR_PUBLIC_SDK_BUILD'; readonly options: BuildV10AppOptions };

const ROLES = ['kernel-primary', 'standard-primary', 'business', 'capability'] as const;
const SHA = /^[0-9a-f]{64}$/;

export function composeTrustedRuntimeBuild(input: {
  readonly appId: string;
  readonly audience: string;
  readonly buildId: string;
  readonly targetProfile: string;
  readonly modules: readonly TrustedModuleSource[];
  readonly routes: BuildV10AppOptions['routes'];
  readonly hardBudget: BuildV10AppOptions['hardBudget'];
}): TrustedBuildResult {
  try {
    if (!input || !Array.isArray(input.modules) || input.modules.length !== 4 ||
        !Array.isArray(input.routes) || input.routes.length < 1 ||
        input.targetProfile !== 'node24-esm/1' ||
        !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(input.appId) ||
        !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(input.audience) ||
        !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(input.buildId)) {
      return { status: 'REFUSED', code: 'TRUSTED_MODULE_INVALID' };
    }
    const roles = new Set<string>();
    const ids = new Set<string>();
    const modules: V10ModuleInput[] = [];
    for (const entry of input.modules) {
      const module = entry?.module;
      if (!module || typeof module.moduleSource !== 'string' ||
          module.moduleSource.length < 64 ||
          module.moduleSource.includes('BINDING_REQUIRED_AT_ACTIVATION') ||
          module.moduleSource.includes('SEMANTIC_BINDING_REQUIRED_AT_ACTIVATION') ||
          !SHA.test(entry.approvedSha256) ||
          !SHA.test(module.moduleSha256 ?? '') ||
          module.moduleSha256 !== entry.approvedSha256 ||
          createHash('sha256').update(module.moduleSource, 'utf8').digest('hex') !== entry.approvedSha256 ||
          !ROLES.includes(module.role as typeof ROLES[number]) ||
          roles.has(module.role) ||
          ids.has(module.packageId) ||
          !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/.test(module.packageId)) {
        return { status: 'REFUSED', code: 'TRUSTED_MODULE_INVALID' };
      }
      roles.add(module.role);
      ids.add(module.packageId);
      modules.push(Object.freeze({
        ...module,
        dependencies: Object.freeze([...(module.dependencies ?? [])]),
        provides: Object.freeze([...(module.provides ?? [])]),
        requires: Object.freeze([...(module.requires ?? [])]),
      }));
    }
    if (ROLES.some((role) => !roles.has(role))) {
      return { status: 'REFUSED', code: 'TRUSTED_MODULE_INVALID' };
    }
    if (!Number.isSafeInteger(input.hardBudget?.maxStepsPerTurn) ||
        !Number.isSafeInteger(input.hardBudget?.maxWorkUnitsPerTurn) ||
        input.hardBudget.maxStepsPerTurn < 1 ||
        input.hardBudget.maxWorkUnitsPerTurn < 1) {
      return { status: 'REFUSED', code: 'TRUSTED_MODULE_INVALID' };
    }
    return {
      status: 'READY_FOR_PUBLIC_SDK_BUILD',
      options: Object.freeze({
        appId: input.appId, audience: input.audience, buildId: input.buildId,
        targetProfile: input.targetProfile, modules: Object.freeze(modules),
        routes: Object.freeze(input.routes.map((route) => Object.freeze({ ...route }))),
        hardBudget: Object.freeze({ ...input.hardBudget }),
      }),
    };
  } catch {
    return { status: 'REFUSED', code: 'TRUSTED_MODULE_INVALID' };
  }
}
