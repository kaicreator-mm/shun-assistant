/**
 * T09 — v0.3 single-domain BUILD composition adapter.
 *
 * Maps the controlled Shun module whitelist (selected K/S/B/C) onto plain-data
 * BUILD inputs for the real public DomainHarness `buildV10App` SDK (consumed
 * by T11's trusted composition; this adapter itself never imports the SDK —
 * the sealed types below are structural mirrors of the frozen v0.10.2-rc.0
 * BUILD input contract). Everything is a pure function: deterministic bytes,
 * fixed role/ABI rows pinned from the real SDK d.ts, no clock, no I/O, and
 * the output is deep-frozen plain data that mints no approval or authority.
 *
 * The selected C module's sealed bytes import exactly `domain-harness-openai-host`
 * and its allowance declares the same specifier. The exported binding record
 * maps that single import to the EXISTING trusted Shun cloud interpreter port
 * (T04 `TrustedCloudInterpreterPort`, installed by T11 as the static
 * `domain-harness-openai-host.generate` entry). No second sender exists.
 */
import { createHash } from 'node:crypto';

/**
 * Structural mirror of the SDK `V10ModuleInput` / `BuildV10AppOptions` /
 * `V10BuiltApp` plain-data types (frozen v0.10.2-rc.0 contracts). Kept local
 * so @shun/domain-app stays zero-dependency and never imports the SDK.
 */
export interface V10ModuleInput {
  readonly packageId: string;
  readonly role: string;
  readonly abiVersion: string;
  readonly moduleSource?: string;
  readonly moduleSha256?: string;
  readonly endpoint: string;
  readonly dependencies?: readonly string[];
  readonly externalImports?: {
    readonly node?: readonly string[];
    readonly npm?: readonly string[];
    readonly native?: readonly string[];
  };
  readonly provides?: readonly string[];
  readonly requires?: readonly string[];
  readonly optional?: boolean;
  readonly capabilityId?: string;
  readonly handlers?: readonly { readonly operationId: string; readonly handler: string }[];
}

export interface V10RouteRowInput {
  readonly intentId: string;
  readonly operationId: string;
  readonly capabilityId: string;
  readonly handlerId: string;
}

export interface BuildV10AppOptions {
  readonly appId: string;
  readonly audience: string;
  readonly targetProfile: string;
  readonly modules: readonly V10ModuleInput[];
  readonly routes: readonly V10RouteRowInput[];
  readonly hardBudget: { readonly maxStepsPerTurn: number; readonly maxWorkUnitsPerTurn: number };
  readonly buildId: string;
}

/** Controlled whitelist of selectable Shun module declarations. */
export type SelectedModuleKind =
  | 'kernel'
  | 'semantic'
  | 'business'
  | 'capability-llm-openai-compatible';

export type SelectedModuleDeclaration = Readonly<{ kind: SelectedModuleKind }>;

/** The composition output: SDK-ready options plus the static import binding record. */
export interface ComposedDomainBuild {
  /** Feed directly to the real public `buildV10App`; plain frozen data. */
  readonly options: BuildV10AppOptions;
  /**
   * Static external-import → trusted Shun port mapping. The selected C's only
   * ordinary import binds to the existing T04 trusted cloud interpreter port
   * at T11 activation; no second sender may be created for it.
   */
  readonly externalImportBindings: Readonly<Record<string, string>>;
}

export type CompositionRefusalCode = 'BUILD_INPUT_INVALID';

export type CompositionResult =
  | Readonly<{ status: 'REFUSED'; code: CompositionRefusalCode; detail: string }>
  | ComposedDomainBuild;

// ---- Constants pinned from the real public SDK d.ts (the contracts package
// of the frozen 0.10.2-rc.0 tarballs: V10_TARGET_PROFILE / V10_SELECTED_ROLE_ABI).
export const V03_TARGET_PROFILE = 'node24-esm/1';
export const V03_KERNEL_PACKAGE_ID = 'shun.kernel.primary';
export const V03_SEMANTIC_PACKAGE_ID = 'shun.semantic.primary';
export const V03_BUSINESS_PACKAGE_ID = 'shun.business.goal';
export const V03_CAPABILITY_PACKAGE_ID = 'shun.capability.llm-openai-compatible';
/** The existing trusted Shun cloud interpreter port identity (T04, T11 installs). */
export const V03_TRUSTED_CLOUD_INTERPRETER_PORT = 'shun.trusted-cloud-interpreter.v03';
export const V03_CLOUD_IMPORT_SPECIFIER = 'domain-harness-openai-host';
export const V03_INTENT_ID = 'goal-interpret';
export const V03_OPERATION_ID = 'interpretGoal';

/** Static record: the C module's single external import binds to this port. */
export const V03_EXTERNAL_IMPORT_BINDINGS: Readonly<Record<string, string>> = Object.freeze({
  [V03_CLOUD_IMPORT_SPECIFIER]: V03_TRUSTED_CLOUD_INTERPRETER_PORT,
});

/** Selected per-role ABI rows of the pinned Node24 profile (SDK V10_SELECTED_ROLE_ABI). */
const ROLE_ABI: Readonly<Record<SelectedModuleKind, string>> = Object.freeze({
  kernel: 'v08-kernel-abi/1',
  semantic: 'v08-standard-sdk-abi/1',
  business: 'v08-business-abi/1',
  'capability-llm-openai-compatible': 'v08-capability-abi/1',
});

const SDK_ROLES: Readonly<Record<SelectedModuleKind, string>> = Object.freeze({
  kernel: 'kernel-primary',
  semantic: 'standard-primary',
  business: 'business',
  'capability-llm-openai-compatible': 'capability',
});

const PACKAGE_IDS: Readonly<Record<SelectedModuleKind, string>> = Object.freeze({
  kernel: V03_KERNEL_PACKAGE_ID,
  semantic: V03_SEMANTIC_PACKAGE_ID,
  business: V03_BUSINESS_PACKAGE_ID,
  'capability-llm-openai-compatible': V03_CAPABILITY_PACKAGE_ID,
});

/** Feature the S primary provides; the B package requires it (closed closure). */
const SEMANTIC_FEATURE_KEY = 'standard:goal-semantic/1';
const BUSINESS_INTENT_KEY = `intent:${V03_INTENT_ID}`;
const HARD_BUDGET = Object.freeze({ maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 });
const DEFAULT_BUILD_ID = 'shun-v0.3-t09';
const IDENTITY = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;

function refused(detail: string): CompositionResult {
  return { status: 'REFUSED', code: 'BUILD_INPUT_INVALID', detail };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

// ---- Sealed module bytes. Deterministic ESM boundary manifests: no clock,
// no randomness, no import edges except the C module's single pinned
// dependency-harness import (declared in its allowance). Runtime dispatch is
// bound at trusted activation (T11); these bytes carry no authority.
const KERNEL_SOURCE = `// Sealed v0.3 Shun K primary boundary (T09 BUILD composition).
// Effect Permit/Journal/Replay/UNKNOWN stay owned by the selected K gate.
// Dispatch binding happens only at trusted activation (T11); this sealed
// module carries no authority and no external import edges.
export const kernelManifest = Object.freeze({
  packageId: '${V03_KERNEL_PACKAGE_ID}',
  role: 'kernel-primary',
  targetProfile: '${V03_TARGET_PROFILE}',
});
export function dispatchKernelEffect() {
  throw new Error('K_EFFECT_BINDING_REQUIRED_AT_ACTIVATION');
}
`;

const SEMANTIC_SOURCE = `// Sealed v0.3 Shun S primary boundary (T09 BUILD composition).
// Semantic selection is provided by the existing trusted Shun semantic
// adapter at activation; the sealed module declares only its feature key.
export const semanticManifest = Object.freeze({
  packageId: '${V03_SEMANTIC_PACKAGE_ID}',
  role: 'standard-primary',
  providesFeature: '${SEMANTIC_FEATURE_KEY}',
});
export function selectGoalSemantic() {
  throw new Error('SEMANTIC_BINDING_REQUIRED_AT_ACTIVATION');
}
`;

const BUSINESS_SOURCE = `// Sealed v0.3 Shun goal Business boundary (T09 BUILD composition).
// The business intent stays the only admitted route source for the goal
// interpretation flow; no model-supplied intent can be sealed here.
export const businessManifest = Object.freeze({
  packageId: '${V03_BUSINESS_PACKAGE_ID}',
  role: 'business',
  intent: '${BUSINESS_INTENT_KEY}',
  requiresFeature: '${SEMANTIC_FEATURE_KEY}',
});
export function goalBusinessIntent() {
  return Object.freeze({ intent: '${BUSINESS_INTENT_KEY}' });
}
`;

const CAPABILITY_SOURCE = `// Sealed v0.3 Shun selected C (OpenAI-compatible) boundary.
// Single-sender seam: the only ordinary import is the static
// domain-harness-openai-host entry, bound at activation to the EXISTING
// trusted Shun cloud interpreter port below. No second sender exists.
import { generate } from '${V03_CLOUD_IMPORT_SPECIFIER}';
export const capabilityManifest = Object.freeze({
  packageId: '${V03_CAPABILITY_PACKAGE_ID}',
  role: 'capability',
  capabilityId: '${V03_TRUSTED_CLOUD_INTERPRETER_PORT}',
  externalImportBindings: Object.freeze({
    '${V03_CLOUD_IMPORT_SPECIFIER}': '${V03_TRUSTED_CLOUD_INTERPRETER_PORT}',
  }),
});
export async function ${V03_OPERATION_ID}(input) {
  return generate(input);
}
`;

function sealedModule(
  kind: SelectedModuleKind,
  source: string,
  extra: Omit<
    V10ModuleInput,
    'packageId' | 'role' | 'abiVersion' | 'moduleSource' | 'moduleSha256' | 'endpoint'
  >,
): V10ModuleInput {
  return deepFreeze({
    packageId: PACKAGE_IDS[kind],
    role: SDK_ROLES[kind],
    abiVersion: ROLE_ABI[kind],
    moduleSource: source,
    moduleSha256: sha256Hex(source),
    endpoint: './index.js',
    ...extra,
  });
}

/**
 * Compose the v0.3 single-domain BUILD input from the controlled selection.
 * Refuses (never guesses) unknown roles, duplicates, missing or extra
 * declarations; the successful output is deep-frozen plain data ready for
 * the real public `buildV10App`.
 */
export function composeDomainBuild(input: {
  readonly appId: unknown;
  readonly audience: unknown;
  readonly buildId?: unknown;
  readonly selectedModules: unknown;
}): CompositionResult {
  try {
    if (!isRecord(input)) return refused('composition input must be a plain record');
    const allowed = ['appId', 'audience', 'buildId', 'selectedModules'];
    for (const key of Object.keys(input)) {
      if (!allowed.includes(key)) return refused(`unknown composition field '${key}'`);
    }
    const identity = (value: unknown): string | null =>
      typeof value === 'string' && IDENTITY.test(value) ? value : null;
    const appId = identity(input.appId);
    if (!appId) return refused('appId must be a bounded identity string');
    const audience = identity(input.audience);
    if (!audience) return refused('audience must be a bounded identity string');
    let buildId = DEFAULT_BUILD_ID;
    if (input.buildId !== undefined) {
      const parsed = identity(input.buildId);
      if (!parsed) return refused('buildId must be a bounded identity string');
      buildId = parsed;
    }

    const declarations = input.selectedModules;
    if (!Array.isArray(declarations) || declarations.length === 0) {
      return refused('selectedModules must be a non-empty array of declarations');
    }
    const counts = new Map<SelectedModuleKind, number>();
    for (const declaration of declarations) {
      if (!isRecord(declaration)) return refused('each selected module must be a plain record');
      const keys = Object.keys(declaration).sort();
      if (keys.length !== 1 || keys[0] !== 'kind') {
        return refused('selected module declaration must carry exactly one field: kind');
      }
      const kind = declaration.kind;
      if (typeof kind !== 'string' || !(kind in ROLE_ABI)) {
        return refused(`unknown selected module role ${String(kind)}`);
      }
      counts.set(kind as SelectedModuleKind, (counts.get(kind as SelectedModuleKind) ?? 0) + 1);
    }
    for (const kind of Object.keys(ROLE_ABI) as SelectedModuleKind[]) {
      const count = counts.get(kind) ?? 0;
      if (count === 0) return refused(`missing required selected module role '${kind}'`);
      if (count > 1) return refused(`duplicate selected module role '${kind}'`);
    }

    const modules: V10ModuleInput[] = [
      sealedModule('kernel', KERNEL_SOURCE, {
        dependencies: [],
        externalImports: { node: [], npm: [], native: [] },
        provides: [],
        requires: [],
      }),
      sealedModule('semantic', SEMANTIC_SOURCE, {
        dependencies: [],
        externalImports: { node: [], npm: [], native: [] },
        provides: [SEMANTIC_FEATURE_KEY],
        requires: [],
      }),
      sealedModule('business', BUSINESS_SOURCE, {
        dependencies: [V03_SEMANTIC_PACKAGE_ID],
        externalImports: { node: [], npm: [], native: [] },
        provides: [BUSINESS_INTENT_KEY],
        requires: [SEMANTIC_FEATURE_KEY],
      }),
      sealedModule('capability-llm-openai-compatible', CAPABILITY_SOURCE, {
        dependencies: [],
        externalImports: { node: [], npm: [V03_CLOUD_IMPORT_SPECIFIER], native: [] },
        provides: [],
        requires: [],
        capabilityId: V03_TRUSTED_CLOUD_INTERPRETER_PORT,
        handlers: [{ operationId: V03_OPERATION_ID, handler: V03_OPERATION_ID }],
      }),
    ];

    const routes: V10RouteRowInput[] = [
      {
        intentId: V03_INTENT_ID,
        operationId: V03_OPERATION_ID,
        capabilityId: V03_TRUSTED_CLOUD_INTERPRETER_PORT,
        handlerId: V03_OPERATION_ID,
      },
    ];

    const options = deepFreeze({
      appId,
      audience,
      buildId,
      targetProfile: V03_TARGET_PROFILE,
      modules,
      routes,
      hardBudget: HARD_BUDGET,
    }) satisfies BuildV10AppOptions;
    return deepFreeze({
      options,
      externalImportBindings: V03_EXTERNAL_IMPORT_BINDINGS,
    }) satisfies ComposedDomainBuild;
  } catch (error) {
    return refused(
      `composition input could not be read: ${error instanceof Error ? error.message : 'unknown'}`,
    );
  }
}
