// R03-INT — production journey composition for the windows-effect, provider
// first-use and meta-feedback intents (OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
// R03C (#288): adds the read-only cross-Case Meta shared-experience query and
// the Host-global Provider prepare/confirm binding surfaces.
//
// All intents traverse the SAME selected public v0.10.3 DomainApp as
// goal-interpret (no second kernel/dispatcher): the trusted composition
// installs the REAL Host bindings before activation, and every HTTP submit
// is authenticated against the durable Host-issued submit-reference ledger
// for the live Guided Case step BEFORE any Kernel entry — identical
// fail-closed semantics to the goal gateway. The Host-global Provider
// prepare/confirm route is the deliberate exception: it requires no Guided
// Case and no reference pair by contract.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { SendReceipt } from '../../../../packages/domain-app/src/api/gateway.ts';
import type { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import type { HostMetaShadowStore } from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';
import type { TrustedProviderBindingConfig } from '../../../../packages/domain-host/src/provider/provider-host-binding.ts';
import type { SqliteHostSubmitReferenceLedger } from './composition-approval.ts';

export interface JourneyBindingsConfig {
  /** Real executor authority store + bounded effect workspace (J02 route). */
  readonly windows?: { readonly authorityDir: string; readonly workspaceRoot: string };
  /** Real pinned CuratedProvider chain (J05 route). */
  readonly provider?: TrustedProviderBindingConfig;
  /** Real durable Shadow store (J09 route). */
  readonly meta?: { readonly store: HostMetaShadowStore };
}

/**
 * Fail-closed identity check + module import of one staged consumer binding.
 * Exported so the production composition can drive the Host-global Provider
 * prepare/confirm surfaces through the SAME staged module instance the
 * sealed capability imports.
 */
export async function loadStagedBindingModule(
  consumerRoot: string,
  packageName: string,
): Promise<Record<string, unknown>> {
  const hostDir = join(consumerRoot, 'node_modules', packageName);
  const manifest = JSON.parse(readFileSync(join(hostDir, 'package.json'), 'utf8')) as {
    name?: string;
    main?: string;
  };
  if (
    manifest.name !== packageName ||
    manifest.main !== './index.mjs' ||
    !existsSync(join(hostDir, manifest.main ?? ''))
  ) {
    throw new Error(`V03_JOURNEY_BINDING_REFUSED:${packageName}`);
  }
  return (await import(pathToFileURL(join(hostDir, manifest.main as string)).href)) as Record<
    string,
    unknown
  >;
}

/**
 * Fail-closed install: each declared route family needs its real binding.
 * The install MUST go through the SAME staged consumer module instance the
 * sealed capability imports (exactly like the T04 openai-host seam), so the
 * module-global installed binding is coherent for both sides.
 */
export async function installJourneyBindings(
  config: JourneyBindingsConfig,
  consumerRoot: string,
): Promise<void> {
  const stagedInstall = async (
    packageName: string,
    installer: string,
    argument: unknown,
  ): Promise<void> => {
    const module = await loadStagedBindingModule(consumerRoot, packageName);
    if (typeof module[installer] !== 'function') {
      throw new Error(`V03_JOURNEY_BINDING_SEAM_REFUSED:${packageName}`);
    }
    (module[installer] as (input: unknown) => void)(argument);
  };
  if (config.windows)
    await stagedInstall(
      'shun-windows-effect-host',
      'installTrustedWindowsEffectBinding',
      config.windows,
    );
  if (config.provider)
    await stagedInstall('shun-provider-host', 'installTrustedProviderBinding', config.provider);
  if (config.meta) await stagedInstall('shun-meta-host', 'installTrustedMetaBinding', config.meta);
}

const CASE_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
const CURRENTNESS_REF = /^shun\.currentness\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const APPROVAL_REF = /^shun\.approval\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_ID = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const RATINGS = new Set(['HELPFUL', 'NOT_HELPFUL']);
const CATEGORIES = new Set([
  'INCORRECT_RESULT',
  'MISSING_STEP',
  'WRONG_TARGET',
  'UNSAFE_SUGGESTION',
  'TOO_COMPLEX',
  'OTHER',
]);
const CORRECTIONS = new Set([
  'WRONG_OBJECT',
  'MISSING_CONSTRAINT',
  'STALE_CONTEXT',
  'POLICY_MISMATCH',
  'NO_CORRECTION',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length &&
    keys.every((key, index) => key === [...expected].sort()[index])
  );
}

function canonicalSnapshot(raw: unknown): { ok: true; value: unknown } | { ok: false } {
  try {
    const text = JSON.stringify(raw);
    if (text === undefined || text.length > 65_536) return { ok: false };
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function refused(code: string, detail: string): SendReceipt {
  return {
    status: 'REFUSED',
    code: code as never,
    detail,
    sendCalls: 0,
    journalEntries: 0,
    refusedAtUnixMs: Date.now(),
  };
}

function validRefs(value: Record<string, unknown>): boolean {
  return (
    typeof value.caseId === 'string' &&
    CASE_ID.test(value.caseId) &&
    typeof value.currentnessRef === 'string' &&
    CURRENTNESS_REF.test(value.currentnessRef) &&
    typeof value.approvalRef === 'string' &&
    APPROVAL_REF.test(value.approvalRef)
  );
}

/**
 * Same truthful classification contract as the goal gateway: only a
 * K-admitted envelope with explicitly terminal, executed and successful
 * effects is COMPLETED; refusal stays refused; anything unresolved is
 * UNKNOWN and owned by the K journal — never a fake success.
 * Exported for the R03C Host-global Provider confirm path, which reuses the
 * identical classification for its fixed facade.send.
 */
export function classifyJourneyKernelResult(result: unknown): SendReceipt {
  if (!isRecord(result)) {
    return { status: 'UNKNOWN', code: 'KERNEL_RESULT_UNKNOWN', sendCalls: 1 };
  }
  if (result.status === 'refused' || result.status === 'rejected') {
    return { status: 'KERNEL_REFUSED', code: 'KERNEL_REFUSED', sendCalls: 1 };
  }
  if (result.status !== 'admitted') {
    return { status: 'UNKNOWN', code: 'KERNEL_RESULT_UNKNOWN', sendCalls: 1 };
  }
  const admitted = result.admitted;
  if (!isRecord(admitted) || !Array.isArray(admitted.effects)) {
    return { status: 'UNKNOWN', code: 'KERNEL_RESULT_UNKNOWN', sendCalls: 1 };
  }
  if (admitted.effects.length === 0) {
    return { status: 'ADMITTED', sendCalls: 1, result };
  }
  for (const effect of admitted.effects) {
    if (
      !isRecord(effect) ||
      effect.disposition !== 'executed' ||
      !isRecord(effect.output) ||
      effect.output.phase !== 'terminal' ||
      !isRecord(effect.output.outcome)
    ) {
      return { status: 'UNKNOWN', code: 'EFFECT_RESULT_UNKNOWN', sendCalls: 1 };
    }
    if (effect.output.outcome.ok !== true) {
      return effect.output.outcome.ok === false
        ? { status: 'KERNEL_REFUSED', code: 'KERNEL_REFUSED', sendCalls: 1 }
        : { status: 'UNKNOWN', code: 'EFFECT_RESULT_UNKNOWN', sendCalls: 1 };
    }
  }
  return { status: 'COMPLETED', sendCalls: 1, result };
}

export interface JourneySubmits {
  /** J02: one K-permitted scoped Windows effect (plan/grant references only). */
  effectSubmit(raw: unknown): Promise<SendReceipt>;
  /** J02 negative witness: the same sealed route WITHOUT a K permit. */
  effectProbeSubmit(raw: unknown): Promise<SendReceipt>;
  /**
   * R03C: the legacy Case-scoped provider first-use route is SUPERSEDED by
   * the Host-global two-step prepare/confirm surface (no Guided Case, no
   * reference pair, one-time Host requestRef). The K intent itself now
   * consumes only {requestRef}, so this route refuses closed instead of
   * fabricating a request: POST /api/v03/provider/prepare + /confirm.
   */
  providerFirstUse(raw: unknown): Promise<SendReceipt>;
  /** J09: one opt-in feedback submission → durable Shadow candidate. */
  metaFeedback(raw: unknown): Promise<SendReceipt>;
  /**
   * R03C: read-only cross-Case shared-experience query for the current
   * Guided Case (target Case = the live Case; source Case is provenance
   * only). Input matches the #285 store contract exactly.
   */
  metaSharedQuery(raw: unknown): Promise<SendReceipt>;
}

export function createJourneySubmits(deps: {
  readonly facade: { send(payload: unknown): Promise<unknown> };
  readonly selectedCase: Pick<HostGuidedService, 'state'>;
  readonly references: SqliteHostSubmitReferenceLedger;
  readonly now: () => number;
}): JourneySubmits {
  let attemptCounter = 0;
  const liveCase = (caseId: string): { stepId: string } | null => {
    const liveStep = deps.selectedCase.state().currentStep;
    if (!liveStep || liveStep.taskId !== caseId || liveStep.validUntilUnixMs <= deps.now()) {
      return null;
    }
    return { stepId: liveStep.stepId };
  };
  const verifyRefs = (
    caseId: string,
    stepId: string,
    currentnessRef: string,
    approvalRef: string,
  ): { ok: true } | { ok: false; code: string } => {
    const verified = deps.references.verify({ caseId, stepId, currentnessRef, approvalRef });
    return verified.status === 'VALID' ? { ok: true } : { ok: false, code: verified.code };
  };
  const send = async (intentType: string, caseId: string, input: unknown): Promise<SendReceipt> => {
    try {
      const result = await deps.facade.send({
        intentType,
        instanceKey: caseId,
        messageId: `msg-j-${++attemptCounter}`,
        input,
      });
      return classifyJourneyKernelResult(result);
    } catch (error) {
      // Message-only diagnostics (never payload content) for the operator log.
      console.error(
        '[v03-journeys] send failed:',
        error instanceof Error ? error.message : String(error),
      );
      return { status: 'UNKNOWN', code: 'SEND_OUTCOME_UNKNOWN', sendCalls: 1 };
    }
  };
  const admit = async (
    raw: unknown,
    extraKeys: readonly string[],
    validateExtra: (value: Record<string, unknown>) => string | null,
    intentType: string,
    buildInput: (value: Record<string, unknown>) => unknown,
  ): Promise<SendReceipt> => {
    const snapshot = canonicalSnapshot(raw);
    if (!snapshot.ok || !isRecord(snapshot.value)) {
      return refused('GATEWAY_INPUT_INVALID', 'submission is not bounded canonical JSON data');
    }
    const value = snapshot.value;
    if (!exactKeys(value, [...extraKeys, 'caseId', 'currentnessRef', 'approvalRef'])) {
      return refused('GATEWAY_INPUT_INVALID', 'submission keys do not match the journey contract');
    }
    if (!validRefs(value)) {
      return refused('GATEWAY_INPUT_INVALID', 'caseId/reference pair is not well formed');
    }
    const extraError = validateExtra(value);
    if (extraError !== null) return refused('GATEWAY_INPUT_INVALID', extraError);
    const live = liveCase(value.caseId as string);
    if (!live) return refused('HOST_CASE_NOT_CURRENT', 'no live Guided Case for this caseId');
    const refs = verifyRefs(
      value.caseId as string,
      live.stepId,
      value.currentnessRef as string,
      value.approvalRef as string,
    );
    if (!refs.ok) return refused(refs.code, 'Host-issued reference pair rejected');
    return send(intentType, value.caseId as string, buildInput(value));
  };

  return Object.freeze({
    effectSubmit: (raw: unknown) =>
      admit(
        raw,
        ['actionRef', 'planRef', 'grantRef'],
        (value) => {
          if (typeof value.actionRef !== 'string' || !SAFE_ID.test(value.actionRef)) {
            return 'actionRef must be a bounded action identity';
          }
          if (typeof value.planRef !== 'string' || !SHA256.test(value.planRef)) {
            return 'planRef must be the canonical plan hash';
          }
          if (typeof value.grantRef !== 'string' || !SAFE_ID.test(value.grantRef)) {
            return 'grantRef must be a bounded grant identity';
          }
          return null;
        },
        'submitWindowsAction',
        (value) => ({
          actionRef: value.actionRef,
          planRef: value.planRef,
          grantRef: value.grantRef,
          taskId: value.caseId,
        }),
      ),
    effectProbeSubmit: (raw: unknown) =>
      admit(
        raw,
        ['actionRef', 'planRef', 'grantRef'],
        (value) => {
          if (typeof value.actionRef !== 'string' || !SAFE_ID.test(value.actionRef)) {
            return 'actionRef must be a bounded action identity';
          }
          if (typeof value.planRef !== 'string' || !SHA256.test(value.planRef)) {
            return 'planRef must be the canonical plan hash';
          }
          if (typeof value.grantRef !== 'string' || !SAFE_ID.test(value.grantRef)) {
            return 'grantRef must be a bounded grant identity';
          }
          return null;
        },
        'submitUnpermittedWindowsProbe',
        (value) => ({
          actionRef: value.actionRef,
          planRef: value.planRef,
          grantRef: value.grantRef,
          taskId: value.caseId,
        }),
      ),
    providerFirstUse: () =>
      Promise.resolve(
        refused(
          'PROVIDER_ROUTE_SUPERSEDED',
          'provider first-use is Host-global: POST /api/v03/provider/prepare, then /api/v03/provider/confirm with the issued requestRef',
        ),
      ),
    metaSharedQuery: (raw: unknown) => {
      const snapshot = canonicalSnapshot(raw);
      if (!snapshot.ok || !isRecord(snapshot.value)) {
        return Promise.resolve(
          refused('GATEWAY_INPUT_INVALID', 'submission is not bounded canonical JSON data'),
        );
      }
      const value = snapshot.value;
      const allowed = new Set([
        'caseId',
        'currentnessRef',
        'approvalRef',
        'capabilityId',
        'taskClass',
        'limit',
      ]);
      if (!Object.keys(value).every((key) => allowed.has(key))) {
        return Promise.resolve(
          refused(
            'GATEWAY_INPUT_INVALID',
            'submission keys do not match the shared-query contract (no tags or free fields)',
          ),
        );
      }
      if (
        typeof value.caseId !== 'string' ||
        typeof value.currentnessRef !== 'string' ||
        typeof value.approvalRef !== 'string' ||
        typeof value.capabilityId !== 'string'
      ) {
        return Promise.resolve(
          refused('GATEWAY_INPUT_INVALID', 'caseId, reference pair and capabilityId are required'),
        );
      }
      if (!validRefs(value)) {
        return Promise.resolve(
          refused('GATEWAY_INPUT_INVALID', 'caseId/reference pair is not well formed'),
        );
      }
      if (!SAFE_ID.test(value.capabilityId)) {
        return Promise.resolve(
          refused('GATEWAY_INPUT_INVALID', 'capabilityId must be a bounded vocabulary code'),
        );
      }
      if (
        value.taskClass !== undefined &&
        (typeof value.taskClass !== 'string' || !SAFE_ID.test(value.taskClass))
      ) {
        return Promise.resolve(
          refused('GATEWAY_INPUT_INVALID', 'taskClass must be a bounded vocabulary code'),
        );
      }
      if (
        value.limit !== undefined &&
        (!Number.isSafeInteger(value.limit) ||
          (value.limit as number) < 1 ||
          (value.limit as number) > 20)
      ) {
        return Promise.resolve(
          refused(
            'GATEWAY_INPUT_INVALID',
            'limit must be an integer within the bounded store maximum (20)',
          ),
        );
      }
      const live = liveCase(value.caseId);
      if (!live)
        return Promise.resolve(
          refused('HOST_CASE_NOT_CURRENT', 'no live Guided Case for this caseId'),
        );
      const refs = verifyRefs(
        value.caseId,
        live.stepId,
        value.currentnessRef as string,
        value.approvalRef as string,
      );
      if (!refs.ok)
        return Promise.resolve(refused(refs.code, 'Host-issued reference pair rejected'));
      return send('querySharedExperiences', value.caseId as string, {
        targetCaseRef: value.caseId,
        capabilityId: value.capabilityId,
        // The workflow rule projects the full frozen field set; absent
        // optional values travel as null and the effect handler omits them
        // before the Host store call (the #285 contract is optional-only).
        taskClass: value.taskClass === undefined ? null : value.taskClass,
        limit: value.limit === undefined ? null : value.limit,
      });
    },
    metaFeedback: (raw: unknown) =>
      admit(
        raw,
        ['caseRef', 'sourceRevision', 'rating', 'category', 'correction'],
        (value) => {
          if (typeof value.caseRef !== 'string' || !SAFE_ID.test(value.caseRef)) {
            return 'caseRef must be a bounded Case reference';
          }
          if (typeof value.sourceRevision !== 'string' || !SAFE_ID.test(value.sourceRevision)) {
            return 'sourceRevision must be a bounded revision reference';
          }
          if (typeof value.rating !== 'string' || !RATINGS.has(value.rating)) {
            return 'rating must be HELPFUL or NOT_HELPFUL';
          }
          if (typeof value.category !== 'string' || !CATEGORIES.has(value.category)) {
            return 'category must be a frozen feedback category';
          }
          if (typeof value.correction !== 'string' || !CORRECTIONS.has(value.correction)) {
            return 'correction must be a frozen correction value (NO_CORRECTION when absent)';
          }
          return null;
        },
        'submitMetaFeedback',
        (value) => ({
          selected: true,
          caseRef: value.caseRef,
          sourceRevision: value.sourceRevision,
          rating: value.rating,
          category: value.category,
          correction: value.correction,
        }),
      ),
  });
}

/**
 * R03C (#288): operator-pinned Meta case provisioning, extended from the
 * legacy single-record Host file to a BOUNDED multi-Case batch while
 * preserving the exact hash-pinning and fail-closed validation.
 *
 * File forms (exactly one, never both):
 *   legacy:   { "receipt": {...}, "consent": {...} }
 *   batch:    { "cases": [ { "receipt": {...}, "consent": {...} }, ... ] }
 *
 * The whole file stays sha256-pinned; every record must carry the minimal
 * receipt/consent shape and the durable store re-validates strictly on
 * write (fail-closed). The batch is bounded so a pinned file can seed more
 * than one source Case into the SAME local DB without an unbounded boot cost.
 */
export const META_CASE_PROVISION_MAX_CASES = 16;

export function provisionMetaFromHostFile(input: {
  store: HostMetaShadowStore;
  file: string;
  sha256: string;
}): void {
  const bytes = readFileSync(resolve(input.file));
  if (createHash('sha256').update(bytes).digest('hex') !== input.sha256) {
    throw new Error('V03_META_CASE_DIGEST_REFUSED');
  }
  const raw = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
  const legacy = raw.receipt !== undefined || raw.consent !== undefined;
  const batch = raw.cases !== undefined;
  if (legacy === batch) {
    // Neither form, or a file trying to be both: refuse closed.
    throw new Error('V03_META_CASE_INVALID');
  }
  const entries: unknown[] = batch
    ? (raw.cases as unknown[])
    : [{ receipt: raw.receipt, consent: raw.consent }];
  if (
    !Array.isArray(entries) ||
    entries.length < 1 ||
    entries.length > META_CASE_PROVISION_MAX_CASES
  ) {
    throw new Error('V03_META_CASE_BATCH_BOUND_REFUSED');
  }
  for (const entry of entries) {
    if (!isRecord(entry)) throw new Error('V03_META_CASE_INVALID');
    const receipt = entry.receipt as Record<string, unknown> | undefined;
    const consent = entry.consent as Record<string, unknown> | undefined;
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
}
