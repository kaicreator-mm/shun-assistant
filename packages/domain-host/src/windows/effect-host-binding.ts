/**
 * R03-INT — trusted production install seam binding the selected K's sealed
 * Windows capability (`shun-windows-effect-host`) to the REAL Shun authority
 * chain (OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 *
 * The composing trusted process installs ONE binding over the operator's
 * executor authority store and effect workspace. Every port below is REAL:
 *   - authorization.resolve reads the durable plan/grant records
 *     (FilePlanSource/FileGrantSource) — never caller JSON;
 *   - osAuthority.recheck reads the durable current-authority state;
 *   - actionController.authorizeEffect is the real Shun grant-presentation
 *     validation (HMAC integrity + expiry + revocation), the same validator
 *     the Windows executor backend applies;
 *   - windows.execute is the real LocalWindowsBackend over the operator's
 *     authority dir and effect workspace root.
 * No second kernel, dispatcher or authority store is introduced; the K Permit
 * itself is read by the underlying effect-host adapter.
 */
import { join } from 'node:path';
import { validateGrantPresentation } from '../../../contracts/src/authorization.ts';
import {
  FileCurrentnessSource,
  FileGrantSource,
  FilePlanSource,
  hmacGrantIntegrityVerifier,
  resolveGrantHmacKeyFile,
} from '../../../executor-windows/src/trusted-store.ts';
import { LocalWindowsBackend } from '../../../executor-windows/src/backend.ts';
import { createWindowsEffectHost, type WindowsHostEnvelope } from './effect-host.ts';

export interface TrustedWindowsEffectBindingConfig {
  /** Operator-provisioned executor authority directory (absolute). */
  readonly authorityDir: string;
  /** Bounded effect workspace root (absolute); every effect lands inside it. */
  readonly workspaceRoot: string;
}

interface InstalledBinding {
  readonly host: ReturnType<typeof createWindowsEffectHost>;
  readonly backend: LocalWindowsBackend;
}

let installed: InstalledBinding | undefined;

export function installTrustedWindowsEffectBinding(
  config: TrustedWindowsEffectBindingConfig,
): void {
  if (installed !== undefined) throw new Error('WINDOWS_HOST_ALREADY_INSTALLED');
  if (
    typeof config?.authorityDir !== 'string' ||
    typeof config?.workspaceRoot !== 'string' ||
    !config.authorityDir ||
    !config.workspaceRoot
  ) {
    throw new Error('WINDOWS_HOST_CONFIGURATION_REFUSED');
  }
  const planSource = new FilePlanSource(join(config.authorityDir, 'plans'));
  const grantSource = new FileGrantSource(join(config.authorityDir, 'grants'));
  const currentness = new FileCurrentnessSource(
    join(config.authorityDir, 'current-authority.json'),
  );
  const keyFile = resolveGrantHmacKeyFile(config.authorityDir);
  const verifyIntegrity = hmacGrantIntegrityVerifier(keyFile);
  const backend = new LocalWindowsBackend({
    authorityDir: config.authorityDir,
    workspaceRoot: config.workspaceRoot,
  });
  const host = createWindowsEffectHost({
    binding: { capabilityId: 'windows', operationId: 'windows.execute' },
    authorization: {
      async resolve(input: {
        readonly effectId: string;
        readonly actionRef: string;
        readonly planRef: string;
        readonly grantRef: string;
      }) {
        const plan = planSource.byPlanHash(input.planRef);
        if (!plan) return null;
        const grant = grantSource.byGrantId(input.grantRef);
        if (!grant) return null;
        const action = plan.actions.find((entry) => entry.actionId === input.actionRef);
        if (!action) return null;
        return {
          effectId: input.effectId,
          plan,
          grant,
          action: {
            taskId: plan.taskId,
            actionId: action.actionId,
            planHash: plan.planHash,
            policySnapshotRevision: plan.policySnapshotRevision,
            authorizationKind: 'DURABLE_POLICY' as const,
            authorizationRef: grant.grantId,
            expiresAt: grant.expiresAt,
            action,
          },
        };
      },
    },
    actionController: {
      async authorizeEffect(input: {
        readonly plan: unknown;
        readonly action: unknown;
        readonly grant: unknown;
      }) {
        const verdict = validateGrantPresentation({
          grant: input.grant,
          plan: input.plan,
          action: input.action,
          currentAuthority: currentness.read(),
          now: new Date().toISOString(),
          verifyIntegrity,
        });
        return verdict;
      },
    },
    osAuthority: {
      async recheck() {
        const state = currentness.read();
        return state.kind === 'CURRENT' && state.policyStatus === 'ACTIVE'
          ? { ok: true }
          : { ok: false };
      },
    },
    windows: {
      async execute(input: { readonly effectId: string; readonly action: unknown }) {
        return backend.execute(input.action as never);
      },
    },
  });
  installed = { host, backend };
}

/** K→C callback: the ONLY entry the sealed capability reaches. */
export async function windowsExecute(
  payload: unknown,
  dispatchContext: unknown,
): Promise<WindowsHostEnvelope> {
  if (installed === undefined) throw new Error('WINDOWS_HOST_NOT_INSTALLED');
  return installed.host.dispatch(payload, dispatchContext);
}

/** Trusted-process evidence accessor (receipts/verification only). */
export function trustedWindowsEffectBindingStatus(): Readonly<{
  installed: boolean;
}> {
  return { installed: installed !== undefined };
}
