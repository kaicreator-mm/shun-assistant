// Test factories: a disposable authority store + typed action/plan/grant
// builders matching the frozen contracts exactly (canonical plan hash, HMAC
// integrity envelope, CURRENT currentness record).
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type ActionPlan,
  type AuthorizationGrant,
  type AuthorizedAction,
  type CurrentAuthorityState,
  computePlanHash,
} from '@shun/contracts';
import { build } from 'esbuild';
import { isElevatedToken } from '../src/elevation.ts';
import {
  generateGrantHmacKey,
  type HelperPin,
  sha256File,
  signGrantWithHmac,
  writeCurrentAuthority,
  writeGrantHmacKey,
  writeGrantRecord,
  writeHelperPin,
  writePlanRecord,
} from '../src/trusted-store.ts';

/**
 * Host posture gates for the always-on suite. GitHub's windows-latest
 * runners run with an ELEVATED admin token, so elevation-negative cases are
 * meaningful only on a filtered-token host (like a developer workstation);
 * Windows-only surfaces are skipped on other platforms so the root
 * cross-platform `pnpm test` stays honest instead of failing.
 */
export const ON_WINDOWS = process.platform === 'win32';

export const IS_ELEVATED_HOST: boolean = (() => {
  if (!ON_WINDOWS) return false;
  try {
    return isElevatedToken(
      execFileSync('whoami.exe', ['/groups', '/fo', 'csv'], {
        encoding: 'utf8',
        windowsHide: true,
      }),
    );
  } catch {
    return false;
  }
})();

export const AUTHORITY_ID = 'shun.action-controller.test';
export const AUTHORITY_REVISION = 'auth-rev-1';
export const POLICY_REVISION = 'policy-rev-1';

export interface TestAuthority {
  root: string;
  authorityDir: string;
  workspaceRoot: string;
  hmacKey: string;
  helperBundle: string;
  relayScript: string;
}

/** Build the helper bundle with the TEST authority dir baked in + a full pin. */
export async function createTestAuthority(basename = 'shun-exec-'): Promise<TestAuthority> {
  const root = mkdtempSync(join(tmpdir(), basename));
  const authorityDir = join(root, 'authority');
  const workspaceRoot = join(root, 'workspace');
  const distDir = join(root, 'dist');
  mkdirSync(authorityDir, { recursive: true });
  mkdirSync(workspaceRoot, { recursive: true });
  mkdirSync(distDir, { recursive: true });

  const helperBundle = join(distDir, 'executor-helper.mjs');
  await build({
    entryPoints: [join(import.meta.dirname, '..', 'src', 'helper', 'executor-helper.ts')],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    outfile: helperBundle,
    define: { SHUN_EXECUTOR_AUTHORITY_DIR: JSON.stringify(authorityDir) },
  });

  const relayScript = join(import.meta.dirname, '..', 'src', 'relay', 'elevate-relay.ps1');
  const hmacKey = generateGrantHmacKey();
  writeGrantHmacKey(authorityDir, hmacKey);
  writeCurrentAuthority(authorityDir, currentAuthority());

  const pin: HelperPin = {
    schemaVersion: 'shun.executor-windows.helper-pin/1',
    helperRevision: 'shun.executor-windows.helper/test',
    helperSha256: sha256File(helperBundle),
    relaySha256: sha256File(relayScript),
    workspaceRoot,
    pinnedAt: new Date().toISOString(),
  };
  writeHelperPin(authorityDir, pin);
  return { root, authorityDir, workspaceRoot, hmacKey, helperBundle, relayScript };
}

export function disposeTestAuthority(authority: TestAuthority): void {
  rmSync(authority.root, { recursive: true, force: true });
}

export function currentAuthority(
  overrides?: Partial<Extract<CurrentAuthorityState, { kind: 'CURRENT' }>>,
): CurrentAuthorityState {
  return {
    kind: 'CURRENT',
    authorityId: AUTHORITY_ID,
    authorityRevision: AUTHORITY_REVISION,
    policySnapshotRevision: POLICY_REVISION,
    policyStatus: 'ACTIVE',
    revokedGrantIds: [],
    ...overrides,
  };
}

export function writeCurrentAuthorityState(
  authority: TestAuthority,
  state: CurrentAuthorityState,
): void {
  writeCurrentAuthority(authority.authorityDir, state);
}

// ---- action / plan / grant factories. ----

export interface ActionSpec {
  actionId?: string;
  op: string;
  parameters: Record<string, unknown>;
  requiredPrivilege?: 'NONE' | 'USER' | 'ELEVATED';
  sideEffectClass?: 'R0' | 'R1' | 'R2' | 'R3';
  timeoutMs?: number;
  filesystemScope?: { read: string[]; write: string[] };
  registryScope?: { write: string[] };
  expectedState?: Record<string, unknown>;
  taskId?: string;
  policySnapshotRevision?: string;
}

export interface BuiltAction {
  plan: ActionPlan;
  action: AuthorizedAction;
  grant: AuthorizationGrant;
}

export function buildAuthorizedAction(
  authority: TestAuthority,
  spec: ActionSpec,
  grantOverrides?: { expiresAt?: string; revoked?: boolean },
): BuiltAction {
  const actionId = spec.actionId ?? `act-${randomUUID().slice(0, 8)}`;
  const taskId = spec.taskId ?? 'task-1';
  const policySnapshotRevision = spec.policySnapshotRevision ?? POLICY_REVISION;
  const planAction = {
    actionId,
    bindingRef: 'binding-1',
    op: spec.op,
    parameters: spec.parameters,
    sideEffectClass: spec.sideEffectClass ?? ('R1' as const),
    requiredPrivilege: spec.requiredPrivilege ?? ('USER' as const),
    ...(spec.filesystemScope ? { filesystemScope: spec.filesystemScope } : {}),
    ...(spec.registryScope ? { registryScope: spec.registryScope } : {}),
    ...(spec.timeoutMs !== undefined ? { timeoutMs: spec.timeoutMs } : {}),
    ...(spec.expectedState ? { expectedState: spec.expectedState } : {}),
  };
  const planNoHash = {
    taskId,
    capabilityId: 'test.capability',
    bindingRefs: ['binding-1'],
    rankingPolicyRevision: 'rank-rev-1',
    policySnapshotRevision,
    actions: [planAction],
    verificationPlan: {
      verifierId: 'test-verifier',
      verifierRevision: '1',
      checks: [{ checkId: 'post-state' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE' as const,
      reconcileBeforeRetry: true as const,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED' as const,
    },
  };
  const plan: ActionPlan = { ...planNoHash, planHash: computePlanHash(planNoHash as ActionPlan) };
  writePlanRecord(join(authority.authorityDir, 'plans'), plan);

  const expiresAt = grantOverrides?.expiresAt ?? new Date(Date.now() + 15 * 60_000).toISOString();
  const grantNoIntegrity = {
    grantId: `grant-${randomUUID().slice(0, 8)}`,
    issuer: { authorityId: AUTHORITY_ID, authorityRevision: AUTHORITY_REVISION },
    taskId,
    planHash: plan.planHash,
    policySnapshotRevision,
    actionScope: {
      actionIds: [actionId],
      privilegeLevel: planAction.requiredPrivilege,
      ...(spec.filesystemScope ? { filesystem: spec.filesystemScope } : {}),
      ...(spec.registryScope ? { registry: spec.registryScope } : {}),
    },
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt,
  };
  const grant: AuthorizationGrant = {
    ...grantNoIntegrity,
    integrity: signGrantWithHmac(authority.hmacKey, grantNoIntegrity as AuthorizationGrant),
  };
  writeGrantRecord(join(authority.authorityDir, 'grants'), grant);
  if (grantOverrides?.revoked) {
    const current = currentAuthority({ revokedGrantIds: [grant.grantId] });
    writeCurrentAuthorityState(authority, current);
  }

  const action: AuthorizedAction = {
    taskId,
    actionId,
    planHash: plan.planHash,
    policySnapshotRevision,
    authorizationKind: 'DURABLE_POLICY',
    authorizationRef: grant.grantId,
    action: planAction,
  };
  return { plan, action, grant };
}

// ---- privileged helper invocation (direct, non-elevated — no UAC). ----

export interface HelperRun {
  exitCode: number;
  journal: string;
  receipt: string | undefined;
  stderr: string;
}

export function runHelperDirectly(
  authority: TestAuthority,
  envelopeFile: string,
  journalFile: string,
  receiptFile: string,
  timeoutMs = 60000,
  cwd?: string,
): HelperRun {
  let exitCode = -1;
  let stderr = '';
  try {
    execFileSync(
      process.execPath,
      [authority.helperBundle, envelopeFile, journalFile, receiptFile],
      {
        timeout: timeoutMs,
        windowsHide: true,
        encoding: 'utf8',
        ...(cwd ? { cwd } : {}),
      },
    );
    exitCode = 0;
  } catch (e) {
    const err = e as { status?: number; stderr?: string };
    exitCode = err.status ?? -1;
    stderr = String(err.stderr ?? '');
  }
  let receipt: string | undefined;
  try {
    if (existsSync(receiptFile)) receipt = readText(receiptFile);
  } catch {
    receipt = undefined;
  }
  return {
    exitCode,
    journal: existsSync(journalFile) ? readText(journalFile) : '',
    receipt,
    stderr,
  };
}

function readText(file: string): string {
  return readFileSync(file, 'utf8');
}

// ---- fs fixtures. ----

export function tempWorkspace(prefix = 'shun-exec-ws-'): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** Windows junction (reparse point) for reparse-rejection tests. */
export function createJunction(linkPath: string, targetPath: string): void {
  // PowerShell avoids cmd.exe's quote-stripping quirks; single quotes keep
  // the paths literal (temp paths never contain single quotes).
  execFileSync(
    join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe',
    ),
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `New-Item -ItemType Junction -Path '${linkPath}' -Value '${targetPath}' | Out-Null`,
    ],
    { windowsHide: true },
  );
}

export function copyDir(src: string, dest: string): void {
  cpSync(src, dest, { recursive: true });
}

export { existsSync, mkdirSync, symlinkSync };

/** Test-side non-null unwrapping that keeps biome's noNonNullAssertion clean. */
export function must<T>(value: T | undefined | null, what = 'value'): T {
  if (value === undefined || value === null) throw new Error(`missing ${what}`);
  return value;
}
