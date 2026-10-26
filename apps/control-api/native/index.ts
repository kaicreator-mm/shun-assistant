// v0.2 T08 C02: Shun-owned private IPC trusted consent broker — host-side
// surface. Fail-closed loader (recipe-runtime native-loader precedent): on
// non-Windows or when the pinned artifacts are missing/tampered, everything
// reports typed unavailability. There is NO JS pipe fallback and NO path
// where the public HTTP layer can mint a consent approval.
//
// This module performs zero network I/O and never touches a credential; the
// only egress-relevant capability (the single-use broker assertion) is
// consumed by the T01 TrustedDeepSeekTransport composition in the T08
// integration task, not here.
import { createRequire } from 'node:module';
import type { CloudConsentApproval } from '@shun/contracts';
import { brokerExePath, verifyArtifacts } from './artifacts.ts';

/** Fixed refusal code outside the trusted native lane. */
export const PRIVATE_CONSENT_UNAVAILABLE = 'PRIVATE_CONSENT_BROKER_UNAVAILABLE' as const;

export type PrivateConsentAvailability =
  | { ok: true; exeSha256: string; addonSha256: string }
  | { ok: false; code: typeof PRIVATE_CONSENT_UNAVAILABLE; reason: string };

export function privateConsentHostAvailability(): PrivateConsentAvailability {
  const check = verifyArtifacts();
  if (!check.ok) {
    return { ok: false, code: PRIVATE_CONSENT_UNAVAILABLE, reason: check.reason ?? 'UNKNOWN' };
  }
  return {
    ok: true,
    exeSha256: check.exeSha256 as string,
    addonSha256: check.addonSha256 as string,
  };
}

interface ConsentHostAddon {
  generatePipeName(): string;
  spawnBroker(
    exePath: string,
    pipeName: string,
    desktop: string | null,
  ): { pid: number; pipeName: string; imagePath: string };
  connectBroker(pipeName: string, expectExePath: string, timeoutMs: number): BrokerSessionAddon;
  armDialogAutomation(
    pid: number,
    action: 'allow' | 'deny' | 'none',
    findTimeoutMs: number,
  ): number;
  collectDialogAutomation(id: number): { found: boolean; clicked: boolean; done: boolean };
  killSpawnedBroker(pid: number): boolean;
  spawnedBrokerLog(pid: number): string;
  inspectProcessToken(pid: number): {
    openable: boolean;
    userSid: string | null;
    logonSid: string | null;
    sessionId: number | null;
    image: string | null;
    detail: string;
  };
}

interface BrokerSessionAddon {
  pid: number;
  readonly facts: {
    pid: number;
    pipeName: string;
    brokerId: string;
    brokerRevision: string;
    osSessionId: number;
    principalUserSid: string;
    logonSid: string;
    serverImage: string;
    protocol: number;
  };
  requestConsent(requestJson: string): {
    outcome: string;
    detail: string;
    approvalJson: string | null;
  };
  verifyApproval(approvalJson: string): { valid: boolean; reason: string };
  checkNonce(confirmationNonce: string): boolean;
  brokerLog(): string;
  shutdown(timeoutMs: number): { exitCode: number | null; timedOut: boolean };
  kill(): { exitCode: number | null; timedOut: boolean };
}

let cachedAddon: ConsentHostAddon | null | undefined;

function loadAddon(): ConsentHostAddon | null {
  if (cachedAddon !== undefined) return cachedAddon;
  if (process.platform !== 'win32') {
    cachedAddon = null;
    return cachedAddon;
  }
  try {
    // Import AFTER artifact verification in the callers; the loader itself
    // still never falls back to any JS implementation.
    const require = createRequire(import.meta.url);
    cachedAddon = require('../native/host/shun_consent_host.node') as ConsentHostAddon;
  } catch {
    cachedAddon = null;
  }
  return cachedAddon;
}

/** The exact consent request the broker validates and (on approval) mints. */
export interface BrokerConsentRequest {
  taskId: string;
  principalId: string;
  sessionId: string;
  /** EXACT T01 buildDeepSeekGoalDisclosure projection JSON. */
  projectionJson: string;
  approvedProjectionSha256: string;
  scopeRevision: string;
  disclosureCategories: readonly ['GOAL_TEXT'];
  registryRevision: string;
  policyRevision: string;
  pricingRevision: string;
  revocationEpoch: number;
  maxCalls: number;
  maxInputTokens: number;
  maxOutputTokens: number;
  maxCostMicros: number;
  /** Backend consent window (ISO); the broker clamps expiry to 5 minutes. */
  issuedAt: string;
  expiresAt: string;
  /** Broker dialog auto-deny timeout; clamped to [1s, 600s]. */
  dialogTimeoutMs?: number;
}

/** Closed outcome vocabulary — redacted, no raw OS errors ever surface. */
export type BrokerConsentOutcome =
  | 'APPROVED'
  | 'DENIED'
  | 'DENIED_TIMEOUT'
  | 'REFUSED_NONINTERACTIVE'
  | 'REFUSED_DIGEST_MISMATCH'
  | 'REFUSED_SCOPE_INVALID'
  | 'REFUSED_PROJECTION_INVALID'
  | 'REFUSED_SCOPE_EXPIRED'
  | 'REFUSED_TRANSPORT'
  | 'REFUSED_REQUEST_MALFORMED';

export type BrokerConsentResult =
  | { outcome: 'APPROVED'; approval: CloudConsentApproval }
  | { outcome: Exclude<BrokerConsentOutcome, 'APPROVED'> };

export type BrokerExitInfo = { exitCode: number | null; timedOut: boolean };

export type BrokerFacts = Readonly<{
  pid: number;
  pipeName: string;
  brokerId: string;
  brokerRevision: string;
  osSessionId: number;
  principalUserSid: string;
  logonSid: string;
  serverImage: string;
  protocol: number;
  exeSha256: string;
}>;

export class PrivateConsentBrokerSession {
  private constructor(
    private readonly session: BrokerSessionAddon,
    private readonly exeSha256: string,
  ) {}

  /**
   * Spawn a fresh broker on an unguessable pipe name and adopt it. `desktop`
   * exists ONLY for the non-interactive refusal proof (private window
   * station); production callers pass nothing.
   */
  static open(options?: { desktop?: string }): PrivateConsentBrokerSession {
    const availability = privateConsentHostAvailability();
    if (!availability.ok) {
      throw new Error(`${PRIVATE_CONSENT_UNAVAILABLE}:${availability.reason}`);
    }
    const addon = loadAddon();
    if (addon === null) {
      throw new Error(`${PRIVATE_CONSENT_UNAVAILABLE}:ADDON_UNLOADABLE`);
    }
    const exePath = brokerExePath();
    const pipeName = addon.generatePipeName();
    const spawned = addon.spawnBroker(exePath, pipeName, options?.desktop ?? null);
    try {
      const session = addon.connectBroker(spawned.pipeName, exePath, 10_000);
      return new PrivateConsentBrokerSession(session, availability.exeSha256);
    } catch (error) {
      // Leak guard: never leave a spawned broker behind on a failed open.
      addon.killSpawnedBroker(spawned.pid);
      // Typed refusal surface: a squatter, a dead broker or a handshake
      // failure never leaks the raw OS error string.
      const code = String(error).includes('REFUSED_SERVER_IDENTITY')
        ? 'REFUSED_SERVER_IDENTITY'
        : 'REFUSED_HANDSHAKE';
      throw new Error(`${PRIVATE_CONSENT_UNAVAILABLE}:${code}`);
    }
  }

  get facts(): BrokerFacts {
    const inner = this.session.facts;
    return { ...inner, exeSha256: this.exeSha256 };
  }

  get pid(): number {
    return this.session.pid;
  }

  /** Blocking; the dialog belongs to the broker process. */
  requestConsent(request: BrokerConsentRequest): BrokerConsentResult {
    // Flat wire shape: every CloudDisclosureScope field at the root with the
    // pinned provider literals; the broker whitelists the same keys back into
    // the minted scope, so nothing else can ride along.
    const wire = {
      taskId: request.taskId,
      principalId: request.principalId,
      sessionId: request.sessionId,
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: 'https://api.deepseek.com/chat/completions',
      approvedProjectionSha256: request.approvedProjectionSha256,
      scopeRevision: request.scopeRevision,
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: request.registryRevision,
      policyRevision: request.policyRevision,
      pricingRevision: request.pricingRevision,
      revocationEpoch: request.revocationEpoch,
      maxCalls: request.maxCalls,
      maxInputTokens: request.maxInputTokens,
      maxOutputTokens: request.maxOutputTokens,
      maxCostMicros: request.maxCostMicros,
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      projectionJson: request.projectionJson,
      dialogTimeoutMs: request.dialogTimeoutMs,
    };
    const reply = this.session.requestConsent(JSON.stringify(wire));
    if (reply.outcome === 'APPROVED' && reply.approvalJson !== null) {
      return {
        outcome: 'APPROVED',
        approval: JSON.parse(reply.approvalJson) as CloudConsentApproval,
      };
    }
    return { outcome: reply.outcome as Exclude<BrokerConsentOutcome, 'APPROVED'> };
  }

  /** Verify + atomically consume the broker assertion (single use). */
  verifyApproval(approval: CloudConsentApproval): { valid: boolean; reason: string } {
    return this.session.verifyApproval(JSON.stringify(approval));
  }

  /** Non-consuming nonce freshness probe. */
  checkNonce(confirmationNonce: string): boolean {
    return this.session.checkNonce(confirmationNonce);
  }

  /** Redacted broker evidence log (structured BRD lines, no goal text). */
  brokerLog(): string[] {
    return this.session
      .brokerLog()
      .split(/\r?\n/)
      .filter((line) => line.length > 0);
  }

  shutdown(timeoutMs = 5_000): BrokerExitInfo {
    return this.session.shutdown(timeoutMs);
  }

  kill(): BrokerExitInfo {
    return this.session.kill();
  }
}

/** Test-only instruments against the REAL broker dialog/process. */
export const brokerTestInstruments = {
  armDialog(pid: number, action: 'allow' | 'deny' | 'none', findTimeoutMs: number): number | null {
    const addon = loadAddon();
    if (addon === null) return null;
    return addon.armDialogAutomation(pid, action, findTimeoutMs);
  },
  collectDialog(id: number): { found: boolean; clicked: boolean; done: boolean } {
    const addon = loadAddon();
    if (addon === null) return { found: false, clicked: false, done: true };
    return addon.collectDialogAutomation(id);
  },
  inspectProcessToken(pid: number) {
    const addon = loadAddon();
    if (addon === null) {
      return {
        openable: false,
        userSid: null,
        logonSid: null,
        sessionId: null,
        image: null,
        detail: 'addon unavailable',
      } as const;
    }
    return addon.inspectProcessToken(pid);
  },
};
