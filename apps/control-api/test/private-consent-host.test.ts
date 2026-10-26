import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import {
  type CloudConsentApproval,
  CloudConsentApprovalSchema,
  canonicalJson,
  validateCloudConsent,
} from '@shun/contracts';
import { afterAll, describe, expect, it } from 'vitest';
// T01's exact projection builder is reused read-only across the workspace
// boundary: @shun/llm-remote cannot be added to this package's dependencies
// here because the parallel T08 C01 lane (PR #191) owns apps/control-api's
// package.json + pnpm-lock importer edits — no shared file edits across
// parallel branches. The relative import is the disjoint-path alternative.
import { buildDeepSeekGoalDisclosure } from '../../../packages/llm-remote/src/deepseek-transport.ts';
import { brokerExePath } from '../native/artifacts.ts';
import {
  type BrokerConsentRequest,
  brokerTestInstruments,
  PrivateConsentBrokerSession,
  privateConsentHostAvailability,
} from '../native/index.ts';

const execFileAsync = promisify(execFile);
const availability = privateConsentHostAvailability();
const win32Real = process.platform === 'win32' && availability.ok;

// Evidence ledger: every row is a real OS fact observed during this run
// (dialog interactions, exit codes, principal tokens, artifact digests).
const evidence: string[] = [];
function record(row: string): void {
  evidence.push(row);
}

const GOAL = '把桌面上的截图按月份归档 / Archive desktop screenshots by month';

function buildRequest(overrides: Partial<BrokerConsentRequest> = {}): BrokerConsentRequest {
  const disclosure = buildDeepSeekGoalDisclosure(GOAL);
  if (disclosure === null) throw new Error('T01 disclosure builder refused the fixture goal');
  const now = Date.now();
  return {
    taskId: 'task-t08c02-evidence',
    principalId: 'principal-local-user',
    sessionId: 'session-local-1',
    projectionJson: disclosure.projectionJson,
    approvedProjectionSha256: disclosure.sha256,
    scopeRevision: 'v02-consent-scope-r1',
    disclosureCategories: ['GOAL_TEXT'],
    registryRevision: 'registry-r1',
    policyRevision: 'policy-r1',
    pricingRevision: 'pricing-r1',
    revocationEpoch: 0,
    maxCalls: 1,
    maxInputTokens: 4096,
    maxOutputTokens: 2048,
    maxCostMicros: 500_000,
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 10 * 60 * 1000).toISOString(),
    ...overrides,
  };
}

function currentnessFor(approval: CloudConsentApproval, nonceIsUnused: boolean) {
  return {
    kind: 'CURRENT' as const,
    taskId: approval.scope.taskId,
    principalId: approval.scope.principalId,
    sessionId: approval.scope.sessionId,
    registryRevision: approval.scope.registryRevision,
    policyRevision: approval.scope.policyRevision,
    pricingRevision: approval.scope.pricingRevision,
    scopeRevision: approval.scope.scopeRevision,
    revocationEpoch: approval.scope.revocationEpoch,
    nonceIsUnused,
  };
}

afterAll(() => {
  if (evidence.length > 0) {
    // Real-run evidence: SHAs, OS principal facts, dialog interactions, exit codes.
    console.info(`T08 C02 REAL EVIDENCE (${process.platform}, node ${process.version})`);
    for (const row of evidence) {
      console.info(`  ${row}`);
    }
  }
});

describe('T08 C02 Shun-owned private IPC trusted consent broker (real Windows)', () => {
  it('pins the exact committed artifact digests', async () => {
    if (!win32Real || !availability.ok) return;
    record(`exeSha256=${availability.exeSha256}`);
    record(`addonSha256=${availability.addonSha256}`);
    record(`node=${process.version} platform=${process.platform}`);
  }, 10_000);

  it('mints a single-use contract-valid approval through a REAL native dialog', async () => {
    if (!win32Real) return;
    const session = PrivateConsentBrokerSession.open();
    try {
      const facts = session.facts;
      record(
        `broker pid=${facts.pid} id=${facts.brokerId} rev=${facts.brokerRevision} osSession=${facts.osSessionId} userSid=${facts.principalUserSid}`,
      );
      record(`pipe=${facts.pipeName}`);
      record(`serverImage=${facts.serverImage}`);

      // OS principal evidence: the broker's token equals this process's
      // token facts (same user SID / logon SID / session id).
      const brokerToken = brokerTestInstruments.inspectProcessToken(facts.pid);
      const selfToken = brokerTestInstruments.inspectProcessToken(process.pid);
      record(
        `principal broker(sid=${brokerToken.userSid} logon=${brokerToken.logonSid} session=${brokerToken.sessionId})`,
      );
      record(
        `principal host(sid=${selfToken.userSid} logon=${selfToken.logonSid} session=${selfToken.sessionId})`,
      );
      expect(brokerToken.userSid).toBe(facts.principalUserSid);
      expect(brokerToken.sessionId).toBe(facts.osSessionId);
      expect(brokerToken.userSid).toBe(selfToken.userSid);
      expect(brokerToken.logonSid).toBe(selfToken.logonSid);
      expect(brokerToken.sessionId).toBe(selfToken.sessionId);

      const request = buildRequest({ dialogTimeoutMs: 20_000 });
      const armId = brokerTestInstruments.armDialog(session.pid, 'allow', 20_000);
      expect(armId).not.toBeNull();
      const result = session.requestConsent(request);
      const dialog = brokerTestInstruments.collectDialog(armId as number);
      record(
        `dialog real=#32770 found=${dialog.found} clickedAllow=${dialog.clicked} outcome=${result.outcome}`,
      );
      expect(dialog.found).toBe(true);
      expect(dialog.clicked).toBe(true);
      expect(result.outcome).toBe('APPROVED');
      if (result.outcome !== 'APPROVED') return;

      const approval: CloudConsentApproval = result.approval;
      // The broker-minted record satisfies the frozen v0.2 contract exactly.
      const parsed = CloudConsentApprovalSchema.safeParse(approval);
      expect(parsed.success).toBe(true);
      record(`approval consentId=${approval.consentId} channel=${approval.issuer.channel}`);
      expect(approval.issuer.channel).toBe('AUTHENTICATED_PRIVATE_IPC');
      expect(approval.displayedProjectionSha256).toBe(request.approvedProjectionSha256);
      expect(approval.scope.approvedProjectionSha256).toBe(
        buildDeepSeekGoalDisclosure(GOAL)?.sha256,
      );

      // Freshness probe still sees the nonce as unused before consumption.
      expect(session.checkNonce(approval.confirmationNonce)).toBe(true);

      // The trusted backend gate accepts it exactly once.
      const verdict = validateCloudConsent({
        approval,
        currentness: currentnessFor(approval, true),
        now: new Date().toISOString(),
        verifyBroker: (candidate) => session.verifyApproval(candidate).valid,
      });
      expect(verdict.ok).toBe(true);
      record(`validateCloudConsent first=${verdict.ok}`);

      // Second presentation of the SAME approval must never authorize again.
      const second = session.verifyApproval(approval);
      record(`single-use second=${second.valid} reason=${second.reason}`);
      expect(second.valid).toBe(false);
      expect(second.reason).toBe('ASSERTION_CONSUMED');
      expect(session.checkNonce(approval.confirmationNonce)).toBe(false);
      const verdictAfter = validateCloudConsent({
        approval,
        currentness: currentnessFor(approval, false),
        now: new Date().toISOString(),
        verifyBroker: (candidate) => session.verifyApproval(candidate).valid,
      });
      expect(verdictAfter.ok).toBe(false);

      // Broker restart invalidates every outstanding proof (new key + new
      // ledger): the old approval is dead for any future broker instance.
      const killed = session.kill();
      record(`kill exitCode=${killed.exitCode}`);
      const successor = PrivateConsentBrokerSession.open();
      try {
        const revived = successor.verifyApproval(approval);
        const nonceAfterRestart = successor.checkNonce(approval.confirmationNonce);
        record(
          `restart revived=${revived.valid} reason=${revived.reason} nonceUnused=${nonceAfterRestart}`,
        );
        expect(revived.valid).toBe(false);
        expect(nonceAfterRestart).toBe(false);
        const exit = successor.shutdown();
        record(`successor clean exitCode=${exit.exitCode} timedOut=${exit.timedOut}`);
        expect(exit.exitCode).toBe(0);
      } finally {
        successor.shutdown();
      }
    } finally {
      session.shutdown();
    }
  }, 90_000);

  it('denies on a REAL dialog Deny click with zero approval', async () => {
    if (!win32Real) return;
    const session = PrivateConsentBrokerSession.open();
    try {
      const armId = brokerTestInstruments.armDialog(session.pid, 'deny', 20_000);
      const result = session.requestConsent(buildRequest({ dialogTimeoutMs: 20_000 }));
      const dialog = brokerTestInstruments.collectDialog(armId as number);
      record(
        `deny dialog found=${dialog.found} clickedDeny=${dialog.clicked} outcome=${result.outcome}`,
      );
      expect(dialog.found).toBe(true);
      expect(dialog.clicked).toBe(true);
      expect(result.outcome).toBe('DENIED');
      const exit = session.shutdown();
      record(`deny broker exitCode=${exit.exitCode}`);
      expect(exit.exitCode).toBe(0);
    } finally {
      session.shutdown();
    }
  }, 60_000);

  it('auto-denies an unattended dialog (fail-closed default)', async () => {
    if (!win32Real) return;
    const session = PrivateConsentBrokerSession.open();
    try {
      const armId = brokerTestInstruments.armDialog(session.pid, 'none', 6_000);
      const result = session.requestConsent(
        buildRequest({ taskId: 'task-t08c02-timeout', dialogTimeoutMs: 1_500 }),
      );
      const dialog = brokerTestInstruments.collectDialog(armId as number);
      record(
        `timeout dialog appeared=${dialog.found} clicked=${dialog.clicked} outcome=${result.outcome}`,
      );
      expect(dialog.found).toBe(true);
      expect(dialog.clicked).toBe(false);
      expect(result.outcome).toBe('DENIED_TIMEOUT');
    } finally {
      session.shutdown();
    }
  }, 60_000);

  it('never shows any prompt when the projection digest does not match', async () => {
    if (!win32Real) return;
    const session = PrivateConsentBrokerSession.open();
    try {
      const tampered = buildRequest({
        taskId: 'task-t08c02-digest',
        approvedProjectionSha256: `${'0'.repeat(64)}`,
        dialogTimeoutMs: 5_000,
      });
      const armId = brokerTestInstruments.armDialog(session.pid, 'none', 2_500);
      const result = session.requestConsent(tampered);
      const dialog = brokerTestInstruments.collectDialog(armId as number);
      record(`digest-mismatch dialog appeared=${dialog.found} outcome=${result.outcome}`);
      expect(dialog.found).toBe(false);
      expect(result.outcome).toBe('REFUSED_DIGEST_MISMATCH');
    } finally {
      session.shutdown();
    }
  }, 60_000);

  it('refuses arbitrary provider targets inside the projection itself', async () => {
    if (!win32Real) return;
    const session = PrivateConsentBrokerSession.open();
    try {
      // Digest-CONSISTENT tampering: the projection is rebuilt with an
      // attacker-chosen destination and its OWN correct sha256, so the
      // digest check passes and the pinned-literal check must refuse —
      // proving the provider target cannot be swapped even when the
      // client-side hash is recomputed to match.
      const evilProjection = canonicalJson({
        destination: 'https://evil.example.com/chat/completions',
        disclosureCategories: ['GOAL_TEXT'],
        goalText: GOAL,
        modelId: 'deepseek-flash',
        providerId: 'deepseek',
      });
      const request = buildRequest({
        taskId: 'task-t08c02-target',
        projectionJson: evilProjection,
        approvedProjectionSha256: createHash('sha256').update(evilProjection, 'utf8').digest('hex'),
        dialogTimeoutMs: 5_000,
      });
      const armId = brokerTestInstruments.armDialog(session.pid, 'none', 2_500);
      const result = session.requestConsent(request);
      const dialog = brokerTestInstruments.collectDialog(armId as number);
      record(`target-drift(dialog-consistent) appeared=${dialog.found} outcome=${result.outcome}`);
      expect(dialog.found).toBe(false);
      expect(result.outcome).toBe('REFUSED_PROJECTION_INVALID');
    } finally {
      session.shutdown();
    }
  }, 60_000);

  it('refuses instead of approving invisibly without an interactive desktop', async () => {
    if (!win32Real) return;
    const session = PrivateConsentBrokerSession.open({
      desktop: 'winsta0\\ShunT08C02HiddenDesk',
    });
    try {
      const facts = session.facts;
      record(`noninteractive broker pid=${facts.pid} (private window station)`);
      const armId = brokerTestInstruments.armDialog(session.pid, 'none', 3_000);
      const result = session.requestConsent(
        buildRequest({ taskId: 'task-t08c02-nointeractive', dialogTimeoutMs: 8_000 }),
      );
      const dialog = brokerTestInstruments.collectDialog(armId as number);
      record(`noninteractive dialog appeared=${dialog.found} outcome=${result.outcome}`);
      expect(dialog.found).toBe(false);
      expect(result.outcome).toBe('REFUSED_NONINTERACTIVE');
      const exit = session.shutdown();
      record(`noninteractive broker exitCode=${exit.exitCode}`);
      expect(exit.exitCode).toBe(0);
    } finally {
      session.shutdown();
    }
  }, 60_000);

  it('keeps broker exit codes and the evidence log redacted', async () => {
    if (!win32Real) return;
    // Usage error exits 2 with the fixed usage line (documented contract).
    const usage: { code?: number; stderr?: string } = await execFileAsync(brokerExePath(), [
      '--bogus',
    ]).then(
      () => ({ code: 0 }),
      (error: { code?: number; stderr?: string }) => error,
    );
    record(`usage exitCode=${usage.code}`);
    expect(usage.code).toBe(2);

    const session = PrivateConsentBrokerSession.open();
    try {
      const armId = brokerTestInstruments.armDialog(session.pid, 'allow', 20_000);
      const result = session.requestConsent(buildRequest({ dialogTimeoutMs: 20_000 }));
      expect(result.outcome).toBe('APPROVED');
      brokerTestInstruments.collectDialog(armId as number);
      const lines = session.brokerLog();
      record(`broker log lines=${lines.length}`);
      // Structured BRD lines only; never the goal text, a nonce or a MAC.
      for (const line of lines) {
        expect(line.startsWith('BRD ')).toBe(true);
        expect(line.includes(GOAL)).toBe(false);
      }
      expect(lines.some((line) => line.includes('GRANTED'))).toBe(true);
      expect(
        lines.some((line) => line.includes('REFUSED') || line.includes('CLIENT_REFUSED')),
      ).toBe(false);
      // Nonce/MAC redaction: raw proof material never reaches the log.
      const approval = (result as { approval: CloudConsentApproval }).approval;
      expect(lines.some((line) => line.includes(approval.confirmationNonce))).toBe(false);
      expect(lines.some((line) => line.includes(approval.issuer.proof))).toBe(false);
    } finally {
      session.shutdown();
    }
  }, 60_000);
});
