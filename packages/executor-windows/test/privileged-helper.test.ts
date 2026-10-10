// Privileged-boundary negatives on the REAL bundled helper (no UAC needed):
// the helper is spawned directly on a filtered token and must refuse —
// inside the privileged boundary, before any side effect — forged grants,
// plan tamper, stale/revoked authority & policy, unresolvable currentness,
// privilege inconsistency, substituted bundles and workspace escapes.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readEnvelopeFile, writeEnvelopeFile } from '../src/envelope.ts';
import { verifyPinnedHelper } from '../src/helper-pinning.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import { readHelperPin } from '../src/trusted-store.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  currentAuthority,
  disposeTestAuthority,
  must,
  runHelperDirectly,
  type TestAuthority,
  writeCurrentAuthorityState,
} from './helpers.ts';

describe('one-shot helper — privileged-boundary negatives (real bundle, filtered token)', () => {
  let authority: TestAuthority;
  let workspace: string;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-helper-');
    workspace = join(authority.workspaceRoot, 'runs');
    mkdirSync(workspace, { recursive: true });
  });

  afterAll(() => {
    disposeTestAuthority(authority);
  });

  function envelopePaths(name: string) {
    const runDir = join(workspace, name);
    mkdirSync(runDir, { recursive: true });
    return {
      envelopeFile: join(runDir, 'envelope.json'),
      journalFile: join(runDir, 'journal.jsonl'),
      receiptFile: join(runDir, 'receipt.json'),
      runDir,
    };
  }

  function validEnvelope(
    name: string,
    overrides?: {
      tamperPlan?: boolean;
      dropIntegrity?: boolean;
      reSignIntegrity?: boolean;
      requiredPrivilege?: 'USER' | 'ELEVATED';
    },
  ) {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'helper-target.txt'), content: 'from helper' },
      requiredPrivilege: overrides?.requiredPrivilege ?? 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    const grant = overrides?.dropIntegrity ? { ...built.grant, integrity: undefined } : built.grant;
    const plan = overrides?.tamperPlan
      ? {
          ...built.plan,
          actions: [
            {
              ...must(built.plan.actions[0], 'plan action'),
              parameters: { path: join(workspace, 'TAMPERED.txt'), content: 'x' },
            },
          ],
        }
      : built.plan;
    const paths = envelopePaths(name);
    writeEnvelopeFile(paths.envelopeFile, {
      action: built.action,
      grant,
      plan,
      io: {
        journalFile: paths.journalFile,
        receiptFile: paths.receiptFile,
        evidenceDir: join(paths.runDir, 'evidence'),
      },
    });
    return { ...paths, built };
  }

  it('elevation-required action on a filtered token → REFUSED with privilege journal, no effect', () => {
    const p = validEnvelope('privilege-negative');
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(run.receipt).toBeDefined();
    expect(JSON.parse(must(run.receipt, 'helper receipt')).terminal).toBe('REFUSED');
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.reason).toContain('filtered');
    const phases = journalPhases(readJournal(p.journalFile));
    expect(phases).toContain('RECEIVED');
    expect(phases).toContain('SCOPE_OK'); // scope validated before privilege...
    expect(phases).not.toContain('PRIVILEGE_OK'); // ...refusal happens here
    expect(phases).not.toContain('EXEC_START');
    expect(existsSync(join(workspace, 'helper-target.txt'))).toBe(false);
  });

  it('USER action on the same token runs the full validation chain to EXEC', () => {
    const target = join(workspace, 'user-ok.txt');
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: target, content: 'helper user-level' },
      requiredPrivilege: 'USER',
      sideEffectClass: 'R1',
      filesystemScope: { read: [], write: [workspace] },
    });
    const p = envelopePaths('user-positive');
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode, run.receipt ?? run.stderr).toBe(0);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).terminal).toBe('SUCCEEDED');
    expect(existsSync(target)).toBe(true);
    expect(journalPhases(readJournal(p.journalFile))).toContain('RECEIPT_WRITTEN');
  });

  it('forged grant (self-declared, no integrity envelope) → REFUSED GRANT_NOT_AUTHENTIC', () => {
    const p = validEnvelope('forged-grant', { dropIntegrity: true });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_NOT_AUTHENTIC',
    );
    expect(journalPhases(readJournal(p.journalFile))).not.toContain('EXEC_START');
  });

  it('plan tampered after approval → REFUSED GRANT_PLAN_MISMATCH inside the helper', () => {
    const p = validEnvelope('plan-tamper', { tamperPlan: true });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_PLAN_MISMATCH',
    );
  });

  it('stale authority revision → REFUSED GRANT_AUTHORITY_STALE', () => {
    const p = validEnvelope('stale-authority');
    // grant was issued under auth-rev-1; current authority moved on
    writeCurrentAuthorityState(authority, currentAuthority({ authorityRevision: 'auth-rev-2' }));
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    writeCurrentAuthorityState(authority, currentAuthority());
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_AUTHORITY_STALE',
    );
  });

  it('superseded policy revision → REFUSED GRANT_POLICY_STALE', () => {
    const p = validEnvelope('stale-policy');
    writeCurrentAuthorityState(
      authority,
      currentAuthority({ policySnapshotRevision: 'policy-rev-2' }),
    );
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    writeCurrentAuthorityState(authority, currentAuthority());
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_POLICY_STALE',
    );
  });

  it('revoked policy → REFUSED GRANT_POLICY_REVOKED', () => {
    const p = validEnvelope('revoked-policy');
    writeCurrentAuthorityState(
      authority,
      currentAuthority({ policyStatus: 'REVOKED', policySnapshotRevision: 'policy-rev-9' }),
    );
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    writeCurrentAuthorityState(authority, currentAuthority());
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_POLICY_REVOKED',
    );
  });

  it('revoked grant id → REFUSED GRANT_REVOKED', () => {
    const p = validEnvelope('revoked-grant');
    writeCurrentAuthorityState(
      authority,
      currentAuthority({ revokedGrantIds: [p.built.grant.grantId] }),
    );
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    writeCurrentAuthorityState(authority, currentAuthority());
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_REVOKED',
    );
  });

  it('unresolvable currentness (corrupt record) → REFUSED GRANT_CURRENTNESS_UNRESOLVABLE', () => {
    const p = validEnvelope('unresolvable-currentness');
    writeFileSync(join(authority.authorityDir, 'current-authority.json'), '{corrupt', 'utf8');
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    writeCurrentAuthorityState(authority, currentAuthority());
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_CURRENTNESS_UNRESOLVABLE',
    );
  });

  it('missing currentness record → REFUSED GRANT_CURRENTNESS_UNRESOLVABLE (fail closed)', () => {
    const p = validEnvelope('missing-currentness');
    const backup = 'current-authority.json.bak';
    const record = join(authority.authorityDir, 'current-authority.json');
    writeFileSync(join(authority.authorityDir, backup), JSON.stringify(currentAuthority()), 'utf8');
    rmSync(record);
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    writeFileSync(record, JSON.stringify(currentAuthority()), 'utf8');
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_CURRENTNESS_UNRESOLVABLE',
    );
  });

  it('expired grant → REFUSED GRANT_EXPIRED', () => {
    const p = envelopePaths('expired-grant');
    const built = buildAuthorizedAction(
      authority,
      {
        op: 'windows.fs.write',
        parameters: { path: join(workspace, 'expired.txt'), content: 'x' },
        requiredPrivilege: 'USER',
        filesystemScope: { read: [], write: [workspace] },
      },
      { expiresAt: new Date(Date.now() - 1000).toISOString() },
    );
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).detail.rejectionCode).toBe(
      'GRANT_EXPIRED',
    );
  });

  it('scope escape (target outside grant filesystem scope) → REFUSED before effects', () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(authority.root, 'outside-scope.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [join(workspace, 'allowed')] },
    });
    const p = envelopePaths('scope-escape');
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(existsSync(join(authority.root, 'outside-scope.txt'))).toBe(false);
    expect(journalPhases(readJournal(p.journalFile))).not.toContain('EXEC_START');
  });

  it('substituted helper bundle → the helper refuses its own identity (defense in depth)', async () => {
    // Build a SECOND bundle from the same sources but pointing at a bogus
    // authority dir: content differs → pin self-check must fail.
    const { build } = await import('esbuild');
    const impostor = join(authority.root, 'impostor.mjs');
    await build({
      entryPoints: [join(import.meta.dirname, '..', 'src', 'helper', 'executor-helper.ts')],
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node24',
      outfile: impostor,
      define: { SHUN_EXECUTOR_AUTHORITY_DIR: JSON.stringify(join(authority.root, 'elsewhere')) },
    });
    const pin = readHelperPin(authority.authorityDir);
    const check = verifyPinnedHelper(impostor, authority.relayScript, pin);
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toContain('helper identity mismatch');

    // The launcher-side check refuses BEFORE any UAC/subprocess; running the
    // impostor directly also refuses inside (no pin in its bogus authority).
    // Unique target file: no other case in this file writes it.
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'impostor-target.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const p = envelopePaths('impostor');
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    const run = runHelperDirectly(
      { ...authority, helperBundle: impostor },
      p.envelopeFile,
      p.journalFile,
      p.receiptFile,
    );
    expect(run.exitCode).toBe(2);
    expect(existsSync(join(workspace, 'impostor-target.txt'))).toBe(false);
  });

  it('launcher I/O path outside the pinned workspace root → REFUSED pre-journal (no files written)', () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'escape-io.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const evilDir = mkdtempSync(join(tmpdir(), 'shun-evil-io-'));
    const envelopeFile = join(evilDir, 'envelope.json');
    const journalFile = join(evilDir, 'journal.jsonl');
    const receiptFile = join(evilDir, 'receipt.json');
    writeEnvelopeFile(envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: { journalFile, receiptFile, evidenceDir: join(evilDir, 'evidence') },
    });
    const run = runHelperDirectly(authority, envelopeFile, journalFile, receiptFile);
    expect(run.exitCode).toBe(2);
    expect(existsSync(journalFile)).toBe(false);
    expect(existsSync(receiptFile)).toBe(false);
    expect(existsSync(join(workspace, 'escape-io.txt'))).toBe(false);
  });

  it('cancel sentinel present before effects → CANCELLED receipt (exit 5)', () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'cancel-me.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const p = envelopePaths('cancel-before');
    writeFileSync(join(p.runDir, 'cancel.sentinel'), 'x', 'utf8');
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        cancelFile: join(p.runDir, 'cancel.sentinel'),
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(5);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).terminal).toBe('CANCELLED');
    expect(existsSync(join(workspace, 'cancel-me.txt'))).toBe(false);
  });

  it('action deadline (tiny timeoutMs) → TIMED_OUT receipt (exit 4)', () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'deadline.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
      timeoutMs: 1,
    });
    const p = envelopePaths('deadline');
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(4);
    expect(JSON.parse(must(run.receipt, 'helper receipt')).terminal).toBe('TIMED_OUT');
  });

  it('malformed envelope (unknown key) → REFUSED pre-journal without receipt', () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'never.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const p = envelopePaths('malformed-envelope');
    writeEnvelopeFile(p.envelopeFile, {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: p.journalFile,
        receiptFile: p.receiptFile,
        evidenceDir: join(p.runDir, 'evidence'),
      },
    });
    // smuggle a key into the envelope after writing
    const raw = readEnvelopeFile(p.envelopeFile) as unknown as Record<string, unknown>;
    raw.helperOverride = 'C:\\evil\\helper.mjs';
    writeFileSync(p.envelopeFile, JSON.stringify(raw), 'utf8');
    const run = runHelperDirectly(authority, p.envelopeFile, p.journalFile, p.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(existsSync(p.journalFile)).toBe(false);
  });
});
