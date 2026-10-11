// T04 C06 — same-user-writable trust anchor: tamper detection + fail-closed.
//
// The authority store (grants / currentness / HMAC key / pin) lives in the
// user's profile and is writable by the very user whose authority it
// anchors. A same-user attacker rewriting anchor files must NEVER get
// "presented, therefore fine": the privileged boundary re-verifies every
// anchor inside its own boundary and refuses on any mismatch, corruption or
// rollback of the currentness pairing. These are the end-to-end negative
// controls (real helper bundle, real refusal channel).
//
// Residual (ESCALATED): with the HMAC key co-located AND readable by the
// same user, a determined same-user attacker can rewrite grants and RE-SIGN
// them. Closing that hole needs an independently protected trust principal
// (privileged authority service / ACL'd key path). The external-key tests
// below prove the in-scope hardening: once the key path is externalized via
// the build define, store tampering alone cannot forge grants again.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AuthorizationGrant } from '@shun/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import {
  generateGrantHmacKey,
  readHelperPin,
  sha256File,
  signGrantWithHmac,
  writeGrantHmacKey,
  writeHelperPin,
} from '../src/trusted-store.ts';
import {
  buildAuthorizedAction,
  buildHelperBundle,
  createTestAuthority,
  currentAuthority,
  disposeTestAuthority,
  IS_ELEVATED_HOST,
  must,
  ON_WINDOWS,
  runHelperDirectly,
  type TestAuthority,
  writeCurrentAuthorityState,
} from './helpers.ts';

interface RunSetup {
  envelopeFile: string;
  journalFile: string;
  receiptFile: string;
  targetFile: string;
}

/** Assemble a valid ELEVATED run directory; returns the I/O paths. */
function setupRun(authority: TestAuthority, subdir: string): RunSetup {
  const runDir = join(authority.workspaceRoot, subdir);
  mkdirSync(runDir, { recursive: true });
  const targetFile = join(runDir, 'effect-target.txt');
  const built = buildAuthorizedAction(authority, {
    op: 'windows.fs.write',
    parameters: { path: targetFile, content: 'x' },
    requiredPrivilege: 'ELEVATED',
    sideEffectClass: 'R2',
    filesystemScope: { read: [], write: [authority.workspaceRoot] },
  });
  const setup: RunSetup = {
    envelopeFile: join(runDir, 'envelope.json'),
    journalFile: join(runDir, 'journal.jsonl'),
    receiptFile: join(runDir, 'receipt.json'),
    targetFile,
  };
  writeEnvelopeFile(setup.envelopeFile, {
    action: built.action,
    grant: built.grant,
    plan: built.plan,
    io: {
      journalFile: setup.journalFile,
      receiptFile: setup.receiptFile,
      evidenceDir: join(runDir, 'evidence'),
    },
  });
  return setup;
}

function receiptReason(run: { receipt: string | undefined }): string {
  if (!run.receipt) return '';
  const parsed = JSON.parse(run.receipt) as { detail?: { reason?: string } };
  return parsed.detail?.reason ?? '';
}

describe.skipIf(!ON_WINDOWS)('C06 — same-user trust-anchor tampering refuses (real helper)', () => {
  let authority: TestAuthority;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-c06-');
  });

  afterAll(() => disposeTestAuthority(authority));

  it('a rewritten grant record (widened scope, stale envelope) is refused', () => {
    const setup = setupRun(authority, 'c06-tampered-grant');
    // Same-user attacker rewrites the presented grant: widen the scope,
    // keep the original integrity envelope (they cannot re-sign without the
    // protected key — and with a co-located key, the envelope no longer
    // matches the tampered payload either way).
    const envelope = JSON.parse(readFileSync(setup.envelopeFile, 'utf8')) as {
      grant: AuthorizationGrant;
    };
    envelope.grant = {
      ...envelope.grant,
      actionScope: {
        ...envelope.grant.actionScope,
        filesystem: { read: [], write: ['C:\\'] },
      },
    };
    writeFileSync(setup.envelopeFile, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');

    const run = runHelperDirectly(
      authority,
      setup.envelopeFile,
      setup.journalFile,
      setup.receiptFile,
    );
    expect(run.exitCode).toBe(2);
    expect(receiptReason(run)).toContain('GRANT_NOT_AUTHENTIC');
    expect(existsSync(setup.targetFile)).toBe(false);
  });

  it('an emptied HMAC key file fails closed (unverifiable = unauthentic)', () => {
    const setup = setupRun(authority, 'c06-emptied-key');
    writeFileSync(join(authority.authorityDir, 'grant-hmac.key'), '\n', 'utf8');
    try {
      const run = runHelperDirectly(
        authority,
        setup.envelopeFile,
        setup.journalFile,
        setup.receiptFile,
      );
      expect(run.exitCode).toBe(2);
      expect(receiptReason(run)).toContain('GRANT_NOT_AUTHENTIC');
      expect(existsSync(setup.targetFile)).toBe(false);
    } finally {
      writeGrantHmacKey(authority.authorityDir, authority.hmacKey);
    }
  });

  it('a rolled-back currentness record (stale authority revision) breaks the grant pairing', () => {
    const setup = setupRun(authority, 'c06-rollback-currentness');
    // Attacker restores a pre-revocation-era record: older authorityRevision
    // than the grant was issued against.
    writeCurrentAuthorityState(authority, currentAuthority({ authorityRevision: 'auth-rev-0' }));
    try {
      const run = runHelperDirectly(
        authority,
        setup.envelopeFile,
        setup.journalFile,
        setup.receiptFile,
      );
      expect(run.exitCode).toBe(2);
      expect(receiptReason(run)).toContain('GRANT_AUTHORITY_STALE');
      expect(existsSync(setup.targetFile)).toBe(false);
    } finally {
      writeCurrentAuthorityState(authority, currentAuthority());
    }
  });
});

describe.skipIf(!ON_WINDOWS)(
  'C06 — externalized HMAC key path (in-scope hardening, real helper)',
  () => {
    let authority: TestAuthority;
    let externalKeyFile: string;
    let externalBundle: string;
    let externalKey: string;

    beforeAll(async () => {
      authority = await createTestAuthority('shun-c06-ext-');
      // The protected key location (deployment would ACL this to
      // Administrators/SYSTEM; here a temp file models that path).
      externalKeyFile = join(mkdtempSync(join(tmpdir(), 'shun-c06-key-')), 'grant-hmac.key');
      externalKey = generateGrantHmacKey();
      writeFileSync(externalKeyFile, `${externalKey}\n`, 'utf8');
      // Store starts consistent (co-located key == external key).
      writeGrantHmacKey(authority.authorityDir, externalKey);
      // Bundle trusts the EXTERNAL path only.
      externalBundle = join(authority.root, 'dist', 'executor-helper-extkey.mjs');
      await buildHelperBundle(authority.authorityDir, externalBundle, {
        SHUN_EXECUTOR_HMAC_KEY_FILE: JSON.stringify(externalKeyFile),
      });
      const pin = must(readHelperPin(authority.authorityDir), 'pin');
      writeHelperPin(authority.authorityDir, {
        ...pin,
        helperSha256: sha256File(externalBundle),
      });
      // From here on this suite's authority signs with the EXTERNAL key and
      // runs the external-key bundle: the legitimate path of the world where
      // the trust anchor key lives on the protected path.
      authority = {
        ...authority,
        hmacKey: externalKey,
        helperBundle: externalBundle,
      };
    });

    afterAll(() => disposeTestAuthority(authority));

    it('a store-located attacker key + re-signed grant still fails (external key wins)', () => {
      const setup = setupRun(authority, 'c06-ext-forged');
      // Attacker who can write the store swaps the co-located key and
      // re-signs the presented grant with THEIR key.
      const attackerKey = generateGrantHmacKey();
      writeGrantHmacKey(authority.authorityDir, attackerKey);
      try {
        const envelope = JSON.parse(readFileSync(setup.envelopeFile, 'utf8')) as {
          grant: AuthorizationGrant;
        };
        envelope.grant = {
          ...envelope.grant,
          integrity: signGrantWithHmac(attackerKey, envelope.grant),
        };
        writeFileSync(setup.envelopeFile, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');

        const run = runHelperDirectly(
          authority,
          setup.envelopeFile,
          setup.journalFile,
          setup.receiptFile,
        );
        expect(run.exitCode).toBe(2);
        expect(receiptReason(run)).toContain('GRANT_NOT_AUTHENTIC');
        expect(existsSync(setup.targetFile)).toBe(false);
      } finally {
        writeGrantHmacKey(authority.authorityDir, externalKey);
      }
    });

    it('genuine authority signatures still verify against the external key', () => {
      const setup = setupRun(authority, 'c06-ext-legit');
      const run = runHelperDirectly(
        authority,
        setup.envelopeFile,
        setup.journalFile,
        setup.receiptFile,
      );
      // HMAC passed: the refusal (if any) is NOT about grant authenticity.
      expect(receiptReason(run)).not.toContain('GRANT_NOT_AUTHENTIC');
      expect(existsSync(setup.journalFile)).toBe(true);
      if (IS_ELEVATED_HOST) {
        expect(run.exitCode).toBe(0);
        expect(existsSync(setup.targetFile)).toBe(true);
      } else {
        // Filtered token: refused at elevation consistency after grant OK.
        expect(run.exitCode).toBe(2);
        expect(receiptReason(run)).toContain('filtered');
        expect(existsSync(setup.targetFile)).toBe(false);
      }
    });
  },
);
