// T04 C06 — KNOWN-OPEN DEFECT RECORD (Audit-A #10 C06, P0 OPEN). This file is
// an EXPECTED-FAILURE record (it.fails), not a green test and not a fix: the
// attack recipe below RUNS on every suite invocation, currently fails exactly
// as the defect predicts, and vitest reports it as an expected failure —
// keeping a live regression signal instead of the silent describe.skip.
//
// The attack recipe (audit negative control), attacker = a malicious process
// running as the SAME Windows user, controlling only ordinary user processes
// and files (no admin token, no protected authority writer):
//
//   1. Overwrite the co-located grant-integrity key  <authority>/grant-hmac.key
//      with an attacker-chosen key (same-user writable AND readable).
//   2. Re-sign a grant for an arbitrary authorized action with that key (the
//      HMAC scheme is frozen and the key is readable — `signGrantWithHmac` is
//      ordinary library code), keep the grantId so the trusted grant-source
//      lookup resolves, and write the forged record into <authority>/grants/.
//   3. Rewrite <authority>/current-authority.json to CURRENT for the attacker's
//      authority/revision pair (same-user writable).
//   4. (Unnecessary but possible for completeness: rewrite helper-pin.json —
//      the attacker does not even need it, the LEGITIMATE pinned helper
//      accepts the forged envelope.)
//   5. Present the forged envelope to the real pinned helper.
//
// REQUIRED behavior (the expected-to-fail assertions below): the privileged boundary
// must REFUSE — no GRANT_OK in the journal, structured REFUSED receipt, no
// effect — because a trust anchor an attacker can rewrite cannot authenticate
// anything. TODAY (default deployment, key co-located in the same-user-writable
// store) the helper validates the envelope against the store key, the forged
// signature VERIFIES, and the run proceeds past GRANT_OK/PRIVILEGE_OK — on an
// elevated host the effect EXECUTES. The privilege consistency check refuses
// only the elevation dimension on a filtered-token host; the AUTHENTICITY of
// the forged grant is (wrongly) accepted today.
//
// Why it.fails instead of describe.skip: closing this requires an
// INDEPENDENTLY PROTECTED WRITER/TRUST PRINCIPAL (privileged authority
// service owning issuance/revocation/currentness/pin updates, or a store
// whose only writer is an elevated principal) — an architecture decision
// outside the T04 write set (packages/executor-windows/**). It must not be
// "closed" by asserting that same-user ACLs protect the store (they do not —
// the attacker IS the user), and T04 explicitly forbids evading with
// comment-level or ACL-theater mitigations. The in-scope hardening that DID
// land (4502de8): tamper detection without the key
// (authority-store-tamper.test.ts) and key EXTERNALIZATION to a protected
// path (SHUN_EXECUTOR_HMAC_KEY_FILE) — which closes the hole ONLY for
// deployments that actually protect the external key path; the DEFAULT
// co-located deployment remains exposed and ESCALATED to the Controller.
// While the defect is open, the assertions below FAIL (the helper accepts
// the re-signed anchor); it.fails turns that predictable failure into a
// tracked, per-run signal. The tradeoff is documented honesty: it.fails
// cannot distinguish "failed for the predicted reason" from "failed for an
// unrelated reason" — the receipt assertions below pin the expected refusal
// reason so any change in failure shape is reviewable in the output.
//
// Un-skipping contract: when the trust principal lands, the assertions below
// start PASSING and vitest flips this test to FAILED ("expected to fail but
// passed") — that red IS the forced removal signal. Re-express steps 1-2
// against the new seam (e.g. request the forged signature from the authority
// service and expect rejection THERE, plus the helper refusing any anchor
// not attested by the service), keep the recipe, drop the `.fails` marker,
// and delete this paragraph.
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { AuthorizationGrant } from '@shun/contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import {
  generateGrantHmacKey,
  signGrantWithHmac,
  writeGrantHmacKey,
  writeGrantRecord,
} from '../src/trusted-store.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  runHelperDirectly,
  type TestAuthority,
} from './helpers.ts';

describe('C06 KNOWN-OPEN (P0, escalated): same-user re-signed anchors must NOT authenticate', () => {
  let authority: TestAuthority;
  let workspace: string;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-c06-open-');
    workspace = join(authority.workspaceRoot, 'runs');
    mkdirSync(workspace, { recursive: true });
  });

  afterAll(() => disposeTestAuthority(authority));

  // it.fails: the recipe below EXECUTES every run and is expected to fail
  // while C06 is architecturally open (the helper accepts the re-signed
  // anchor). When the trust principal lands and the boundary refuses, these
  // assertions pass and vitest flips this test to FAILED — the forced
  // de-listing signal (see the un-skipping contract in the header).
  it.fails('a same-user attacker who replaces the co-located HMAC key and re-signs gets NOTHING through the boundary', () => {
    // Steps 1-2: attacker key in the store, grant re-signed under it.
    const attackerKey = generateGrantHmacKey();
    writeGrantHmacKey(authority.authorityDir, attackerKey);

    const target = join(workspace, 'c06-open-never.txt');
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: target, content: 'forged effect' },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    // Re-sign the SAME grant payload with the attacker key and publish the
    // forged record in the trusted grant source (same-user writable).
    const { integrity: _original, ...grantPayload } = built.grant;
    const forgedGrant = {
      ...grantPayload,
      integrity: signGrantWithHmac(attackerKey, grantPayload as AuthorizationGrant),
    };
    writeGrantRecord(join(authority.authorityDir, 'grants'), forgedGrant);

    const runDir = join(workspace, 'c06-open-run');
    mkdirSync(runDir, { recursive: true });
    const journalFile = join(runDir, 'journal.jsonl');
    const receiptFile = join(runDir, 'receipt.json');
    writeEnvelopeFile(join(runDir, 'envelope.json'), {
      action: built.action,
      grant: forgedGrant,
      plan: built.plan,
      io: { journalFile, receiptFile, evidenceDir: join(runDir, 'evidence') },
    });

    // Step 5: the REAL pinned helper must reject the forged anchor chain.
    // (Direct spawn — UAC is not the subject; the helper binary is identical
    // to the one the relay would elevate, and today it accepts this envelope.)
    const run = runHelperDirectly(
      authority,
      join(runDir, 'envelope.json'),
      journalFile,
      receiptFile,
    );

    expect(run.exitCode).toBe(2);
    expect(run.receipt).toBeDefined();
    expect(run.receipt).toContain('GRANT_NOT_AUTHENTIC');
    expect(journalPhases(readJournal(journalFile))).not.toContain('GRANT_OK');
    expect(existsSync(target)).toBe(false);
  });
});
