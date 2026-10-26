// T07 F04B3b hard-kill child: a REAL second Node process that rebuilds the
// trusted host boundary over the SAME durable SQLite store and runs the REAL
// authorized physical mutation, then STOPS THE WORLD (Atomics.wait futex
// hold) at one of the four effect phases so the PARENT can terminate the OS
// process externally (SIGKILL / TerminateProcess). Spawned ONLY by
// sqlite-file-mutation-phase-hardkill.test.ts via
// `node --experimental-transform-types` (the trusted sources use TypeScript
// parameter properties, which strip-only mode cannot run); not collected by
// vitest (no *.test.ts name) and never imported by src.
//
// argv: <sqliteFile> <fixturesFile (JSON {action, plan})> <phase P1|P2|P3|P4>
//
// Phase hold points — all inside the REAL trusted composition (the boundary
// reserves the durable STARTED row and hands journal-backed checkpoints to
// the injected REAL vertical-files bridge):
//   P1 PRECOMMIT_DURABLE — the immutable pre-effect snapshot is durable and
//      read back, but NO destination IO has happened yet;
//   P2 onDestCreate — the destination name exists through the exclusive
//      FILE_CREATE only, zero source bytes written;
//   P3 onRename — the no-replace relocation succeeded (source name gone,
//      full bytes at the destination), before any post-state verification;
//   P4 after the full verified effect return — the physical effect is
//      COMPLETE and bridge-verified, but the boundary has NOT journaled the
//      terminal state yet (recordOutcome runs only after the wrapper
//      returns, and it never returns).
// P1-P3 hold inside the package-internal instrumented seam reached with the
// ADMITTED intent of the authorized action (the same composition PR #186's
// e2e uses); P4 holds behind the production entry executeAuthorizedFileMutation.
// The child NEVER exits by itself after a phase marker: only the parent's
// kill ends the process, so a normal exit code is always a falsifier
// failure, never a kill proof.
import { readFileSync, writeSync } from 'node:fs';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { AuthorizedActionSchema } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import {
  executeAuthorizedFileMutation,
  executeVerifiedFileMutation,
  type FileMutationInstrument,
} from '../../vertical-files/src/file-mutation-host.ts';
import { SqliteFileMutationAuthorizationBoundary } from '../src/sqlite-file-mutation-host.ts';

const INTEGRITY_SECRET = 'private-test-integrity';
const ISSUANCE_SECRET = 'private-test-issuance';

/** Futex hold on the main thread: no timer, no IO, no exit — the process
 * stays alive inside the phase callback until the parent kills it. */
function holdForever(): never {
  const cell = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    Atomics.wait(cell, 0, 0);
  }
}

const [sqliteFile, fixturesPath, phase] = process.argv.slice(2);
if (
  typeof sqliteFile !== 'string' ||
  typeof fixturesPath !== 'string' ||
  (phase !== 'P1' && phase !== 'P2' && phase !== 'P3' && phase !== 'P4')
) {
  writeSync(2, 'CHILD_ARGS_REFUSED');
  process.exitCode = 2;
} else {
  const fixtures = JSON.parse(readFileSync(fixturesPath, 'utf8')) as {
    action: unknown;
    plan: unknown;
  };
  const action = AuthorizedActionSchema.parse(fixtures.action);
  const store = new ShunStore({ file: sqliteFile });
  const adapter = new ShunStoreAuthorizationAdapter(store);
  const clock = () => new Date().toISOString();
  const authority = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: INTEGRITY_SECRET,
    issuanceSecret: ISSUANCE_SECRET,
    clock,
  });
  const controller = new ActionController({
    authority,
    policyState: adapter,
    approvals: {
      requestApproval: async () => {
        throw new Error('approval cannot be reached');
      },
    },
    issuanceSecret: ISSUANCE_SECRET,
    clock,
  });

  const holdAtPhase = (): void => {
    writeSync(1, `PHASE_READY:${phase}\n`);
    holdForever();
  };

  const instrument: FileMutationInstrument = {
    onStage: (stage) => {
      if (phase === 'P1' && stage === 'PRECOMMIT_DURABLE') holdAtPhase();
    },
    onDestCreate: () => {
      if (phase === 'P2') holdAtPhase();
    },
    onRename: () => {
      if (phase === 'P3') holdAtPhase();
    },
  };

  const boundary = new SqliteFileMutationAuthorizationBoundary({
    store,
    controller,
    loadPlanByHash: async () => fixtures.plan,
    executeFileMutation: async (authorizedAction, checkpoints) => {
      if (phase === 'P4') {
        // The REAL production entry runs the physical effect to a fully
        // verified completion. Holding BEFORE this wrapper returns leaves
        // the boundary suspended between the verified effect and its
        // durable terminal-state commit.
        const completed = executeAuthorizedFileMutation(authorizedAction, checkpoints);
        if (completed.ok) holdAtPhase();
        return completed;
      }
      const parameters = authorizedAction.action.parameters as Record<string, unknown>;
      return executeVerifiedFileMutation(
        {
          op: authorizedAction.action.op,
          sourcePath: parameters.sourcePath,
          destinationPath: parameters.destinationPath,
        },
        authorizedAction.actionId,
        instrument,
        checkpoints,
      );
    },
  });

  const result = await boundary.execute(action);
  // Reaching this line means no phase hold happened — surface it honestly;
  // a normal child exit can never be counted as a forced death by the
  // parent's kill-evidence gate.
  writeSync(2, `CHILD_UNEXPECTED_RETURN:${result.ok ? 'ok' : result.code}`);
  process.exitCode = 3;
  await store.close();
}
