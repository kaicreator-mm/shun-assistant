// T04 child process harness, spawned by the Windows host tests as:
//   node --experimental-strip-types test/helpers/hardkill-child.ts \
//        <dbPath> <identityJson> <planJson> <mode>
// It attaches to the REAL durable store and composes the REAL trusted host
// (persisted policy -> ActionController grant -> journaled reservation).
//
// mode=block (hard-kill falsifier): acknowledges the committed STARTED row
// synchronously on stdout, then waits to be force-killed: no receipt, no
// journal observation, no graceful close, no WAL checkpoint.
//
// mode=effect (missing-addon falsifier): runs the whole loop to completion
// with the genuine native effect and reports the final runner result, so the
// parent can prove a missing native addon fails closed in a fresh process.
import { writeSync } from 'node:fs';
import type { ActionPlan } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { createSqliteAuthorizedRecipeEffectHost } from '../../src/index.ts';
import { SqliteR0EffectJournal } from '../../src/sqlite-r0-effect-journal.ts';
import { executeTrustedWindowsR0Search } from '../../src/trusted-windows-r0-effect.ts';
import {
  buildAuthorityStack,
  buildCurrentness,
  type HostFixtureIdentity,
} from './win-e2e-fixture.ts';

const [dbPath, identityJson, planJson, mode = 'block'] = process.argv.slice(2);
if (!dbPath || !identityJson || !planJson) {
  writeSync(2, 'CHILD_ARGUMENTS_MISSING\n');
  process.exit(11);
}
const identity = JSON.parse(identityJson) as HostFixtureIdentity;
const plan = JSON.parse(planJson) as ActionPlan;

try {
  const store = new ShunStore({ file: dbPath });
  const { controller } = buildAuthorityStack(store);
  const live = createSqliteAuthorizedRecipeEffectHost({
    store,
    controller,
    currentness: buildCurrentness(store),
    loadExpectedPlan: () => plan,
    loadPlanByHash: async (hash) => (hash === plan.planHash ? plan : null),
    executeScopedSearch:
      mode === 'block'
        ? async (action) => {
            // The journaled boundary has now committed the durable STARTED
            // row. Acknowledge synchronously, then wait to be force-killed.
            writeSync(1, `PRE_EFFECT ${JSON.stringify(action)}\n`);
            await new Promise<never>(() => {});
            return undefined as never;
          }
        : async (action) =>
            executeTrustedWindowsR0Search(action, {
              phaseJournal: new SqliteR0EffectJournal(store),
            }),
  });
  live.runner
    .run(identity)
    .then(
      (result) => {
        writeSync(1, `CHILD_RUN_DONE ${JSON.stringify(result)}\n`);
        process.exit(0);
      },
      (error: unknown) => {
        writeSync(2, `CHILD_RUN_FAILED ${error instanceof Error ? error.message : 'unknown'}\n`);
        process.exit(10);
      },
    )
    .catch(() => process.exit(10));
  if (mode === 'block') {
    // Keep the event loop parked while the effect promise never settles; the
    // parent's kill is the only intended way out.
    setInterval(() => {}, 60_000);
  }
} catch (error) {
  writeSync(2, `CHILD_BOOT_FAILED ${error instanceof Error ? error.message : 'unknown'}\n`);
  process.exit(12);
}
