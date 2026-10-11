// Child-process fixture for crash-hard-kill.test.ts (Issue #36, C05).
// Runs OUTSIDE the vitest process: it opens the store, commits effects one by
// one, reports each commit on stdout, and keeps working so the parent can
// hard-kill the process at an arbitrary point — no clean teardown, no
// wal_checkpoint(TRUNCATE), no close().
import { ShunStore } from '../../src/index.ts';

const file = process.argv[2];
if (typeof file !== 'string' || file.length < 1) {
  process.stderr.write('usage: node write-effects.ts <db-file>\n');
  process.exit(2);
}

const store = new ShunStore({ file });
// Keep the event loop alive even if the apply loop finishes before the
// parent's kill lands.
const keepAlive = setInterval(() => {}, 60_000);

async function main(): Promise<void> {
  for (let i = 1; i <= 50; i += 1) {
    await store.apply(`effect-${i}`, {
      recordKind: 'execution_receipt',
      recordId: `receipt-${i}`,
      payload: { seq: i, actionId: `action-${i}`, terminal: 'SUCCEEDED' },
    });
    process.stdout.write(`APPLIED ${i}\n`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  process.stdout.write('ALL-DONE\n');
}

main().catch((error: unknown) => {
  process.stderr.write(`fixture error: ${String(error)}\n`);
  process.exit(1);
});

process.on('exit', () => {
  clearInterval(keepAlive);
});
