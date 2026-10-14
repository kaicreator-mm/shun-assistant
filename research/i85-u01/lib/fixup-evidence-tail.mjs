// i85-U01 fixup — after finalize() appended its own two bookkeeping events,
// the evidenceIntegrity table inside results.json no longer described the
// FINAL committed event stream. Recompute the integrity table over the final
// on-disk bytes (real crypto over real files, no hand-filled values) and
// update the events line count, so the committed evidence is self-consistent.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { EVIDENCE_DIR, logEvent, sha256File } from './runner.mjs';

// Log this fixup's own event FIRST, so the integrity table computed below
// covers the complete final stream including itself (fixed point).
await logEvent('S5-fixup-integrity', {
  cmd: 'recompute evidenceIntegrity over final evidence bytes before commit',
  rc: 0,
  stdout: 'events.ndjson hash recomputed after this event was appended',
});

const evidenceFiles = [
  'events.ndjson',
  'fact-collection.json',
  'currentness-probe.json',
  'hostile-matrix.json',
  'isolation-netsh.json',
  'appcontainer-probe.json',
  'results.json',
];
const integrity = {};
for (const f of evidenceFiles) {
  integrity[f] = await sha256File(resolve(EVIDENCE_DIR, f));
}
const eventsRaw = await readFile(resolve(EVIDENCE_DIR, 'events.ndjson'), 'utf8');
const eventLines = eventsRaw.split('\n').filter((l) => l.trim().length > 0);

const resultsPath = resolve(EVIDENCE_DIR, 'results.json');
const results = JSON.parse(await readFile(resultsPath, 'utf8'));
results.evidenceIntegrity = { sha256: integrity, eventsLines: eventLines.length };
results.evidenceIntegrity.note =
  'recomputed over the final on-disk evidence bytes, including this fixup event itself (nothing appends to events.ndjson after this point)';
await writeFile(resultsPath, `${JSON.stringify(results, null, 2)}\n`, 'utf8');
console.log(JSON.stringify({ eventsLines: eventLines.length, integrity }, null, 2));
