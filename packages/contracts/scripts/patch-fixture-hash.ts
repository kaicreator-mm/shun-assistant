// Fixture maintenance utility: computes the canonical plan hash of the
// action-plan fixture with the real contracts implementation and patches the
// planHash placeholder in the related fixtures. Run after any deliberate
// change to fixtures/valid/action-plan/single-binding.json:
//   pnpm --filter @shun/contracts patch:fixtures
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type ActionPlan, computePlanHash } from '../src/plan.ts';

const fixturesDir = join(import.meta.dirname, '../fixtures');
const planPath = join(fixturesDir, 'valid/action-plan/single-binding.json');

const plan = JSON.parse(readFileSync(planPath, 'utf8')) as ActionPlan;
const hash = computePlanHash(plan);
if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('computed hash is not sha256 hex');

const targets = [
  planPath,
  join(fixturesDir, 'valid/authorized-action/r1-automatic.json'),
  join(fixturesDir, 'valid/authorization-grant/automatic.json'),
  join(fixturesDir, 'invalid/grant-forged-no-integrity.json'),
];

let patched = 0;
for (const file of targets) {
  const raw = readFileSync(file, 'utf8');
  if (raw.includes('PLANHASH_PLACEHOLDER')) {
    writeFileSync(file, raw.replaceAll('PLANHASH_PLACEHOLDER', hash), 'utf8');
    patched += 1;
    console.log(`patched ${file} -> ${hash}`);
  }
}
if (patched === 0) console.log('no placeholders found; fixtures already consistent');
