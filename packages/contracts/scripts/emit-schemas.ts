// Regenerates the committed public JSON Schema artifacts in src/schema/ from the
// Zod contract registry. The committed files are the public contract surface;
// a drift test guarantees they stay byte-identical to this emission.
import { mkdirSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { CONTRACTS } from '../src/registry.ts';
import { CONTRACTS_REVISION, schemaId } from '../src/version.ts';

const outDir = join(import.meta.dirname, '../src/schema');
mkdirSync(outDir, { recursive: true });

const keep = new Set<string>();
for (const contract of CONTRACTS) {
  const json = z.toJSONSchema(contract.schema) as Record<string, unknown>;
  const withIdentity = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: schemaId(contract.name),
    title: contract.name,
    'x-contracts-revision': CONTRACTS_REVISION,
    ...json,
  };
  const file = join(outDir, `${contract.name}.schema.json`);
  writeFileSync(file, `${JSON.stringify(withIdentity, null, 2)}\n`, 'utf8');
  keep.add(`${contract.name}.schema.json`);
  console.log(`emitted ${contract.name}.schema.json`);
}

for (const name of readdirSync(outDir)) {
  if (!keep.has(name)) {
    unlinkSync(join(outDir, name));
    console.log(`removed stale ${name}`);
  }
}
