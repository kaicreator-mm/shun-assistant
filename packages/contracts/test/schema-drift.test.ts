import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emitPublicJsonSchema } from '../scripts/emit-schemas.ts';
import { CONTRACTS } from '../src/registry.ts';

const SCHEMA_DIR = join(import.meta.dirname, '../src/schema');

describe('committed JSON Schema artifacts are authoritative and drift-free', () => {
  it.each(CONTRACTS.map((c) => c.name))(
    '%s: emission (Zod + safety-invariant overlay) matches the committed artifact byte-for-byte',
    (name) => {
      const entry = CONTRACTS.find((c) => c.name === name);
      if (!entry) throw new Error(`missing contract ${name}`);

      const rebuilt = emitPublicJsonSchema(name, entry.schema);
      const committed = readFileSync(join(SCHEMA_DIR, `${name}.schema.json`), 'utf8');
      expect(`${JSON.stringify(rebuilt, null, 2)}\n`).toBe(committed);
    },
  );
});
