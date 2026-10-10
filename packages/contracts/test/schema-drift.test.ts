import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { CONTRACTS } from '../src/registry.ts';
import { CONTRACTS_REVISION, schemaId } from '../src/version.ts';

const SCHEMA_DIR = join(import.meta.dirname, '../src/schema');

describe('committed JSON Schema artifacts are authoritative and drift-free', () => {
  it.each(CONTRACTS.map((c) => c.name))(
    '%s: emission matches the committed artifact byte-for-byte',
    (name) => {
      const entry = CONTRACTS.find((c) => c.name === name);
      if (!entry) throw new Error(`missing contract ${name}`);

      const rebuilt = {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        $id: schemaId(name),
        title: name,
        'x-contracts-revision': CONTRACTS_REVISION,
        ...z.toJSONSchema(entry.schema),
      };
      const committed = readFileSync(join(SCHEMA_DIR, `${name}.schema.json`), 'utf8');
      expect(`${JSON.stringify(rebuilt, null, 2)}\n`).toBe(committed);
    },
  );
});
