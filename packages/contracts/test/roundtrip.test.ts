import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/plan.ts';
import { CONTRACTS, parseOrThrow } from '../src/registry.ts';
import { validFixturesFor } from './helpers.ts';

const SCHEMA_DIR = join(import.meta.dirname, '../src/schema');

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);

const validatorCache = new Map<string, ReturnType<typeof ajv.compile>>();
function validatorFor(schemaName: string): ReturnType<typeof ajv.compile> {
  const cached = validatorCache.get(schemaName);
  if (cached) return cached;
  const committed = JSON.parse(readFileSync(join(SCHEMA_DIR, `${schemaName}.schema.json`), 'utf8'));
  const compiled = ajv.compile(committed);
  validatorCache.set(schemaName, compiled);
  return compiled;
}

describe('schema roundtrips', () => {
  for (const entry of CONTRACTS) {
    const fixtures = validFixturesFor(entry);
    if (fixtures.length === 0) continue;

    describe(entry.name, () => {
      for (const fixture of fixtures) {
        it(`${fixture.file}: parses, survives serialize→reparse byte-exactly, and validates against the committed JSON Schema`, () => {
          const parsed = parseOrThrow(entry.schema, fixture.json);

          const serialized = JSON.parse(JSON.stringify(parsed)) as unknown;
          const reparsed = parseOrThrow(entry.schema, serialized);
          expect(reparsed).toEqual(parsed);
          expect(canonicalJson(reparsed)).toBe(canonicalJson(parsed));

          const validate = validatorFor(entry.name);
          const ok = validate(fixture.json);
          expect(validate.errors ?? []).toEqual([]);
          expect(ok).toBe(true);
        });
      }

      it('declares at least one contract fixture', () => {
        expect(fixtures.length).toBeGreaterThan(0);
      });
    });
  }

  it('emitted strict objects reject unknown keys in JSON Schema form', () => {
    const committed = JSON.parse(
      readFileSync(join(SCHEMA_DIR, 'goal-contract.schema.json'), 'utf8'),
    ) as Record<string, unknown>;
    expect(committed.additionalProperties).toBe(false);
  });
});
