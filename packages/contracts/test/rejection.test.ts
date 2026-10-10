import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseOrThrow } from '../src/registry.ts';
import { ShunContractError } from '../src/taxonomy.ts';
import { entryByName, INVALID_FIXTURES_DIR, invalidFixtureManifest } from './helpers.ts';

describe('invalid/unknown contract data is rejected with typed codes', () => {
  for (const [file, expectation] of invalidFixtureManifest()) {
    it(`${file}: ${expectation.schema} rejects with ${expectation.code}`, () => {
      const raw = JSON.parse(readFileSync(join(INVALID_FIXTURES_DIR, file), 'utf8')) as unknown;
      const result = entryByName(expectation.schema).schema.safeParse(raw);
      expect(result.success).toBe(false);

      let caught: unknown;
      try {
        parseOrThrow(entryByName(expectation.schema).schema, raw);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(ShunContractError);
      expect((caught as ShunContractError).code).toBe(expectation.code);
    });
  }

  it('the manifest covers a meaningful negative surface', () => {
    expect(invalidFixtureManifest().length).toBeGreaterThanOrEqual(15);
  });

  it('unknown enum values are structurally rejected (not coerced)', () => {
    const result = entryByName('goal-contract').schema.safeParse({
      taskId: 't',
      objective: 'o',
      objects: [],
      constraints: {},
      privacyPolicy: { localOnly: true, externalDisclosure: 'SOMETIMES' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      ambiguityDisposition: 'READY',
    });
    expect(result.success).toBe(false);
  });
});
