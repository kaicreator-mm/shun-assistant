import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ContractEntry } from '../src/registry.ts';
import { CONTRACTS, contractByName } from '../src/registry.ts';

export const FIXTURES_ROOT = join(import.meta.dirname, '../fixtures');
export const INVALID_FIXTURES_DIR = join(FIXTURES_ROOT, 'invalid');

export function loadFixture(relPath: string): unknown {
  return JSON.parse(readFileSync(join(FIXTURES_ROOT, relPath), 'utf8'));
}

export function validFixturesFor(entry: ContractEntry): { file: string; json: unknown }[] {
  const dir = join(FIXTURES_ROOT, 'valid', entry.name);
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((n) => n.endsWith('.json'))
    .sort()
    .map((n) => ({
      file: `${entry.name}/${n}`,
      json: JSON.parse(readFileSync(join(dir, n), 'utf8')),
    }));
}

export type InvalidFixtureExpectation = { schema: string; code: string };

export function invalidFixtureManifest(): [file: string, expectation: InvalidFixtureExpectation][] {
  const raw = JSON.parse(
    readFileSync(join(INVALID_FIXTURES_DIR, 'manifest.json'), 'utf8'),
  ) as Record<string, InvalidFixtureExpectation>;
  return Object.entries(raw).sort(([a], [b]) => (a < b ? -1 : 1));
}

export function entryByName(name: string): ContractEntry {
  const entry = contractByName(name);
  if (!entry) throw new Error(`unknown contract name in manifest: ${name}`);
  return entry;
}

/** Reverse key order at every object depth — used to prove hash order-insensitivity. */
export function reverseKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseKeysDeep);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .reverse()
        .map(([k, v]) => [k, reverseKeysDeep(v)]),
    );
  }
  return value;
}

export { CONTRACTS };
