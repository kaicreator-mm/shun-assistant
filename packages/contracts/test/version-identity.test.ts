import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONTRACTS } from '../src/registry.ts';
import { CONTRACTS_REVISION, schemaId } from '../src/version.ts';

const SCHEMA_DIR = join(import.meta.dirname, '../src/schema');

/** The frozen T00 public schema surface — changes here are contract changes. */
const FROZEN_SURFACE = [
  'action-plan',
  'authorization-authority',
  'authorization-grant',
  'authorized-action',
  'c000-resolution-record',
  'c001-image-batch-process-input',
  'c001-image-batch-process-output',
  'c002-jit-lifecycle-input',
  'c002-jit-lifecycle-output',
  'c003-storage-diagnose-input',
  'c003-storage-diagnose-output',
  'capability-definition',
  'current-authority-state',
  'environment-facts',
  'execution-receipt',
  'goal-contract',
  'goal-request',
  'provider-capability-binding',
  'provider-definition',
  'provider-environment-binding',
  'verification-receipt',
].sort();

describe('contract version identity', () => {
  it('exposes the frozen contracts revision', () => {
    expect(CONTRACTS_REVISION).toBe('shun.contracts/0.1');
  });

  it('covers exactly the frozen T00 public schema surface', () => {
    expect(CONTRACTS.map((c) => c.name).sort()).toEqual(FROZEN_SURFACE);
  });

  it.each(CONTRACTS.map((c) => c.name))('%s: committed artifact carries exact identity', (name) => {
    const file = join(SCHEMA_DIR, `${name}.schema.json`);
    expect(existsSync(file), `${file} must exist`).toBe(true);
    const json = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    expect(json.$id).toBe(schemaId(name));
    expect(json.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(json.title).toBe(name);
    expect(json['x-contracts-revision']).toBe(CONTRACTS_REVISION);
  });

  it('schema ids are urn-stable and version-bound', () => {
    expect(schemaId('action-plan')).toBe('urn:shun:contracts:0.1:action-plan');
  });
});
