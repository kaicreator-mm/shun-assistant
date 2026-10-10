// Artifact/parse parity: the committed JSON Schema artifacts must carry every
// safety invariant that draft 2020-12 can express (via the emission overlays in
// scripts/emit-schemas.ts), while the few invariants JSON Schema cannot express
// are enforced by the shared semantic validators each artifact names in its
// `x-semantic-validation` annotation. Benchmark-only envelope schemas (L2 §4.2)
// are covered here too: they live outside the frozen CONTRACTS surface.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import type { ZodType } from 'zod';
import type { ResolutionRecord } from '../src/capabilities/c000.ts';
import { validateResolutionRecordSemantics } from '../src/capabilities/c000.ts';
import { JitBenchmarkInputSchema, JitLifecycleInputSchema } from '../src/capabilities/c002.ts';
import type { StorageDiagnoseOutput } from '../src/capabilities/c003.ts';
import {
  StorageBenchmarkInputSchema,
  StorageDiagnoseInputSchema,
  validateC003OutputSemantics,
} from '../src/capabilities/c003.ts';
import type { ActionPlan } from '../src/plan.ts';
import { validateActionPlanSemantics } from '../src/plan.ts';
import { CONTRACTS } from '../src/registry.ts';
import {
  entryByName,
  INVALID_FIXTURES_DIR,
  invalidFixtureManifest,
  loadFixture,
  validFixturesFor,
} from './helpers.ts';

const SCHEMA_DIR = join(import.meta.dirname, '../src/schema');

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);

const validatorCache = new Map<string, ReturnType<typeof ajv.compile>>();
function artifactValidator(schemaName: string): ReturnType<typeof ajv.compile> {
  const cached = validatorCache.get(schemaName);
  if (cached) return cached;
  const committed = JSON.parse(readFileSync(join(SCHEMA_DIR, `${schemaName}.schema.json`), 'utf8'));
  const compiled = ajv.compile(committed);
  validatorCache.set(schemaName, compiled);
  return compiled;
}

function clone(value: unknown): Record<string, unknown> {
  return structuredClone(value) as Record<string, unknown>;
}

function zodSchemaFor(schemaName: string): ZodType {
  return entryByName(schemaName).schema;
}

function requiredElement<T>(items: T[], why: string): T {
  const item = items[0];
  if (item === undefined) throw new Error(why);
  return item;
}

/**
 * Invariants draft 2020-12 cannot express, so their manifest fixtures are
 * expected to pass the artifact while the Zod parser (and, where exported, the
 * annotated shared validator) rejects them.
 */
const AJV_INEXPRESSIBLE = new Set([
  'action-plan-dangling-bindingref.json',
  'execution-receipt-bad-time-order.json',
]);

describe('artifact/Zod parity: committed artifacts carry the safety invariants', () => {
  it.each(CONTRACTS.map((c) => c.name))(
    '%s: committed artifact compiles under Ajv (draft 2020-12 + formats)',
    (name) => {
      expect(() => artifactValidator(name)).not.toThrow();
    },
  );

  for (const entry of CONTRACTS) {
    for (const fixture of validFixturesFor(entry)) {
      it(`valid ${fixture.file} passes the committed artifact`, () => {
        const validate = artifactValidator(entry.name);
        expect(validate(fixture.json)).toBe(true);
        expect(validate.errors ?? []).toEqual([]);
      });
    }
  }

  for (const [file, expectation] of invalidFixtureManifest()) {
    it(`invalid ${file} is rejected by the committed artifact (or documented as inexpressible)`, () => {
      const raw = JSON.parse(readFileSync(join(INVALID_FIXTURES_DIR, file), 'utf8')) as unknown;
      const validate = artifactValidator(expectation.schema);
      if (AJV_INEXPRESSIBLE.has(file)) {
        // Not expressible in draft 2020-12: the artifact alone cannot reject it,
        // so the Zod parser must (receipts.ts exports no shared validator;
        // action-plan's is exercised by the annotation tests below).
        expect(zodSchemaFor(expectation.schema).safeParse(raw).success).toBe(false);
      } else {
        expect(validate(raw)).toBe(false);
      }
    });
  }

  it('valid fixtures satisfy the exported shared semantic validators', () => {
    for (const fixture of validFixturesFor(entryByName('c000-resolution-record'))) {
      const parsed = zodSchemaFor('c000-resolution-record').parse(fixture.json);
      expect(validateResolutionRecordSemantics(parsed as ResolutionRecord)).toEqual([]);
    }
    for (const fixture of validFixturesFor(entryByName('c003-storage-diagnose-output'))) {
      const parsed = zodSchemaFor('c003-storage-diagnose-output').parse(fixture.json);
      expect(validateC003OutputSemantics(parsed as StorageDiagnoseOutput)).toEqual([]);
    }
    for (const fixture of validFixturesFor(entryByName('action-plan'))) {
      const parsed = zodSchemaFor('action-plan').parse(fixture.json);
      expect(validateActionPlanSemantics(parsed as ActionPlan)).toEqual([]);
    }
  });
});

/**
 * Mutation negatives for every overlay invariant: each case starts from a valid
 * fixture, breaks exactly one invariant, and must be rejected by the committed
 * artifact itself (not only by the Zod parser).
 */
const OVERLAY_MUTATIONS: {
  name: string;
  schema: string;
  fixture: string;
  mutate: (value: Record<string, unknown>) => void;
}[] = [
  {
    name: 'c000: setting both selectedBindingId and failureDisposition is rejected',
    schema: 'c000-resolution-record',
    fixture: 'valid/c000-resolution-record/selected.json',
    mutate: (value) => {
      value.failureDisposition = { failureCode: 'NO_FEASIBLE_BINDING', detail: 'contradiction' };
    },
  },
  {
    name: 'c000: nulling both selectedBindingId and failureDisposition is rejected',
    schema: 'c000-resolution-record',
    fixture: 'valid/c000-resolution-record/selected.json',
    mutate: (value) => {
      value.selectedBindingId = null;
    },
  },
  {
    name: 'c001: WRITTEN record without outputPath is rejected',
    schema: 'c001-image-batch-process-output',
    fixture: 'valid/c001-image-batch-process-output/mixed.json',
    mutate: (value) => {
      const records = value.records as Record<string, unknown>[];
      const written = records.find((record) => record.status === 'WRITTEN');
      if (!written) throw new Error('fixture must contain a WRITTEN record');
      delete written.outputPath;
    },
  },
  {
    name: 'c001: REJECTED record without rejectionCode is rejected',
    schema: 'c001-image-batch-process-output',
    fixture: 'valid/c001-image-batch-process-output/mixed.json',
    mutate: (value) => {
      const records = value.records as Record<string, unknown>[];
      const rejected = records.find((record) => record.status === 'REJECTED');
      if (!rejected) throw new Error('fixture must contain a REJECTED record');
      delete rejected.rejectionCode;
    },
  },
  {
    name: 'c002: REMOVED finalState without an r2Gate is rejected',
    schema: 'c002-jit-lifecycle-output',
    fixture: 'valid/c002-jit-lifecycle-output/removed.json',
    mutate: (value) => {
      delete value.r2Gate;
    },
  },
  {
    name: 'c002: truncated R2 gate phase sequence is rejected',
    schema: 'c002-jit-lifecycle-output',
    fixture: 'valid/c002-jit-lifecycle-output/removed.json',
    mutate: (value) => {
      const gate = value.r2Gate as Record<string, unknown>;
      gate.phases = ['PLAN', 'PREVIEW', 'CHECKPOINT', 'APPROVAL', 'EXECUTE'];
    },
  },
  {
    name: 'c002: reordered R2 gate phase sequence is rejected',
    schema: 'c002-jit-lifecycle-output',
    fixture: 'valid/c002-jit-lifecycle-output/removed.json',
    mutate: (value) => {
      const gate = value.r2Gate as Record<string, unknown>;
      gate.phases = ['PLAN', 'PREVIEW', 'CHECKPOINT', 'EXECUTE', 'APPROVAL', 'VERIFY'];
    },
  },
  {
    name: 'c002: gate record without approvedBy is rejected',
    schema: 'c002-jit-lifecycle-output',
    fixture: 'valid/c002-jit-lifecycle-output/removed.json',
    mutate: (value) => {
      delete (value.r2Gate as Record<string, unknown>).approvedBy;
    },
  },
  {
    name: 'c002: USER_CREATED_UNKNOWN residue with disposition DELETE is rejected',
    schema: 'c002-jit-lifecycle-output',
    fixture: 'valid/c002-jit-lifecycle-output/removed.json',
    mutate: (value) => {
      const candidates = (value.residueReport as Record<string, unknown>).candidates as Record<
        string,
        unknown
      >[];
      const candidate = candidates.find((c) => c.classification === 'USER_CREATED_UNKNOWN');
      if (!candidate) throw new Error('fixture must contain a USER_CREATED_UNKNOWN candidate');
      candidate.disposition = 'DELETE';
    },
  },
  {
    name: 'c002: PROTECTED residue with disposition DELETE is rejected',
    schema: 'c002-jit-lifecycle-output',
    fixture: 'valid/c002-jit-lifecycle-output/removed.json',
    mutate: (value) => {
      const candidates = (value.residueReport as Record<string, unknown>).candidates as Record<
        string,
        unknown
      >[];
      candidates.push({
        path: 'C:\\fixtures\\protected\\photos',
        classification: 'PROTECTED',
        disposition: 'DELETE',
      });
    },
  },
  {
    name: 'c003: executed cleanup plan without executionEvidence is rejected',
    schema: 'c003-storage-diagnose-output',
    fixture: 'valid/c003-storage-diagnose-output/cleanup-executed.json',
    mutate: (value) => {
      delete value.executionEvidence;
    },
  },
  {
    name: 'c003: executed cleanup plan without reclaimed measurement is rejected',
    schema: 'c003-storage-diagnose-output',
    fixture: 'valid/c003-storage-diagnose-output/cleanup-executed.json',
    mutate: (value) => {
      delete value.reclaimed;
    },
  },
  {
    name: 'c003: PROTECTED cleanup target is rejected',
    schema: 'c003-storage-diagnose-output',
    fixture: 'valid/c003-storage-diagnose-output/cleanup-executed.json',
    mutate: (value) => {
      const targets = (value.cleanupPlan as Record<string, unknown>).targets as Record<
        string,
        unknown
      >[];
      requiredElement(targets, 'fixture must contain a cleanup target').classification =
        'PROTECTED';
    },
  },
  {
    name: 'c003: USER_CREATED_UNKNOWN cleanup target is rejected',
    schema: 'c003-storage-diagnose-output',
    fixture: 'valid/c003-storage-diagnose-output/cleanup-executed.json',
    mutate: (value) => {
      const targets = (value.cleanupPlan as Record<string, unknown>).targets as Record<
        string,
        unknown
      >[];
      requiredElement(targets, 'fixture must contain a cleanup target').classification =
        'USER_CREATED_UNKNOWN';
    },
  },
  {
    name: 'c003: truncated R2 gate phase sequence is rejected',
    schema: 'c003-storage-diagnose-output',
    fixture: 'valid/c003-storage-diagnose-output/cleanup-executed.json',
    mutate: (value) => {
      const gate = (value.cleanupPlan as Record<string, unknown>).r2Gate as Record<string, unknown>;
      gate.phases = ['PLAN'];
    },
  },
];

describe('overlay invariants are enforced by the artifact itself', () => {
  for (const mutation of OVERLAY_MUTATIONS) {
    it(mutation.name, () => {
      const mutated = clone(loadFixture(mutation.fixture));
      mutation.mutate(mutated);

      const validate = artifactValidator(mutation.schema);
      expect(validate(mutated)).toBe(false);
      // The Zod parser rejects the same mutation (belt and suspenders).
      expect(zodSchemaFor(mutation.schema).safeParse(mutated).success).toBe(false);
    });
  }
});

describe('x-semantic-validation annotations close the inexpressible gap', () => {
  it('action-plan: dangling bindingRef passes the artifact but the annotated validator rejects it', () => {
    const raw = loadFixture('invalid/action-plan-dangling-bindingref.json');
    expect(artifactValidator('action-plan')(raw)).toBe(true);
    expect(zodSchemaFor('action-plan').safeParse(raw).success).toBe(false);
    expect(validateActionPlanSemantics(raw as ActionPlan).length).toBeGreaterThan(0);
  });

  it('c000: selectedBindingId outside feasibleBindings passes the artifact but the annotated validator rejects it', () => {
    const mutated = clone(loadFixture('valid/c000-resolution-record/selected.json'));
    mutated.selectedBindingId = 'binding-not-in-feasible-list';
    expect(artifactValidator('c000-resolution-record')(mutated)).toBe(true);
    expect(zodSchemaFor('c000-resolution-record').safeParse(mutated).success).toBe(false);
    expect(validateResolutionRecordSemantics(mutated as ResolutionRecord).length).toBeGreaterThan(
      0,
    );
  });

  it('c003: duplicate protected-asset verification passes the artifact but the annotated validator rejects it', () => {
    const mutated = clone(loadFixture('valid/c003-storage-diagnose-output/cleanup-executed.json'));
    const verification = mutated.protectedAssetVerification as Record<string, unknown>[];
    const first = requiredElement(
      verification,
      'fixture must contain protected-asset verification',
    );
    verification.push({ ...first });
    expect(artifactValidator('c003-storage-diagnose-output')(mutated)).toBe(true);
    expect(zodSchemaFor('c003-storage-diagnose-output').safeParse(mutated).success).toBe(false);
    expect(validateC003OutputSemantics(mutated as StorageDiagnoseOutput).length).toBeGreaterThan(0);
  });
});

describe('benchmark envelopes keep hidden harness truth out of production inputs (L2 §4.2)', () => {
  it('c002: production input rejects the benchmark-only preExistingUserAssets; the envelope accepts them', () => {
    const production = loadFixture('valid/c002-jit-lifecycle-input/jit-remove.json');

    const benchmark = clone(production);
    benchmark.preExistingUserAssets = [{ path: 'C:\\fixtures\\user-assets\\notes.txt' }];
    expect(JitLifecycleInputSchema.safeParse(benchmark).success).toBe(false);
    expect(JitBenchmarkInputSchema.safeParse(benchmark).success).toBe(true);
    // The envelope is strictly additive: it still requires every production field.
    expect(JitBenchmarkInputSchema.safeParse(production).success).toBe(false);
  });

  it('c003: production input rejects growthFixture/baselineSha256; the benchmark envelope requires them', () => {
    const production = loadFixture('valid/c003-storage-diagnose-input/basic.json');

    const benchmark = clone(production);
    benchmark.growthFixture = { kind: 'SYNTHETIC', injectorRef: 'harness://growth-injector-07' };
    const assets = benchmark.protectedAssets as Record<string, unknown>[];
    requiredElement(assets, 'fixture must contain a protected asset').baselineSha256 =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(StorageDiagnoseInputSchema.safeParse(benchmark).success).toBe(false);
    expect(StorageBenchmarkInputSchema.safeParse(benchmark).success).toBe(true);
    // The envelope is strictly additive: it still requires every production field.
    expect(StorageBenchmarkInputSchema.safeParse(production).success).toBe(false);
  });

  it('c003: the benchmark envelope still validates the precommitted baseline format', () => {
    const benchmark = clone(loadFixture('valid/c003-storage-diagnose-input/basic.json'));
    benchmark.growthFixture = { kind: 'REPRODUCIBLE' };
    const assets = benchmark.protectedAssets as Record<string, unknown>[];
    requiredElement(assets, 'fixture must contain a protected asset').baselineSha256 = 'not-a-hash';
    expect(StorageBenchmarkInputSchema.safeParse(benchmark).success).toBe(false);
  });
});
