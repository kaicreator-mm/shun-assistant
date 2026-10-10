// Regenerates the committed public JSON Schema artifacts in src/schema/ from
// the Zod contract registry. The committed files are the public contract surface;
// a drift test guarantees they stay byte-identical to this emission.
//
// Safety-invariant overlays: Zod `.superRefine` refinements do not survive JSON
// Schema emission, so every safety invariant expressible in draft 2020-12 is
// re-declared here as a declarative patch (if/then/const/enum/required). The
// overlay is part of the emission, which keeps the drift test byte-exact while
// making the committed artifacts themselves reject unsafe records — standalone
// Ajv consumers get the same rejections as the Zod parsers. The few invariants
// draft 2020-12 cannot express (array membership, cross-element identity) are
// enforced by the shared semantic validators each artifact names in its
// `x-semantic-validation` annotation.
import { mkdirSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import { NEVER_AUTO_DELETE_CLASSIFICATIONS } from '../src/capabilities/c002.ts';
import { R2_GATE_PHASES } from '../src/plan.ts';
import { CONTRACTS } from '../src/registry.ts';
import { CONTRACTS_REVISION, schemaId } from '../src/version.ts';

type EmittedSchema = Record<string, unknown>;

/** Draft 2020-12 conditional-evaluation vocabulary. */
function ifThen(ifCondition: EmittedSchema, thenConsequent: EmittedSchema): EmittedSchema {
  return {
    if: ifCondition,
    // biome-ignore lint/suspicious/noThenProperty: JSON Schema conditional keyword, not a thenable
    then: thenConsequent,
  };
}

function propertiesOf(schema: EmittedSchema): EmittedSchema {
  return (schema.properties ?? {}) as EmittedSchema;
}

/** Appends one conditional branch to the schema's root `allOf`. */
function withRootAllOf(schema: EmittedSchema, branch: EmittedSchema): EmittedSchema {
  const allOf = Array.isArray(schema.allOf) ? [...(schema.allOf as EmittedSchema[])] : [];
  allOf.push(branch);
  return { ...schema, allOf };
}

/** `phases` must be exactly the complete ordered observable gate sequence. */
function requireCompleteGateSequence(gate: EmittedSchema): EmittedSchema {
  return {
    ...gate,
    properties: { ...propertiesOf(gate), phases: { const: [...R2_GATE_PHASES] } },
  };
}

/** c000: exactly one of selectedBindingId / failureDisposition is set (both fields are required). */
function overlayResolutionRecord(record: EmittedSchema): EmittedSchema {
  const annotated: EmittedSchema = {
    ...record,
    'x-semantic-validation': ['validateResolutionRecordSemantics'],
  };
  return withRootAllOf(
    withRootAllOf(
      withRootAllOf(
        annotated,
        ifThen(
          {
            properties: { selectedBindingId: { type: 'string' } },
            required: ['selectedBindingId'],
          },
          { properties: { failureDisposition: { type: 'null' } } },
        ),
      ),
      ifThen(
        {
          properties: { failureDisposition: { type: 'object' } },
          required: ['failureDisposition'],
        },
        { properties: { selectedBindingId: { type: 'null' } } },
      ),
    ),
    // At least one disposition is always present (both fields are required, so a
    // property-condition anyOf is an exact "not both null" test).
    {
      anyOf: [
        { properties: { selectedBindingId: { type: 'string' } } },
        { properties: { failureDisposition: { type: 'object' } } },
      ],
    },
  );
}

/** c001: per-record status/field pairing (WRITTEN → outputPath, REJECTED → rejectionCode). */
function overlayImageBatchProcessOutput(output: EmittedSchema): EmittedSchema {
  const props = propertiesOf(output);
  return {
    ...output,
    properties: {
      ...props,
      records: {
        ...(props.records as EmittedSchema),
        items: {
          ...((props.records as EmittedSchema).items as EmittedSchema),
          allOf: [
            ifThen(
              { properties: { status: { const: 'WRITTEN' } }, required: ['status'] },
              { required: ['outputPath'] },
            ),
            ifThen(
              { properties: { status: { const: 'REJECTED' } }, required: ['status'] },
              { required: ['rejectionCode'] },
            ),
          ],
        },
      },
    },
  };
}

/** c002: gate-backed removal and fail-closed residue disposition. */
function overlayJitLifecycleOutput(output: EmittedSchema): EmittedSchema {
  const props = propertiesOf(output);
  const residue = props.residueReport as EmittedSchema;
  const residueProps = propertiesOf(residue);
  const candidates = residueProps.candidates as EmittedSchema;
  return withRootAllOf(
    {
      ...output,
      properties: {
        ...props,
        // A REMOVED final state requires the completed R2 gate record.
        r2Gate: requireCompleteGateSequence(props.r2Gate as EmittedSchema),
        residueReport: {
          ...residue,
          properties: {
            ...residueProps,
            // USER_CREATED_UNKNOWN/PROTECTED candidates are never auto-deleted (fail-closed).
            candidates: {
              ...candidates,
              items: {
                ...(candidates.items as EmittedSchema),
                allOf: [
                  ifThen(
                    {
                      properties: {
                        classification: { enum: [...NEVER_AUTO_DELETE_CLASSIFICATIONS] },
                      },
                      required: ['classification'],
                    },
                    { properties: { disposition: { const: 'RETAIN' } } },
                  ),
                ],
              },
            },
          },
        },
      },
    },
    // A REMOVED final state requires the completed R2 gate record.
    ifThen(
      { properties: { finalState: { const: 'REMOVED' } }, required: ['finalState'] },
      { required: ['r2Gate'] },
    ),
  );
}

/** c003: executed cleanup evidence, disposable-only targets, and the gate sequence. */
function overlayStorageDiagnoseOutput(output: EmittedSchema): EmittedSchema {
  const props = propertiesOf(output);
  const cleanupPlan = props.cleanupPlan as EmittedSchema;
  // cleanupPlan is anyOf[object, null] — patch the object branch only.
  const branches = (cleanupPlan.anyOf as EmittedSchema[]).map((branch) => {
    const branchProps = branch.properties as EmittedSchema | undefined;
    if (!branchProps) return branch;
    return {
      ...branch,
      properties: {
        ...branchProps,
        r2Gate: requireCompleteGateSequence(branchProps.r2Gate as EmittedSchema),
      },
    };
  });
  return withRootAllOf(
    {
      ...output,
      properties: { ...props, cleanupPlan: { ...cleanupPlan, anyOf: branches } },
      'x-semantic-validation': ['validateC003OutputSemantics'],
    },
    // A non-null cleanup plan is an executed bounded action: evidence and reclaim measurement required.
    ifThen(
      { properties: { cleanupPlan: { type: 'object' } }, required: ['cleanupPlan'] },
      { required: ['executionEvidence', 'reclaimed'] },
    ),
  );
}

/** Declarative safety-invariant patches keyed by public schema name. */
const SAFETY_INVARIANT_OVERLAYS: Record<string, (schema: EmittedSchema) => EmittedSchema> = {
  'action-plan': (plan) => ({ ...plan, 'x-semantic-validation': ['validateActionPlanSemantics'] }),
  'c000-resolution-record': overlayResolutionRecord,
  'c001-image-batch-process-output': overlayImageBatchProcessOutput,
  'c002-jit-lifecycle-output': overlayJitLifecycleOutput,
  'c003-storage-diagnose-output': overlayStorageDiagnoseOutput,
};

/** The full public emission for one contract: identity header + Zod emission + safety overlay. */
export function emitPublicJsonSchema(name: string, schema: z.ZodType): EmittedSchema {
  const overlay = SAFETY_INVARIANT_OVERLAYS[name];
  const json = overlay
    ? overlay(z.toJSONSchema(schema) as EmittedSchema)
    : (z.toJSONSchema(schema) as EmittedSchema);
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: schemaId(name),
    title: name,
    'x-contracts-revision': CONTRACTS_REVISION,
    ...json,
  };
}

function main(): void {
  const outDir = join(import.meta.dirname, '../src/schema');
  mkdirSync(outDir, { recursive: true });

  const keep = new Set<string>();
  for (const contract of CONTRACTS) {
    const json = emitPublicJsonSchema(contract.name, contract.schema);
    const file = join(outDir, `${contract.name}.schema.json`);
    writeFileSync(file, `${JSON.stringify(json, null, 2)}\n`, 'utf8');
    keep.add(`${contract.name}.schema.json`);
    console.log(`emitted ${contract.name}.schema.json`);
  }

  for (const name of readdirSync(outDir)) {
    if (!keep.has(name)) {
      unlinkSync(join(outDir, name));
      console.log(`removed stale ${name}`);
    }
  }
}

// Run the emission only when invoked directly (`pnpm emit:schemas`); importing
// modules (drift/parity tests) must not perform filesystem writes.
const invoked = process.argv[1]
  ? import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href
  : false;
if (invoked) {
  main();
}
