import {
  type RedactionRecord,
  SupportContextResultSchema,
  SupportObservationSchema,
  type SupportContextResult,
} from './schema.ts';

const REDACTED = '[REDACTED]' as const;

function marker(field: string): RedactionRecord {
  return { field, marker: REDACTED };
}

/**
 * Frozen B-040 minimization boundary.
 *
 * Only OS/build, device model and update status are reportable. Environment
 * values, user paths, process metadata/command lines and unrelated document
 * bodies are intentionally not copied into the report; their field names are
 * retained solely as auditable redaction markers.
 */
export function minimizeSupportContext(raw: unknown): SupportContextResult {
  const observed = SupportObservationSchema.parse(raw);
  const redactions: RedactionRecord[] = [];

  for (const key of Object.keys(observed.env ?? {}).sort()) {
    redactions.push(marker(`env.${key}`));
  }
  for (const [index, process] of (observed.processes ?? []).entries()) {
    redactions.push(marker(`processes[${index}].name`));
    if (process.command_line !== undefined) {
      redactions.push(marker(`processes[${index}].command_line`));
    }
  }
  if (observed.unrelated_document !== undefined) {
    redactions.push(marker('unrelated_document'));
  }

  return SupportContextResultSchema.parse({
    report: {
      schema: 'shun.support-context.v1',
      os: observed.os,
      device: observed.device,
      updates: observed.updates,
      redactions,
    },
    localOnly: true,
    externalDisclosures: [],
  });
}
