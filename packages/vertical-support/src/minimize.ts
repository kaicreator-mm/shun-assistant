import {
  type RedactionRecord,
  type SupportContextResult,
  SupportContextResultSchema,
  SupportObservationSchema,
} from './schema.ts';

const REDACTED = '[REDACTED]' as const;
const SENSITIVE_WORD = /token|secret|password|passwd|private[_ -]?key|api[_ -]?key/i;
const WINDOWS_ABSOLUTE_PATH = /(?:[a-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+)/i;
const PEM_LIKE = /-----BEGIN [A-Z0-9 _-]+-----/i;
const BENCHMARK_LIKE_OPAQUE = /(?:_[A-Z0-9]{2,}){2,}/i;

function marker(field: string): RedactionRecord {
  return { field, marker: REDACTED };
}

function unsafeOutbound(value: string): boolean {
  return (
    value.length > 256 ||
    /[\r\n\0]/.test(value) ||
    SENSITIVE_WORD.test(value) ||
    WINDOWS_ABSOLUTE_PATH.test(value) ||
    PEM_LIKE.test(value) ||
    BENCHMARK_LIKE_OPAQUE.test(value)
  );
}

function outbound(
  value: string,
  field: string,
  redactions: RedactionRecord[],
): string {
  if (!unsafeOutbound(value)) {
    return value;
  }
  redactions.push(marker(field));
  return REDACTED;
}

/**
 * Frozen B-040 minimization boundary.
 *
 * Only OS/build, device model and update status are reportable. Every outbound
 * string is classified before release. Environment values/key names, process
 * metadata/command lines and unrelated document bodies are never copied into
 * the report; only bounded structural audit IDs survive.
 */
export function minimizeSupportContext(raw: unknown): SupportContextResult {
  const observed = SupportObservationSchema.parse(raw);
  const redactions: RedactionRecord[] = [];

  const envCount = Object.keys(observed.env ?? {}).length;
  for (let index = 0; index < envCount; index += 1) {
    redactions.push(marker(`env[${index}].value`));
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
      os: {
        name: outbound(observed.os.name, 'os.name', redactions),
        build: outbound(observed.os.build, 'os.build', redactions),
      },
      device: {
        model: outbound(observed.device.model, 'device.model', redactions),
      },
      updates: {
        last_check: outbound(observed.updates.last_check, 'updates.last_check', redactions),
      },
      redactions,
    },
    localOnly: true,
    externalDisclosures: [],
  });
}
