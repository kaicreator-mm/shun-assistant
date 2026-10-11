import { z } from 'zod';

export const SupportObservationSchema = z.strictObject({
  os: z.strictObject({
    name: z.string().min(1),
    build: z.string().min(1),
  }),
  device: z.strictObject({
    model: z.string().min(1),
  }),
  updates: z.strictObject({
    last_check: z.string().min(1),
  }),
  env: z.record(z.string(), z.string()).optional(),
  processes: z
    .array(
      z.strictObject({
        name: z.string().min(1),
        command_line: z.string().optional(),
      }),
    )
    .optional(),
  unrelated_document: z.string().optional(),
});
export type SupportObservation = z.infer<typeof SupportObservationSchema>;

export const RedactionRecordSchema = z.strictObject({
  field: z.string().min(1),
  marker: z.literal('[REDACTED]'),
});
export type RedactionRecord = z.infer<typeof RedactionRecordSchema>;

export const SupportReportSchema = z.strictObject({
  schema: z.literal('shun.support-context.v1'),
  os: SupportObservationSchema.shape.os,
  device: SupportObservationSchema.shape.device,
  updates: SupportObservationSchema.shape.updates,
  redactions: z.array(RedactionRecordSchema),
});
export type SupportReport = z.infer<typeof SupportReportSchema>;

export const SupportContextResultSchema = z.strictObject({
  report: SupportReportSchema,
  localOnly: z.literal(true),
  externalDisclosures: z.tuple([]),
});
export type SupportContextResult = z.infer<typeof SupportContextResultSchema>;
