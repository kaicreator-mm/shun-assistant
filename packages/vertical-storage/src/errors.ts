// Typed failures for the Loop C storage vertical. Codes are the frozen C-003
// taxonomy (packages/contracts taxonomy.ts STORAGE_DIAGNOSE_FAILURES) — never
// invented locally, never stringly-typed at call sites.
import { StorageDiagnoseFailureSchema } from '@shun/contracts';
import type { z } from 'zod';

export class StorageVerticalError extends Error {
  readonly code: z.infer<typeof StorageDiagnoseFailureSchema>;
  readonly detail: string;

  constructor(code: z.infer<typeof StorageDiagnoseFailureSchema>, detail: string) {
    super(`storage vertical ${code}: ${detail}`);
    this.name = 'StorageVerticalError';
    this.code = StorageDiagnoseFailureSchema.parse(code);
    this.detail = detail;
  }
}
