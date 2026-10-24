// T04 trusted private, non-elevated Windows R0 file.search effect adapter.
// Never expose this module through @shun/recipe-runtime package root or to
// Recipe/model/HTTP. The caller must first pass the real SQLite grant gate,
// durably reserve STARTED, and handle uncertain post-state without retry.
import {
  type AuthorizedAction,
  canonicalJson,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import { type LocalFileSearchObservation, observeScopedFileSearch } from './scoped-file-search.ts';

const REFUSED = 'R0_NATIVE_EFFECT_UNCERTAIN';
const PROVIDER_VERSION = '0.2.0';

function verifiedLocalShape(input: LocalFileSearchObservation): boolean {
  return (
    input.kind === 'R0_LOCAL_FILE_SEARCH_OBSERVATION' &&
    input.truncated === false &&
    input.semanticVerified === false &&
    input.cloudDisclosure === false &&
    Number.isSafeInteger(input.inspectedEntries) &&
    input.inspectedEntries >= 0 &&
    input.inspectedEntries <= 4096 &&
    Array.isArray(input.paths) &&
    input.paths.length <= 128 &&
    input.paths.every(
      (path) =>
        typeof path === 'string' &&
        path.length > 0 &&
        !path.startsWith('\\') &&
        !path.startsWith('/') &&
        !path.includes('\0') &&
        !path.split(/[\\/]/).includes('..'),
    )
  );
}

/**
 * Performs one actual Win32 handle-anchored search, then independently
 * re-scans the SAME approved scope to validate the bounded observation
 * against current native OS state. Any mismatch, revocation by the outer
 * boundary, failure or race is UNKNOWN; no automatic retry is authorized.
 *
 * The second read is verification of the local R0 scan's observed post-state,
 * NOT an independent Task semantic oracle. No file contents or absolute paths
 * are placed in the execution receipt or sent to a provider/cloud.
 */
export async function executeVerifiedNativeR0Search(
  action: AuthorizedAction,
): Promise<ExecutionReceipt> {
  try {
    if (process.platform !== 'win32') throw new Error(REFUSED);
    const startedAt = new Date().toISOString();
    const initial = observeScopedFileSearch(action);
    if (!verifiedLocalShape(initial)) throw new Error(REFUSED);
    const verified = observeScopedFileSearch(action);
    if (!verifiedLocalShape(verified) || canonicalJson(initial) !== canonicalJson(verified))
      throw new Error(REFUSED);
    const endedAt = new Date(Math.max(Date.now(), Date.parse(startedAt))).toISOString();
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: 'local-windows-user',
      providerId: 'shun-win32-r0-native',
      providerVersion: PROVIDER_VERSION,
      startedAt,
      finishedAt: endedAt,
      terminal: 'SUCCEEDED',
      outputRefs: [],
      sideEffectEvidence: {
        sideEffectClass: 'R0',
        recoveryClassification: 'COMPLETED_VERIFIED',
        postStateVerified: true,
      },
    });
  } catch {
    // Never disclose paths/contents, native exceptions or partial results.
    throw new Error(REFUSED);
  }
}
