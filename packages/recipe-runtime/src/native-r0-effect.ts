// T04 trusted private, non-elevated Windows R0 file.search adapter.
// The REAL SQLite grant+current policy gate must authorize it AND durably
// reserve STARTED before invocation. No public Recipe/model/HTTP entry.
// A completed native scan alone cannot prove L2 independent post-state,
// receipt phase, or Task semantics: ALL outcomes remain UNCERTAIN until the
// separate trusted Host verifier and journal provenance are qualified.
import {
  type AuthorizedAction,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import { type LocalFileSearchObservation, observeScopedFileSearch } from './scoped-file-search.ts';

const REFUSED = 'R0_NATIVE_EFFECT_UNCERTAIN';
const PROVIDER_VERSION = '0.2.0';

export function boundedLocalShape(input: LocalFileSearchObservation): boolean {
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
        !path.split(/[\\\\/]/).includes('..'),
    )
  );
}

/**
 * Runs at most ONE genuine local Win32 handle-anchored scan. It deliberately
 * does not report success or claim an independent post-state verification:
 * the same scanner twice would have common-mode errors and no oracle.
 *
 * The only externally returned record is an UNCERTAIN ExecutionReceipt
 * containing zero filenames, absolute paths or file contents; privileged
 * journal stays STARTED/UNCERTAIN, never replayed or semantic Task PASS.
 * A future independent verifier must bind an immutable expected observation,
 * phase journal and trusted separate OS/host proof before a positive receipt.
 */
export async function executeConservativeNativeR0Search(
  action: AuthorizedAction,
): Promise<ExecutionReceipt> {
  try {
    if (process.platform !== 'win32') throw new Error(REFUSED);
    const startedAt = new Date().toISOString();
    const observation = observeScopedFileSearch(action);
    if (!boundedLocalShape(observation)) throw new Error(REFUSED);
    const finishedAt = new Date(Math.max(Date.now(), Date.parse(startedAt))).toISOString();
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: 'local-windows-user',
      providerId: 'shun-win32-r0-native',
      providerVersion: PROVIDER_VERSION,
      startedAt,
      finishedAt,
      terminal: 'UNCERTAIN',
      outputRefs: [],
      sideEffectEvidence: {
        sideEffectClass: 'R0',
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        postStateVerified: false,
      },
    });
  } catch {
    // Never disclose local paths/content, Native OS error or partial scan.
    throw new Error(REFUSED);
  }
}
