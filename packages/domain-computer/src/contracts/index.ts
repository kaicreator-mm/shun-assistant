/**
 * Internal non-effectful module entry for the T00 contracts scaffold.
 *
 * The package-level public exports stay reserved to integration owner T11
 * (no package `exports` field and no `src/index.ts` at T00). This module is
 * pure data and markers: importing it must never dispatch an effect, open a
 * transport, or reach a provider. Adapter seams are explicitly
 * NOT_IMPLEMENTED; downstream frozen Tasks (T01–T09, T11) own behavior.
 */

import { SHUN_LLM_GENERATE_CONTRACT_V1 } from './llm-generate-v1.ts';

export * from './llm-generate-v1.ts';

export const ADAPTER_SEAM_NOT_IMPLEMENTED = 'NOT_IMPLEMENTED' as const;

/**
 * Marker shape for the future selected public K→C adapter seam (T04/T11).
 * Returns inert data only; it authorizes nothing and sends nothing.
 */
export interface ShunSelectedCAdapterSeamV1 {
  readonly adapterState: typeof ADAPTER_SEAM_NOT_IMPLEMENTED;
  readonly contractVersion: typeof SHUN_LLM_GENERATE_CONTRACT_V1;
}

export function selectedCAdapterSeam(): ShunSelectedCAdapterSeamV1 {
  return {
    adapterState: ADAPTER_SEAM_NOT_IMPLEMENTED,
    contractVersion: SHUN_LLM_GENERATE_CONTRACT_V1,
  };
}
