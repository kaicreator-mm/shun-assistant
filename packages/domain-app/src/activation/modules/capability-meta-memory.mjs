/**
 * Shun v0.3 INTERNAL (non-external) Capability — read-only cross-Case Meta
 * shared experience query (R03C, #288). The only static import binds to the
 * trusted composition-installed Meta Host (`shun-meta-host`): the wrapper
 * re-exports a read-only query backed by the exact same durable
 * HostMetaShadowStore instance the feedback binding was installed over.
 *
 * externalEffect stays FALSE: the kernel dispatches this handler directly with
 * zero Permit minting and zero external dispatch. The handler still returns
 * the SAME closed terminal envelope shape every sealed C module returns: a
 * store refusal is an envelope refusal (KERNEL_REFUSED), never an exception
 * across the K boundary. No consent write, no Shadow candidate and no
 * authority of any kind is created by a query.
 */
import { querySharedExperiences as hostQuerySharedExperiences } from 'shun-meta-host';

export const MODULE_ID = 'shun.capability.meta-memory@v0.3.0';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const ENDPOINTS = [{ endpointId: 'capability:shun-meta-memory', kind: 'capability-endpoint' }];
export const CAPABILITY_ID = 'meta-memory';
export const EXTERNAL_EFFECT = false;
export const HANDLERS = [{ operationId: 'meta.querySharedExperiences', handler: 'querySharedExperiences' }];

/**
 * Sealed K→C entry: privacy-minimized verified experiences (advisoryOnly
 * data) or a closed refusal envelope. The #285 store owns every validation
 * rule (vocabulary, currentness, revocation, bounds); nothing is invented here.
 */
export async function querySharedExperiences(payload) {
  try {
    // JSON round-trip: the store marks absent feedback candidates as
    // undefined, which the K canonicalizer (correctly) refuses to marshal.
    // A query result is plain advisory data; dropping absent keys is exact.
    const experiences = JSON.parse(JSON.stringify(hostQuerySharedExperiences(payload)));
    return {
      phase: 'terminal',
      externalRef: 'meta-shared-query',
      outcome: { ok: true, output: experiences },
    };
  } catch (error) {
    return {
      phase: 'terminal',
      externalRef: 'meta-shared-query',
      outcome: {
        ok: false,
        error: {
          code: error instanceof Error ? error.message : 'META_QUERY_REFUSED',
          message: 'trusted Meta Host refused the shared-experience query',
        },
      },
    };
  }
}
