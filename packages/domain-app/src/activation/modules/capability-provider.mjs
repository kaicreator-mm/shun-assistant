/**
 * Shun v0.3 external Effect Capability — curated Provider first use (R03-INT).
 * No transport, staging or spawn is constructed here. The only static import
 * binds to the trusted composition-installed CuratedProvider Host
 * (shun-provider-host): real signature verification, per-run staging,
 * invocation-scoped grant and bounded spawn all live in the Host chain.
 */
import { providerFirstUse } from 'shun-provider-host';

export const MODULE_ID = 'shun.capability.provider-first-use@v0.3.0';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const ENDPOINTS = [{ endpointId: 'capability:shun-provider', kind: 'capability-endpoint' }];
export const CAPABILITY_ID = 'provider';
export const EXTERNAL_EFFECT = true;
export const HANDLERS = [{ operationId: 'provider.firstUse', handler: 'providerFirstUse' }];

export { providerFirstUse };
