/**
 * Shun v0.3 external Effect Capability — opt-in meta feedback (R03-INT).
 * The only static import binds to the trusted composition-installed durable
 * Shadow Host (shun-meta-host). Consent, genuine outcome-receipt binding and
 * the FUTURE_BUILD_SHADOW lifecycle are owned by the real Host store; this
 * C cannot promote, activate or fabricate provenance.
 */
import { submitMetaFeedback } from 'shun-meta-host';

export const MODULE_ID = 'shun.capability.meta-feedback@v0.3.0';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const ENDPOINTS = [{ endpointId: 'capability:shun-meta', kind: 'capability-endpoint' }];
export const CAPABILITY_ID = 'meta';
export const EXTERNAL_EFFECT = true;
export const HANDLERS = [{ operationId: 'meta.submitFeedback', handler: 'submitMetaFeedback' }];

export { submitMetaFeedback };
