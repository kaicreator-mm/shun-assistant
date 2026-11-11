/**
 * Shun v0.3 external Effect Capability — Windows Host boundary (R03-INT).
 * Promoted from the kernel-validated T11 fixture to a trusted production
 * module under OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE. Every dispatch
 * reaches this module ONLY through the selected K external Effect gate; the
 * bare import resolves to the composition-installed trusted Host binding
 * (shun-windows-effect-host) which owns the real ActionController chain.
 */
import { windowsExecute } from 'shun-windows-effect-host';

export const MODULE_ID = 'shun.capability.windows-executor@v0.3.0';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const ENDPOINTS = [{ endpointId: 'capability:windows', kind: 'capability-endpoint' }];
export const CAPABILITY_ID = 'windows';
export const EXTERNAL_EFFECT = true;
export const HANDLERS = [{ operationId: 'windows.execute', handler: 'windowsExecute' }];

export { windowsExecute };
