/**
 * v0.3 T11 — Shun-owned external Effect Capability module for the Windows
 * Host boundary.
 * =====================================================================
 *
 * One sealed external Effect Operation `windows.execute` behind the
 * module-wide `externalEffect: true` classification. Every dispatch reaches
 * this module ONLY through the selected K→C external Effect gate holding a
 * live kernel-issued permit; the gate hands (adapterPayload, dispatchContext)
 * to the T01 `createWindowsEffectHost().dispatch` binding, which is supplied
 * by the trusted deployment through the declared bare import
 * `shun-windows-effect-host` (staged in the deployment root's node_modules —
 * the sealed App bytes never carry Host authority).
 *
 * Kernel ABI: v08-capability-abi/1.
 */
import { windowsExecute } from 'shun-windows-effect-host';

export const MODULE_ID = 'capability-windows-effect@v030.1.0.0';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const ENDPOINTS = [{ endpointId: 'capability:windows', kind: 'capability-endpoint' }];
export const CAPABILITY_ID = 'windows';
export const EXTERNAL_EFFECT = true;
export const HANDLERS = [{ operationId: 'windows.execute', handler: 'windowsExecute' }];

export { windowsExecute };
