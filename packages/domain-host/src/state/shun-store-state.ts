/**
 * T01 — ShunStore business-state adapter for K-mediated writes.
 *
 * This is deliberately NOT a second journal or physical-effect dispatcher.
 * It delegates to the existing ShunStore.apply(effectId, mutation) transaction
 * and receipt table. The effectId is read from K's dispatch context, never
 * accepted as a separate caller field.
 */
import { readKernelEffectPermit } from '../windows/effect-host.ts';

export interface ShunStoreBusinessPort {
  apply(effectId: string, mutation: unknown): Promise<unknown>;
  getEffectReceipt(effectId: string): Promise<unknown>;
}

export function createShunStoreStateAdapter(
  store: ShunStoreBusinessPort,
  binding: Readonly<{ capabilityId: string; operationId: string }>,
) {
  if (
    typeof store?.apply !== 'function' ||
    typeof store?.getEffectReceipt !== 'function' ||
    !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(binding?.capabilityId ?? '') ||
    !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(binding?.operationId ?? '')
  ) {
    throw new TypeError('SHUN_STORE_STATE_CONFIGURATION_REFUSED');
  }

  // Snapshot the trusted store methods and freeze the binding copy exactly
  // once; later mutation of the supplied objects must not swap the business
  // write or receipt readback behind a validated adapter.
  const applyBusinessEffect = store.apply.bind(store);
  const readEffectReceipt = store.getEffectReceipt.bind(store);
  const frozenBinding = Object.freeze({
    capabilityId: binding.capabilityId,
    operationId: binding.operationId,
  });

  return Object.freeze({
    async applyBusinessMutation(context: unknown, mutation: unknown): Promise<unknown> {
      const permit = readKernelEffectPermit(context, frozenBinding);
      if (!permit) throw new Error('K_PERMIT_REQUIRED');
      return applyBusinessEffect(permit.effectId, mutation);
    },

    async readBusinessReceipt(effectId: string): Promise<unknown> {
      if (typeof effectId !== 'string' || !/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/.test(effectId)) {
        throw new Error('SHUN_STORE_EFFECT_ID_INVALID');
      }
      return readEffectReceipt(effectId);
    },
  });
}
