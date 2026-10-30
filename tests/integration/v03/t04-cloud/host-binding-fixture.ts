import {
  createTrustedCloudHostBinding,
  type TrustedCloudHostBindingConfig,
} from '../../../../packages/domain-host/src/cloud/openai-host.ts';

let active: ReturnType<typeof createTrustedCloudHostBinding> | undefined;

export function configureFakeHost(config: TrustedCloudHostBindingConfig): void {
  active = createTrustedCloudHostBinding(config);
}

export function resetFakeHost(): void {
  active = undefined;
}

export async function generate(input: unknown) {
  if (!active) throw new Error('TEST_HOST_BINDING_NOT_CONFIGURED');
  return active.generate(input);
}
