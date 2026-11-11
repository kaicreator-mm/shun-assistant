/**
 * Type-only declaration for the trusted consumer binding package staged by
 * ensure-consumer.mjs (runtime resolves through the vitest alias to the
 * installed consumer layout, exactly as the sealed capability resolves it
 * from the deployment root).
 */
declare module 'domain-harness-openai-host' {
  export function generate(input: unknown): Promise<unknown>;
  export function installTrustedCloudHostBinding(config: unknown): void;
  export function createTrustedCloudHostBinding(config: unknown): Readonly<{
    generate(input: unknown): Promise<unknown>;
  }>;
}
