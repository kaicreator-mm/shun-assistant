import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Real-UAC evidence runs are an explicit operator action: they pop secure
    // desktop prompts and must never fire from `pnpm test` / CI.
    exclude: ['test/evidence/**', '**/node_modules/**'],
    testTimeout: 30000,
  },
});
