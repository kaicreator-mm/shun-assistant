import { defineConfig } from 'vitest/config';

// Evidence suite: real Windows 11 / UAC positive+negative runs (Issue #15
// required evidence). Gated behind SHUN_EXECUTOR_EVIDENCE=1 so an accidental
// `vitest run` never spawns UAC prompts; see test/evidence/README.md.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/evidence/**/*.evidence.test.ts'],
    testTimeout: 300000,
    hookTimeout: 120000,
  },
});
