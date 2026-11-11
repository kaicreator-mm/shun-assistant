import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // The Windows E2E suite renames the committed native addon away to prove
    // fail-closed loading in a fresh process; a parallel test file (e.g. the
    // npm pack probe) would race against that rename window and see the
    // addon missing. Keep test file execution sequential so shared package
    // state is never mutated under a concurrent probe.
    fileParallelism: false,
  },
});
