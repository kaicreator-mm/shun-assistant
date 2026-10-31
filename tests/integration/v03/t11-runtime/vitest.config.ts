import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));

export default {
  root,
  resolve: {
    alias: {
      // The zero-dep domain-computer manifest cannot declare this workspace
      // dep; the T02 suite aliases it the same way (frozen-contract workaround,
      // not a dependency change).
      '@shun/vertical-support': resolve(root, '../../../../packages/vertical-support/src/index.ts'),
      vitest: resolve(root, '../../../../packages/vertical-support/node_modules/vitest'),
    },
  },
  test: {
    include: ['*.test.ts'],
    environment: 'node',
    testTimeout: 300_000,
    hookTimeout: 300_000,
  },
};
