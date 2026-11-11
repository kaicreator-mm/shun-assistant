import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));

export default {
  root,
  resolve: {
    alias: {
      '@shun/vertical-support': resolve(root, '../../../../packages/vertical-support/src/index.ts'),
      vitest: resolve(root, '../../../../packages/vertical-support/node_modules/vitest'),
    },
  },
  test: {
    include: ['*.test.ts'],
    environment: 'node',
  },
};
