import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
export default {
  root,
  resolve: {
    alias: {
      // Same frozen-contract workaround as the T02/T11 suites: the zero-dep
      // domain-computer manifest cannot declare this workspace dependency.
      '@shun/vertical-support': resolve(root, '../../../../packages/vertical-support/src/index.ts'),
      vitest: resolve(root, '../../../../packages/vertical-support/node_modules/vitest'),
    },
  },
  test: { include: ['*.test.ts'], environment: 'node' },
};
