import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));

export default {
  root,
  resolve: {
    alias: {
      '@shun/contracts': resolve(root, '../../../../packages/contracts/src/index.ts'),
      'domain-harness-openai-host': resolve(root, './host-binding-fixture.ts'),
      vitest: resolve(root, '../../../../packages/llm-remote/node_modules/vitest'),
    },
  },
  test: {
    include: ['*.test.ts'],
    environment: 'node',
  },
};
