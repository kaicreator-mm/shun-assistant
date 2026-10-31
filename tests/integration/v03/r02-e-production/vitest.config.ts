import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { consumerDir, ensureV03SdkConsumer } from '../r02-a-build/ensure-consumer.mjs';

const root = dirname(fileURLToPath(import.meta.url));

// The REAL installed public SDK consumer (v0.10.3 tag tarballs) plus the
// trusted domain-harness-openai-host binding to the T04 static entry.
ensureV03SdkConsumer();
const sdk = (name: string, sub: string) => join(consumerDir, 'node_modules/@kaicreator', name, sub);

export default {
  root,
  resolve: {
    alias: {
      // Order matters: the host-seam subpath must win over the bare package.
      '@kaicreator/domain-harness-microkernel/host-seam': sdk(
        'domain-harness-microkernel',
        'dist/host-seam.js',
      ),
      '@kaicreator/domain-harness-microkernel': sdk('domain-harness-microkernel', 'dist/index.js'),
      '@kaicreator/domain-harness-build': sdk('domain-harness-build', 'dist/index.js'),
      '@kaicreator/domain-harness-host-node': sdk('domain-harness-host-node', 'dist/index.js'),
      '@kaicreator/domain-harness-contracts': sdk('domain-harness-contracts', 'dist/index.js'),
      'domain-harness-openai-host': join(
        consumerDir,
        'node_modules/domain-harness-openai-host/index.mjs',
      ),
      vitest: resolve(root, '../../../../packages/vertical-support/node_modules/vitest'),
    },
  },
  test: { include: ['*.test.ts'], environment: 'node', testTimeout: 300_000, hookTimeout: 300_000 },
};
