import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function tempStoreFile(): string {
  return join(mkdtempSync(join(tmpdir(), 'shun-store-')), 'shunstore.db');
}
