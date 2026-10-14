// Temporary CI-only schema artifact transport; MUST DELETE before merging T00.
import { describe, it } from 'vitest';
import { emitPublicJsonSchema } from '../scripts/emit-schemas.ts';
import { CONTRACTS } from '../src/registry.ts';

describe('temporary frozen v0.2 public schema bytes export', () => {
  it('prints deterministic JSON Schema chunks for author artifact commit', () => {
    for (const contract of CONTRACTS.filter((x) => x.name.startsWith('v02-'))) {
      const json = `${JSON.stringify(emitPublicJsonSchema(contract.name, contract.schema), null, 2)}\n`;
      const bytes = Buffer.from(json, 'utf8').toString('base64');
      for (let i = 0; i < bytes.length; i += 1200) {
        console.log(`V02ARTIFACT:${contract.name}:${i / 1200}:${bytes.slice(i, i + 1200)}:END`);
      }
    }
  });
});
