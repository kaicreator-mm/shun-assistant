export const CONTRACTS_REVISION = 'shun.contracts/0.1';
export const SCHEMA_ID_PREFIX = 'urn:shun:contracts:0.1';

export function schemaId(name: string): string {
  return `${SCHEMA_ID_PREFIX}:${name}`;
}
