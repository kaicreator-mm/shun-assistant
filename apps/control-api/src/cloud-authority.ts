// T08 C03: a tiny read-only adapter to the existing operator-issued authority
// model (real-storage/registry-key-pin.ts). There is NO signing private key,
// policy issuer or trust decision reachable through localhost HTTP. A signed
// short-lived operator file is re-read on every reserve/send currentness gate.
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { verifyPinnedRegistryPublicKey } from './real-storage/registry-key-pin.ts';

export const CLOUD_AUTHORITY_SCHEMA = 'shun.cloud-authority/1' as const;

export type OperatorCloudAuthority = Readonly<{
  schema: typeof CLOUD_AUTHORITY_SCHEMA;
  issuedAt: string;
  expiresAt: string;
  enabled: boolean;
  allowExternalDisclosure: boolean;
  registryRevision: string;
  policyRevision: string;
  scopeRevision: string;
  pricingRevision: string;
  revocationEpoch: number;
  inputMicrosPerToken: number;
  outputMicrosPerToken: number;
  maxInputTokens: number;
  maxOutputTokens: number;
  maxCostMicros: number;
}>;

const BODY_FIELDS = [
  'schema',
  'issuedAt',
  'expiresAt',
  'enabled',
  'allowExternalDisclosure',
  'registryRevision',
  'policyRevision',
  'scopeRevision',
  'pricingRevision',
  'revocationEpoch',
  'inputMicrosPerToken',
  'outputMicrosPerToken',
  'maxInputTokens',
  'maxOutputTokens',
  'maxCostMicros',
];
const MAX_AGE_MS = 5 * 60_000;
const CLOCK_SKEW_MS = 5_000;
const POSITIVE_FIELDS = [
  'inputMicrosPerToken',
  'outputMicrosPerToken',
  'maxInputTokens',
  'maxOutputTokens',
  'maxCostMicros',
] as const;
const REVISION_FIELDS = [
  'registryRevision',
  'policyRevision',
  'scopeRevision',
  'pricingRevision',
] as const;

function refuse(): never {
  throw new Error('CLOUD_AUTHORITY_UNAVAILABLE');
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isIso(s: unknown): s is string {
  return (
    typeof s === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s) &&
    Number.isFinite(Date.parse(s)) &&
    new Date(Date.parse(s)).toISOString() === s
  );
}

export function verifyOperatorCloudAuthority(
  raw: unknown,
  publicKeyPem: string,
  pinnedSpkiSha256: string,
  nowMs = Date.now(),
): OperatorCloudAuthority {
  try {
    if (!isObject(raw)) return refuse();
    const keys = Object.keys(raw).sort();
    if (keys.join('|') !== [...BODY_FIELDS, 'signature'].sort().join('|')) return refuse();
    if (
      raw.schema !== CLOUD_AUTHORITY_SCHEMA ||
      raw.enabled !== true ||
      raw.allowExternalDisclosure !== true ||
      !isIso(raw.issuedAt) ||
      !isIso(raw.expiresAt) ||
      !Number.isSafeInteger(nowMs)
    ) {
      return refuse();
    }
    const issuedAt = Date.parse(raw.issuedAt);
    const expiresAt = Date.parse(raw.expiresAt);
    if (
      issuedAt > nowMs + CLOCK_SKEW_MS ||
      nowMs >= expiresAt ||
      expiresAt <= issuedAt ||
      expiresAt - issuedAt > MAX_AGE_MS
    ) {
      return refuse();
    }
    if (
      !REVISION_FIELDS.every(
        (field) => typeof raw[field] === 'string' && /^[A-Za-z0-9._:/-]{1,128}$/.test(raw[field]),
      )
    ) {
      return refuse();
    }
    if (
      !Number.isSafeInteger(raw.revocationEpoch) ||
      (raw.revocationEpoch as number) < 0 ||
      !POSITIVE_FIELDS.every(
        (field) => Number.isSafeInteger(raw[field]) && (raw[field] as number) > 0,
      )
    ) {
      return refuse();
    }
    const expectedWorstCost =
      BigInt(raw.maxInputTokens as number) * BigInt(raw.inputMicrosPerToken as number) +
      BigInt(raw.maxOutputTokens as number) * BigInt(raw.outputMicrosPerToken as number);
    if (
      expectedWorstCost > BigInt(raw.maxCostMicros as number) ||
      expectedWorstCost > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      return refuse();
    }
    if (typeof raw.signature !== 'string' || !/^[a-zA-Z0-9+/]{86}==$/.test(raw.signature)) {
      return refuse();
    }
    // Existing trusted host public-key fingerprint verifier; a file-supplied
    // public key or unsigned digest must never establish its own authority.
    verifyPinnedRegistryPublicKey(publicKeyPem, pinnedSpkiSha256);
    const body: Record<string, unknown> = {};
    for (const name of BODY_FIELDS) body[name] = raw[name];
    const key = createPublicKey(publicKeyPem);
    if (
      key.asymmetricKeyType !== 'ed25519' ||
      !verify(
        null,
        Buffer.from(canonicalJson(body), 'utf8'),
        key,
        Buffer.from(raw.signature, 'base64'),
      )
    ) {
      return refuse();
    }
    return Object.freeze(body as unknown as OperatorCloudAuthority);
  } catch {
    return refuse();
  }
}

/** No caching: the external, independently signed authority may be revoked. */
export function readOperatorCloudAuthority(input: {
  authorityFile: string;
  publicKeyFile: string;
  pinnedSpkiSha256: string;
  now?: () => number;
}): OperatorCloudAuthority {
  try {
    if (
      !isAbsolute(input.authorityFile) ||
      !isAbsolute(input.publicKeyFile) ||
      !/^[a-f0-9]{64}$/.test(input.pinnedSpkiSha256)
    ) {
      return refuse();
    }
    const raw = JSON.parse(readFileSync(input.authorityFile, 'utf8')) as unknown;
    const pem = readFileSync(input.publicKeyFile, 'utf8');
    return verifyOperatorCloudAuthority(
      raw,
      pem,
      input.pinnedSpkiSha256,
      input.now?.() ?? Date.now(),
    );
  } catch {
    return refuse();
  }
}

/**
 * Return only the MATERIAL revision/price/consent policy. A fresh signature
 * with the same facts can renew its five-minute lease without stopping Shun.
 * Any epoch/policy/provider/pricing/budget change => fail closed until the
 * current user performs a separately approved, new-scope operation.
 */
function stableFacts(state: OperatorCloudAuthority): string {
  const { issuedAt: _issued, expiresAt: _expires, ...facts } = state;
  return canonicalJson(facts);
}

export function createCloudAuthorityCurrentness(
  source: () => OperatorCloudAuthority,
  approvedAtStart: OperatorCloudAuthority,
): () => boolean {
  const baseline = stableFacts(approvedAtStart);
  return () => {
    try {
      return stableFacts(source()) === baseline;
    } catch {
      return false;
    }
  };
}
