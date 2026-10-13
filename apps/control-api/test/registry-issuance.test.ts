import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '@shun/contracts';
import { type RegistrySnapshot, snapshotFactsRevision } from '@shun/resolver';
import { describe, expect, it } from 'vitest';
import {
  ISSUANCE_SCHEMA,
  type RegistryIssuanceBody,
  verifyRegistryIssuance,
} from '../src/real-storage/registry-issuance.ts';

const ISSUED = '2026-10-13T02:00:00.000Z';
const EXPIRES = '2026-10-13T02:01:00.000Z';
const NOW = '2026-10-13T02:00:30.000Z';
const WORKSPACE = '/shun/operator-owned';
const keys = generateKeyPairSync('ed25519');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const privateKey = keys.privateKey;

function sourceSnapshot(): RegistrySnapshot {
  // Signer contract only. Production snapshot structure is independently
  // re-validated by ShunRegistry.fromAttestedSnapshot at the consumer.
  return {
    capabilities: [],
    providers: [],
    bindings: [],
    environment: {
      environmentId: 'host-issued-1',
      observationRevision: 'issued-at-source',
      resources: { freeDiskMb: 4096 },
    },
  } as unknown as RegistrySnapshot;
}

function signBody(body: RegistryIssuanceBody) {
  return {
    ...body,
    signature: sign(null, Buffer.from(canonicalJson(body), 'utf8'), privateKey).toString('base64'),
  };
}

function issued(overrides: Partial<RegistryIssuanceBody> = {}) {
  const snapshot = overrides.snapshot ?? sourceSnapshot();
  const body: RegistryIssuanceBody = {
    schema: ISSUANCE_SCHEMA,
    workspace: WORKSPACE,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    snapshot,
    currentRevision: snapshotFactsRevision(snapshot),
    ...overrides,
  };
  return signBody(body);
}

describe('source-issued Registry currentness proof (M02 P1)', () => {
  it('accepts only a fresh independently signed snapshot and exact source revision', () => {
    const proof = issued();
    const result = verifyRegistryIssuance(proof, publicKey, WORKSPACE, NOW);
    expect(result.currentRevision).toBe(snapshotFactsRevision(proof.snapshot));
    expect(result.snapshot).toEqual(proof.snapshot);
    expect(result.expiresAt).toBe(EXPIRES);
  });

  it('refuses operator-issued snapshots scoped to a different workspace', () => {
    const proof = issued({ workspace: '/other/trusted-root' });
    expect(() => verifyRegistryIssuance(proof, publicKey, WORKSPACE, NOW)).toThrow(
      'REAL_STORAGE_REGISTRY_ISSUANCE_WORKSPACE_MISMATCH',
    );
  });

  it('refuses a candidate-rewritten digest even when the local hash is internally consistent', () => {
    const proof = issued();
    const changed = {
      ...proof,
      snapshot: {
        ...proof.snapshot,
        environment: {
          ...proof.snapshot.environment,
          resources: { ...proof.snapshot.environment.resources, freeDiskMb: 2050 },
        },
      },
    };
    changed.currentRevision = snapshotFactsRevision(changed.snapshot);
    // The candidate cannot mint the operator's Ed25519 signature.
    expect(() => verifyRegistryIssuance(changed, publicKey, WORKSPACE, NOW)).toThrow(
      'REAL_STORAGE_REGISTRY_ISSUANCE_SIGNATURE_INVALID',
    );
  });

  it('refuses a malicious or mistaken source-issued revision that is not the snapshot revision', () => {
    const proof = issued({ currentRevision: 'shun.registry-snapshot/1:sha256:bad' });
    expect(() => verifyRegistryIssuance(proof, publicKey, WORKSPACE, NOW)).toThrow(
      'REAL_STORAGE_REGISTRY_ISSUANCE_REVISION_MISMATCH',
    );
  });

  it('refuses unsigned snapshot edits, changed issuance windows and swapped public keys', () => {
    const proof = issued();
    expect(() =>
      verifyRegistryIssuance(
        { ...proof, issuedAt: '2026-10-13T01:59:59.000Z' },
        publicKey,
        WORKSPACE,
        NOW,
      ),
    ).toThrow('REAL_STORAGE_REGISTRY_ISSUANCE_SIGNATURE_INVALID');
    const outsiderKey = generateKeyPairSync('ed25519')
      .publicKey.export({ type: 'spki', format: 'pem' })
      .toString();
    expect(() => verifyRegistryIssuance(proof, outsiderKey, WORKSPACE, NOW)).toThrow(
      'REAL_STORAGE_REGISTRY_ISSUANCE_SIGNATURE_INVALID',
    );
  });

  it('refuses expired, future and unbounded issuance windows before any authority use', () => {
    const proof = issued();
    expect(() =>
      verifyRegistryIssuance(proof, publicKey, WORKSPACE, '2026-10-13T02:01:00.000Z'),
    ).toThrow('REAL_STORAGE_REGISTRY_ISSUANCE_EXPIRED');
    expect(() =>
      verifyRegistryIssuance(
        issued({
          issuedAt: '2026-10-13T02:02:00.000Z',
          expiresAt: '2026-10-13T02:03:00.000Z',
        }),
        publicKey,
        WORKSPACE,
        NOW,
      ),
    ).toThrow('REAL_STORAGE_REGISTRY_ISSUANCE_FUTURE');
    expect(() =>
      verifyRegistryIssuance(
        issued({ expiresAt: '2026-10-13T02:04:00.000Z' }),
        publicKey,
        WORKSPACE,
        NOW,
      ),
    ).toThrow('REAL_STORAGE_REGISTRY_ISSUANCE_UNBOUNDED_LIFETIME');
  });

  it('refuses arbitrary, partial or extra fields rather than implicitly trusting an asserted attestation', () => {
    const proof = issued();
    for (const candidate of [
      null,
      { ...proof, attested: true },
      { ...proof, schema: 'untrusted/self-attestation' },
      { ...proof, signature: '' },
      { ...proof, snapshot: undefined },
    ]) {
      expect(() => verifyRegistryIssuance(candidate, publicKey, WORKSPACE, NOW)).toThrow(
        /REAL_STORAGE_REGISTRY_ISSUANCE_/,
      );
    }
  });
});
