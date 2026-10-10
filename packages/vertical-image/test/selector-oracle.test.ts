import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Sha256Hex } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { scaledDims } from '../src/dims.ts';
import { commitOracle, MAX_ORACLE_SAMPLES, selectSampleEntries } from '../src/oracle.ts';
import type { BindingView } from '../src/provider.ts';
import { infeasibilityReasons, selectBinding } from '../src/selector.ts';
import { sharpBindingView } from '../src/sharp-engine.ts';
import { type FixtureDir, fixtureDir, jpegBytes, testFacts } from './helpers.ts';

function hash(n: number): Sha256Hex {
  return n.toString(16).padStart(64, '0');
}

function bindingView(overrides: Partial<BindingView> = {}): BindingView {
  return {
    bindingId: 'binding-b',
    providerId: 'provider-b',
    providerVersion: '1.0.0',
    adapterId: 'adapter-b',
    interfaceClass: 'I0',
    verifierId: 'verifier.image-c001',
    environmentRequirements: { backendKind: 'LOCAL_WINDOWS' },
    unsupportedFormats: [],
    ...overrides,
  };
}

describe('selectSampleEntries', () => {
  it('picks at most 20 samples in ascending source SHA-256 order', () => {
    const hashes = new Map<string, Sha256Hex>();
    for (let i = 0; i < 30; i++) {
      hashes.set(`img-${String(i).padStart(3, '0')}.jpg`, hash(1000 - i));
    }
    const picked = selectSampleEntries(hashes);
    expect(picked).toHaveLength(MAX_ORACLE_SAMPLES);
    for (let i = 1; i < picked.length; i++) {
      const prev = picked[i - 1];
      const cur = picked[i];
      expect(prev && cur && prev.sourceSha256 <= cur.sourceSha256).toBe(true);
    }
    expect(picked[0]?.inputPath).toBe('img-029.jpg');
  });

  it('uses all files when below the cap and breaks SHA ties by path', () => {
    const hashes = new Map<string, Sha256Hex>([
      ['b.png', hash(1)],
      ['a.png', hash(1)],
    ]);
    const picked = selectSampleEntries(hashes);
    expect(picked.map((p) => p.inputPath)).toEqual(['a.png', 'b.png']);
  });

  it('is deterministic across runs', () => {
    const hashes = new Map<string, Sha256Hex>();
    for (let i = 0; i < 50; i++) {
      hashes.set(`f-${i}.jpg`, hash((i * 7919) % 100000));
    }
    expect(selectSampleEntries(hashes)).toEqual(selectSampleEntries(hashes));
  });
});

describe('commitOracle', () => {
  let dir: FixtureDir;

  it('generates lossless references at the exact output dimensions', async () => {
    dir = await fixtureDir('shun-oracle-test-');
    const hashes = new Map<string, Sha256Hex>();
    const sizes: Array<[number, number]> = [
      [320, 200],
      [200, 320],
      [1600, 900],
    ];
    for (const [i, [w, h]] of sizes.entries()) {
      const bytes = await jpegBytes({ width: w, height: h, seed: 20 + i });
      const path = await dir.write(`src-${i}.jpg`, bytes);
      hashes.set(path, hash(42 + i));
    }
    const oracle = await commitOracle({
      sourceHashes: hashes,
      maxLongEdgePx: 400,
      ssimThreshold: 0.95,
      workDir: join(dir.path, 'oracle'),
    });
    expect(oracle.samples).toHaveLength(3);
    for (const sample of oracle.samples) {
      expect(sample.eligible).toBe(true);
      const referencePath = sample.referencePath;
      expect(referencePath).toBeDefined();
      const reference = await readFile(referencePath as string);
      expect(reference.subarray(0, 4)).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
      const index = Number(sample.inputPath.match(/src-(\d)/)?.[1]);
      const sizeDef = sizes[index] ?? (undefined as [number, number] | undefined);
      if (!sizeDef) {
        throw new Error(`no size definition for sample ${sample.inputPath}`);
      }
      const expected = scaledDims(sizeDef[0], sizeDef[1], 400);
      expect(sample.referenceWidth).toBe(expected.width);
      expect(sample.referenceHeight).toBe(expected.height);
    }
    await dir.cleanup();
  });

  it('marks undecodable sample sources ineligible', async () => {
    dir = await fixtureDir('shun-oracle-test2-');
    const good = await dir.write('good.jpg', await jpegBytes({ width: 80, height: 60, seed: 30 }));
    const bad = await dir.write('bad.jpg', Buffer.from([0xff, 0xd8, 0xff, 0x00, 0x01, 0x02, 0x03]));
    const oracle = await commitOracle({
      sourceHashes: new Map([
        [good, hash(2)],
        [bad, hash(1)],
      ]),
      maxLongEdgePx: 1600,
      ssimThreshold: 0.95,
      workDir: join(dir.path, 'oracle'),
    });
    const badSample = oracle.samples.find((s) => s.inputPath === bad);
    const goodSample = oracle.samples.find((s) => s.inputPath === good);
    expect(badSample?.eligible).toBe(false);
    expect(badSample?.detail).toContain('undecodable');
    expect(goodSample?.eligible).toBe(true);
    await dir.cleanup();
  });
});

describe('selectBinding', () => {
  const facts = testFacts();

  it('prefers I0 over I1 and breaks ties lexicographically', () => {
    const i1 = bindingView({ bindingId: 'binding-a-i1', interfaceClass: 'I1' });
    const i0b = bindingView({ bindingId: 'binding-b-i0', interfaceClass: 'I0' });
    const i0a = bindingView({ bindingId: 'binding-a-i0', interfaceClass: 'I0' });
    const selection = selectBinding(
      [
        { binding: i1, registered: true },
        { binding: i0b, registered: true },
        { binding: i0a, registered: true },
      ],
      facts,
      ['JPG', 'PNG'],
    );
    expect(selection.outcome).toBe('SELECTED');
    expect(selection.selected?.bindingId).toBe('binding-a-i0');
  });

  it('falls back to policy ranking when the preferred binding is missing', () => {
    const b = bindingView({ bindingId: 'binding-real' });
    const selection = selectBinding(
      [{ binding: b, registered: true }],
      facts,
      ['JPG'],
      'binding-preferred',
    );
    expect(selection.outcome).toBe('SELECTED');
    expect(selection.selected?.bindingId).toBe('binding-real');
    expect(
      selection.rankingEvidence.reasons.some((r) => r.includes('binding-preferred missing')),
    ).toBe(true);
  });

  it('skips unregistered candidates', () => {
    const good = bindingView({ bindingId: 'binding-good' });
    const selection = selectBinding(
      [
        {
          binding: bindingView({ bindingId: 'binding-ghost', interfaceClass: 'I0' }),
          registered: false,
        },
        { binding: good, registered: true },
      ],
      facts,
      ['JPG'],
    );
    expect(selection.selected?.bindingId).toBe('binding-good');
    expect(selection.rankingEvidence.reasons.some((r) => r.includes('not registered'))).toBe(true);
  });

  it('returns NO_TRUSTED_PROVIDER when nothing is registered', () => {
    const selection = selectBinding([], facts, ['JPG']);
    expect(selection.outcome).toBe('NO_TRUSTED_PROVIDER');
    expect(selection.selected).toBeNull();
  });

  it('returns NO_FEASIBLE_BINDING when facts do not satisfy requirements', () => {
    const selection = selectBinding(
      [{ binding: bindingView(), registered: true }],
      testFacts({ backendKind: 'LOCAL_POSIX' }),
      ['JPG'],
    );
    expect(selection.outcome).toBe('NO_FEASIBLE_BINDING');
  });

  it('demotes bindings that lack a required format only when full coverage exists', () => {
    const noPng = bindingView({ bindingId: 'binding-nopng', unsupportedFormats: ['PNG'] });
    const full = bindingView({ bindingId: 'binding-full' });
    const withPng = selectBinding(
      [
        { binding: noPng, registered: true },
        { binding: full, registered: true },
      ],
      facts,
      ['JPG', 'PNG'],
    );
    expect(withPng.selected?.bindingId).toBe('binding-full');

    const onlyLimited = selectBinding([{ binding: noPng, registered: true }], facts, [
      'JPG',
      'PNG',
    ]);
    expect(onlyLimited.selected?.bindingId).toBe('binding-nopng');
    expect(onlyLimited.rankingEvidence.reasons.some((r) => r.includes('per-record fallback'))).toBe(
      true,
    );
  });

  it('derives typed infeasibility reasons', () => {
    const reasons = infeasibilityReasons(
      bindingView({
        environmentRequirements: {
          backendKind: 'LOCAL_WINDOWS',
          os: 'LINUX',
          minFreeDiskMb: 999999,
          networkAccess: 'REQUIRED',
        },
      }),
      facts,
    );
    expect(reasons).toEqual([
      'PLATFORM_UNSUPPORTED',
      'NETWORK_POLICY_FORBIDDEN',
      'RESOURCE_INSUFFICIENT',
    ]);
  });
});

describe('sharpBindingView', () => {
  it('declares the local Windows I0 binding covering both formats', () => {
    const view = sharpBindingView();
    expect(view.interfaceClass).toBe('I0');
    expect(view.unsupportedFormats).toEqual([]);
    expect(view.environmentRequirements.backendKind).toBe('LOCAL_WINDOWS');
    expect(view.providerVersion).toMatch(/^sharp@/);
  });
});
