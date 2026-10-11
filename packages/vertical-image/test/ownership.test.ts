// Negative controls for the T05 safety corrections (Issue #38):
// - VI-P0-01: after a failed O_EXCL create (OUTPUT_COLLISION) the executor
//   must never delete the target — whatever sits there was written by
//   someone else and must survive untouched.
// - VI-P0-02: the per-record provider fallback must only use providers that
//   passed the same screening as the selection (registered + feasible), and
//   the receipt must disclose every fallback execution.
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runImageBatchProcess } from '../src/executor.ts';
import type { BindingView, ImageProvider } from '../src/provider.ts';
import { makeSharpImageProvider } from '../src/sharp-engine.ts';
import { type FixtureDir, fixtureDir, jpegBytes, pngBytes, testFacts } from './helpers.ts';

let src: FixtureDir;
let out: FixtureDir;

beforeEach(async () => {
  src = await fixtureDir('shun-own-src-');
  out = await fixtureDir('shun-own-out-');
});

afterEach(async () => {
  await src.cleanup();
  await out.cleanup();
});

const FOREIGN_BYTES = Buffer.from('foreign artifact owned by another writer\n');

function c001Input(files: Array<{ path: string; format: 'JPG' | 'PNG' }>) {
  return {
    taskId: 'task-ownership',
    inputFiles: files,
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: 300 },
    metadataPolicy: { preserveCaptureDate: true as const },
    outputDirectory: out.path,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
    networkUsage: 'LOCAL_ONLY' as const,
  };
}

/**
 * Real sharp provider wrapped so a foreign writer wins the create race: the
 * foreign file appears at the target after the executor's collision precheck
 * but before the provider's 'wx' write, which must then lose with EEXIST.
 */
function raceLosingProvider(): ImageProvider {
  const provider = makeSharpImageProvider();
  const realResize = provider.resizeTo.bind(provider);
  provider.resizeTo = async (request) => {
    await writeFile(request.targetPath, FOREIGN_BYTES, { flag: 'wx' });
    return realResize(request);
  };
  return provider;
}

describe('output ownership after O_EXCL collision (VI-P0-01)', () => {
  it('never deletes the foreign winner of a create race', async () => {
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 301 }));
    const result = await runImageBatchProcess(c001Input([{ path: a, format: 'JPG' }]), {
      facts: testFacts(),
      providers: [raceLosingProvider()],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const record = result.output.records[0];
    expect(record?.status).toBe('REJECTED');
    expect(record?.rejectionCode).toBe('OUTPUT_COLLISION');
    expect(await readFile(join(out.path, 'a.jpg'))).toEqual(FOREIGN_BYTES);
  });

  it('still removes an output the executor itself wrote when the self-check fails', async () => {
    // Over-correction guard: once the executor owns the target, a failed
    // post-write self-check must still remove the bad output.
    const provider = makeSharpImageProvider();
    const realResize = provider.resizeTo.bind(provider);
    provider.resizeTo = async (request) =>
      realResize({ ...request, targetDims: { width: 100, height: 100 } });
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 302 }));
    const result = await runImageBatchProcess(c001Input([{ path: a, format: 'JPG' }]), {
      facts: testFacts(),
      providers: [provider],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const record = result.output.records[0];
    expect(record?.status).toBe('REJECTED');
    expect(record?.rejectionCode).toBe('OUTPUT_VERIFY_FAILED');
    expect(existsSync(join(out.path, 'a.jpg'))).toBe(false);
  });
});

function binding(overrides: Partial<BindingView>): BindingView {
  return {
    bindingId: 'binding-x',
    providerId: 'provider-x',
    providerVersion: '0.0.1',
    adapterId: 'adapter-x',
    interfaceClass: 'I2',
    verifierId: 'verifier.image-c001',
    environmentRequirements: { backendKind: 'LOCAL_WINDOWS' },
    unsupportedFormats: [],
    ...overrides,
  };
}

const FEASIBLE_JPG_ONLY = binding({
  bindingId: 'binding-feasible-jpg-only',
  interfaceClass: 'I0',
  unsupportedFormats: ['PNG'],
});

describe('per-record provider fallback screening (VI-P0-02)', () => {
  it('rejects the record instead of executing an infeasible binding as fallback', async () => {
    const infeasibleFull = binding({
      bindingId: 'binding-infeasible-full',
      environmentRequirements: { backendKind: 'LOCAL_POSIX' }, // infeasible on the observed facts
    });
    const jpg = await src.write('x.jpg', await jpegBytes({ width: 600, height: 400, seed: 311 }));
    const png = await src.write('x.png', await pngBytes({ width: 600, height: 400, seed: 312 }));
    const result = await runImageBatchProcess(
      c001Input([
        { path: jpg, format: 'JPG' },
        { path: png, format: 'PNG' },
      ]),
      {
        facts: testFacts(),
        providers: [
          makeSharpImageProvider(FEASIBLE_JPG_ONLY),
          makeSharpImageProvider(infeasibleFull),
        ],
      },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(jpg)?.status).toBe('WRITTEN');
    expect(byPath.get(png)?.status).toBe('REJECTED');
    expect(byPath.get(png)?.rejectionCode).toBe('UNSUPPORTED_INPUT');
    expect(existsSync(join(out.path, 'x.png'))).toBe(false);
  });

  it('rejects the record instead of executing an unscreened (unregistered) binding as fallback', async () => {
    const unscreenedFull = binding({ bindingId: 'binding-unscreened-full' });
    const jpg = await src.write('x.jpg', await jpegBytes({ width: 600, height: 400, seed: 321 }));
    const png = await src.write('x.png', await pngBytes({ width: 600, height: 400, seed: 322 }));
    const result = await runImageBatchProcess(
      c001Input([
        { path: jpg, format: 'JPG' },
        { path: png, format: 'PNG' },
      ]),
      {
        facts: testFacts(),
        providers: [
          makeSharpImageProvider(FEASIBLE_JPG_ONLY),
          makeSharpImageProvider(unscreenedFull),
        ],
        // Upstream screening registered only the first binding.
        candidates: [{ binding: FEASIBLE_JPG_ONLY, registered: true }],
      },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(jpg)?.status).toBe('WRITTEN');
    expect(byPath.get(png)?.status).toBe('REJECTED');
    expect(byPath.get(png)?.rejectionCode).toBe('UNSUPPORTED_INPUT');
    expect(existsSync(join(out.path, 'x.png'))).toBe(false);
  });

  it('still uses a screened feasible fallback and discloses it in the receipt', async () => {
    const feasiblePngOnly = binding({
      bindingId: 'binding-feasible-png-only',
      interfaceClass: 'I1',
      unsupportedFormats: ['JPG'],
    });
    const jpg = await src.write('x.jpg', await jpegBytes({ width: 600, height: 400, seed: 331 }));
    const png = await src.write('x.png', await pngBytes({ width: 600, height: 400, seed: 332 }));
    const result = await runImageBatchProcess(
      c001Input([
        { path: jpg, format: 'JPG' },
        { path: png, format: 'PNG' },
      ]),
      {
        facts: testFacts(),
        providers: [
          makeSharpImageProvider(FEASIBLE_JPG_ONLY),
          makeSharpImageProvider(feasiblePngOnly),
        ],
      },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(jpg)?.status).toBe('WRITTEN');
    expect(byPath.get(png)?.status).toBe('WRITTEN');
    expect(result.output.selectedBindingId).toBe('binding-feasible-jpg-only');
    expect(result.output.rankingEvidence.reasons.join(' ')).toContain('binding-feasible-png-only');
  });
});
