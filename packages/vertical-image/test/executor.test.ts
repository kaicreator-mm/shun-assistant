import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, stat, truncate, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ShunContractError } from '@shun/contracts';
import sharp from 'sharp';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runImageBatchProcess } from '../src/executor.ts';
import { type BindingView, ImageProviderError } from '../src/provider.ts';
import { makeSharpImageProvider, SHARP_BINDING_ID } from '../src/sharp-engine.ts';
import { type FixtureDir, fixtureDir, jpegBytes, pngBytes, testFacts } from './helpers.ts';

let src: FixtureDir;
let out: FixtureDir;

beforeEach(async () => {
  src = await fixtureDir('shun-exec-src-');
  out = await fixtureDir('shun-exec-out-');
});

afterEach(async () => {
  await src.cleanup();
  await out.cleanup();
});

async function standardBatch() {
  const a = await src.write(
    'a.jpg',
    await jpegBytes({ width: 900, height: 600, seed: 101, captureDate: '2024:01:02 03:04:05' }),
  );
  const b = await src.write('b.jpg', await jpegBytes({ width: 600, height: 900, seed: 102 }));
  const c = await src.write(
    'c.png',
    await pngBytes({ width: 700, height: 500, seed: 103, captureDate: '2023:06:07 08:09:10' }),
  );
  const d = await src.write('d.png', await pngBytes({ width: 200, height: 150, seed: 104 }));
  return [
    { path: a, format: 'JPG' as const },
    { path: b, format: 'JPG' as const },
    { path: c, format: 'PNG' as const },
    { path: d, format: 'PNG' as const },
  ];
}

const deps = () => ({ facts: testFacts(), providers: [makeSharpImageProvider()] });

describe('runImageBatchProcess — happy path', () => {
  it('writes every input, preserves dates, keeps sources intact and verifies PASS', async () => {
    const inputFiles = await standardBatch();
    const result = await runImageBatchProcess(
      {
        taskId: 'task-happy',
        inputFiles,
        operation: { kind: 'RESIZE', maxLongEdgePx: 300 },
        metadataPolicy: { preserveCaptureDate: true },
        outputDirectory: out.path,
        qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1', ssimThreshold: 0.95 },
        networkUsage: 'LOCAL_ONLY',
      },
      deps(),
    );
    if (!result.ok) {
      throw new Error(`expected ok, got ${JSON.stringify(result.failure)}`);
    }
    expect(result.output.records.filter((r) => r.status === 'WRITTEN')).toHaveLength(4);
    expect(result.output.selectedBindingId).toBe(SHARP_BINDING_ID);
    expect(result.output.verification.status).toBe('PASS');
    const checkIds = result.output.verification.checks.map((c) => c.checkId);
    expect(checkIds).toEqual(
      expect.arrayContaining([
        'count-conservation',
        'outputs-decodable',
        'long-edge-bound',
        'capture-date-preserved',
        'ssim-oracle',
        'sources-unchanged',
      ]),
    );

    // Output dims respect the bound; small images are not upscaled.
    const aOut = await sharp(join(out.path, 'a.jpg')).metadata();
    expect(aOut.width).toBe(300);
    expect(aOut.height).toBe(200);
    const dOut = await sharp(join(out.path, 'd.png')).metadata();
    expect(dOut.width).toBe(200);
    expect(dOut.height).toBe(150);

    // Capture dates preserved (JPG EXIF and PNG eXIf).
    const aMeta = await sharp(join(out.path, 'a.jpg')).metadata();
    expect(
      aMeta.exif && Buffer.from(aMeta.exif).toString('latin1').includes('2024:01:02 03:04:05'),
    ).toBe(true);
    const cMeta = await sharp(join(out.path, 'c.png')).metadata();
    expect(
      cMeta.exif && Buffer.from(cMeta.exif).toString('latin1').includes('2023:06:07 08:09:10'),
    ).toBe(true);

    // Original sources untouched and still on disk.
    expect(existsSync(inputFiles[0]?.path ?? '')).toBe(true);
    const ssimCheck = result.output.verification.checks.find((c) => c.checkId === 'ssim-oracle');
    expect(ssimCheck?.status).toBe('PASS');
    expect(result.diagnostics).toEqual({});
  });
});

describe('runImageBatchProcess — task-level failures', () => {
  const input = (
    files: Array<{ path: string; format: 'JPG' | 'PNG' }>,
    outputDirectory: string,
  ) => ({
    taskId: 'task-neg',
    inputFiles: files,
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: 300 },
    metadataPolicy: { preserveCaptureDate: true },
    outputDirectory,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
    networkUsage: 'LOCAL_ONLY' as const,
  });

  it('throws a typed contract error on schema violation', async () => {
    await expect(
      runImageBatchProcess({ inputFiles: [], operation: {} }, deps()),
    ).rejects.toBeInstanceOf(ShunContractError);
  });

  it('refuses an output directory equal to an input directory before any write', async () => {
    const files = await standardBatch();
    const result = await runImageBatchProcess(input(files, src.path), deps());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('POLICY_BLOCKED');
    }
    expect(existsSync(join(src.path, 'a.jpg'))).toBe(true); // sources intact
    expect((await readdir(src.path)).filter((f) => f.endsWith('.tmp')).length).toBe(0);
  });

  it('returns NO_TRUSTED_PROVIDER with no provider and writes nothing', async () => {
    const files = await standardBatch();
    const result = await runImageBatchProcess(input(files, out.path), {
      facts: testFacts(),
      providers: [],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('NO_TRUSTED_PROVIDER');
    }
    expect((await readdir(out.path)).length).toBe(0);
  });

  it('returns NO_FEASIBLE_BINDING when facts do not satisfy the binding', async () => {
    const files = await standardBatch();
    const result = await runImageBatchProcess(input(files, out.path), {
      facts: testFacts({ backendKind: 'LOCAL_POSIX' }),
      providers: deps().providers,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('NO_FEASIBLE_BINDING');
    }
    expect((await readdir(out.path)).length).toBe(0);
  });

  it('falls back to the available binding when the preferred one is missing', async () => {
    const files = await standardBatch();
    const result = await runImageBatchProcess(input(files, out.path), {
      ...deps(),
      preferredBindingId: 'binding-preferred-missing',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.output.selectedBindingId).toBe(SHARP_BINDING_ID);
      expect(result.output.rankingEvidence.reasons.join(' ')).toContain(
        'binding-preferred-missing',
      );
    }
  });
});

describe('runImageBatchProcess — per-record failures', () => {
  const input = (files: Array<{ path: string; format: 'JPG' | 'PNG' }>) => ({
    taskId: 'task-records',
    inputFiles: files,
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: 300 },
    metadataPolicy: { preserveCaptureDate: true },
    outputDirectory: out.path,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
    networkUsage: 'LOCAL_ONLY' as const,
  });

  it('rejects corrupt input per-record while the rest verifies PASS', async () => {
    const files = await standardBatch();
    await truncate(files[1]?.path ?? '', 30);
    const result = await runImageBatchProcess(input(files), deps());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const corrupt = result.output.records.find((r) => r.inputPath === files[1]?.path);
    expect(corrupt?.status).toBe('REJECTED');
    expect(corrupt?.rejectionCode).toBe('DECODE_FAILED');
    expect(result.output.records.filter((r) => r.status === 'WRITTEN')).toHaveLength(3);
    expect(result.output.verification.status).toBe('PASS');
  });

  it('rejects format-mismatched bytes as UNSUPPORTED_INPUT', async () => {
    const jpg = await src.write(
      'fine.jpg',
      await jpegBytes({ width: 300, height: 200, seed: 111 }),
    );
    const lie = await src.write('liar.jpg', await pngBytes({ width: 300, height: 200, seed: 112 }));
    const result = await runImageBatchProcess(
      input([
        { path: jpg, format: 'JPG' },
        { path: lie, format: 'JPG' },
      ]),
      deps(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const liar = result.output.records.find((r) => r.inputPath === lie);
    expect(liar?.rejectionCode).toBe('UNSUPPORTED_INPUT');
    expect(result.diagnostics[lie]).toContain('PNG');
  });

  it('rejects pre-existing targets and in-batch duplicate names up front', async () => {
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 121 }));
    const sub = join(src.path, 'sub');
    await mkdir(sub, { recursive: true });
    const dup = join(sub, 'a.jpg');
    await writeFile(dup, await jpegBytes({ width: 600, height: 400, seed: 125 }));
    const b = await src.write('b.jpg', await jpegBytes({ width: 600, height: 400, seed: 122 }));
    await out.write('A.JPG', Buffer.from([1])); // case-insensitive collision with a.jpg
    const c = await src.write('c.jpg', await jpegBytes({ width: 600, height: 400, seed: 123 }));
    const result = await runImageBatchProcess(
      input([
        { path: a, format: 'JPG' },
        { path: dup, format: 'JPG' },
        { path: b, format: 'JPG' },
        { path: c, format: 'JPG' },
      ]),
      deps(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(a)?.status).toBe('REJECTED');
    expect(byPath.get(a)?.rejectionCode).toBe('OUTPUT_COLLISION');
    expect(byPath.get(dup)?.status).toBe('REJECTED');
    expect(byPath.get(dup)?.rejectionCode).toBe('OUTPUT_COLLISION');
    expect(byPath.get(b)?.status).toBe('WRITTEN');
    expect(byPath.get(c)?.status).toBe('WRITTEN');
    expect(result.output.verification.status).toBe('PASS');
  });

  it('routes formats to another registered provider when the selected one lacks them', async () => {
    const limited: BindingView = {
      bindingId: 'binding-jpg-only',
      providerId: 'provider-jpg-only',
      providerVersion: '0.0.1',
      adapterId: 'adapter-jpg-only',
      interfaceClass: 'I1',
      verifierId: 'verifier.image-c001',
      environmentRequirements: { backendKind: 'LOCAL_WINDOWS' },
      unsupportedFormats: ['PNG'],
    };
    const files = await standardBatch();
    const result = await runImageBatchProcess(input(files), {
      facts: testFacts(),
      providers: [makeSharpImageProvider(limited), makeSharpImageProvider()],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    // The format-complete binding wins over the preferred-class partial one.
    expect(result.output.selectedBindingId).not.toBe('binding-jpg-only');
    expect(result.output.records.filter((r) => r.status === 'WRITTEN')).toHaveLength(4);
  });

  it('marks PNG records UNSUPPORTED_INPUT when no provider covers PNG', async () => {
    const limited: BindingView = {
      bindingId: 'binding-jpg-only',
      providerId: 'provider-jpg-only',
      providerVersion: '0.0.1',
      adapterId: 'adapter-jpg-only',
      interfaceClass: 'I1',
      verifierId: 'verifier.image-c001',
      environmentRequirements: { backendKind: 'LOCAL_WINDOWS' },
      unsupportedFormats: ['PNG'],
    };
    const jpg = await src.write(
      'only.jpg',
      await jpegBytes({ width: 600, height: 400, seed: 131 }),
    );
    const png = await src.write('only.png', await pngBytes({ width: 600, height: 400, seed: 132 }));
    const result = await runImageBatchProcess(
      input([
        { path: jpg, format: 'JPG' },
        { path: png, format: 'PNG' },
      ]),
      { facts: testFacts(), providers: [makeSharpImageProvider(limited)] },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(jpg)?.status).toBe('WRITTEN');
    expect(byPath.get(png)?.rejectionCode).toBe('UNSUPPORTED_INPUT');
  });

  it('reports a missing input file as DECODE_FAILED without aborting the batch', async () => {
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 141 }));
    const ghost = join(src.path, 'ghost.jpg');
    const result = await runImageBatchProcess(
      input([
        { path: a, format: 'JPG' },
        { path: ghost, format: 'JPG' },
      ]),
      deps(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(ghost)?.rejectionCode).toBe('DECODE_FAILED');
    expect(byPath.get(a)?.status).toBe('WRITTEN');
    expect(
      result.output.verification.checks.find((c) => c.checkId === 'sources-unchanged')?.status,
    ).toBe('FAIL');
  });

  it('does not leave partial outputs when a provider explodes mid-write', async () => {
    const a = await src.write('a.jpg', await jpegBytes({ width: 300, height: 200, seed: 151 }));
    const exploding = makeSharpImageProvider();
    exploding.resizeTo = async () => {
      throw new ImageProviderError(
        'OUTPUT_VERIFY_FAILED',
        'binding-x',
        'simulated mid-write crash',
      );
    };
    const result = await runImageBatchProcess(input([{ path: a, format: 'JPG' }]), {
      facts: testFacts(),
      providers: [exploding],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.output.records[0]?.status).toBe('REJECTED');
    expect(existsSync(join(out.path, 'a.jpg'))).toBe(false);
  });
});

describe('runImageBatchProcess — original preservation', () => {
  it('leaves every source byte-identical', async () => {
    const files = await standardBatch();
    const before = new Map<string, Buffer>();
    for (const f of files) {
      before.set(f.path, await readFile(f.path));
    }
    const input = {
      taskId: 'task-preserve',
      inputFiles: files,
      operation: { kind: 'RESIZE' as const, maxLongEdgePx: 300 },
      metadataPolicy: { preserveCaptureDate: true },
      outputDirectory: out.path,
      qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
      networkUsage: 'LOCAL_ONLY' as const,
    };
    const result = await runImageBatchProcess(input, deps());
    expect(result.ok).toBe(true);
    for (const f of files) {
      expect(await readFile(f.path)).toEqual(before.get(f.path));
    }
    // Output dir contains exactly the written outputs, nothing else.
    const listing = await readdir(out.path);
    expect(listing.sort()).toEqual(['a.jpg', 'b.jpg', 'c.png', 'd.png']);
    // Output dir stats: all files non-empty.
    for (const name of listing) {
      const s = await stat(join(out.path, name));
      expect(s.size).toBeGreaterThan(0);
    }
  });
});
