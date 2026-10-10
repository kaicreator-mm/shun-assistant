import { readFile } from 'node:fs/promises';
import sharp from 'sharp';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { scaledDims } from '../src/dims.ts';
import { ImageProviderError } from '../src/provider.ts';
import { makeSharpImageProvider } from '../src/sharp-engine.ts';
import { type FixtureDir, fixtureDir, jpegBytes, pngBytes } from './helpers.ts';

let dir: FixtureDir;

beforeEach(async () => {
  dir = await fixtureDir('shun-engine-test-');
});

afterEach(async () => {
  await dir.cleanup();
});

describe('makeSharpImageProvider', () => {
  it('resizes a JPG to exact target dims and preserves the capture date', async () => {
    const provider = makeSharpImageProvider();
    const bytes = await jpegBytes({
      width: 400,
      height: 260,
      seed: 11,
      captureDate: '2022:03:04 05:06:07',
    });
    const target = dir.pathOf('out.jpg');
    const dims = scaledDims(400, 260, 160);
    const outcome = await provider.resizeTo({
      bytes,
      declaredFormat: 'JPG',
      targetDims: dims,
      targetPath: target,
    });
    expect(outcome.captureDate).toBe('2022:03:04 05:06:07');
    const meta = await sharp(await readFile(target)).metadata();
    expect(meta.format).toBe('jpeg');
    expect(meta.width).toBe(dims.width);
    expect(meta.height).toBe(dims.height);
    expect(meta.exif).toBeDefined();
  });

  it('resizes a PNG and preserves an eXIf capture date', async () => {
    const provider = makeSharpImageProvider();
    const bytes = await pngBytes({
      width: 300,
      height: 200,
      seed: 12,
      captureDate: '2020:12:01 00:01:02',
    });
    const target = dir.pathOf('out.png');
    const dims = scaledDims(300, 200, 150);
    const outcome = await provider.resizeTo({
      bytes,
      declaredFormat: 'PNG',
      targetDims: dims,
      targetPath: target,
    });
    expect(outcome.captureDate).toBe('2020:12:01 00:01:02');
    const meta = await sharp(await readFile(target)).metadata();
    expect(meta.format).toBe('png');
    expect(meta.exif).toBeDefined();
  });

  it('reports DECODE_FAILED for truncated declared-format bytes', async () => {
    const provider = makeSharpImageProvider();
    const bytes = await jpegBytes({ width: 200, height: 140, seed: 13 });
    const truncated = bytes.subarray(0, Math.floor(bytes.length / 3));
    await expect(
      provider.resizeTo({
        bytes: truncated,
        declaredFormat: 'JPG',
        targetDims: { width: 100, height: 70 },
        targetPath: dir.pathOf('corrupt.jpg'),
      }),
    ).rejects.toBeInstanceOf(ImageProviderError);
  });

  it('reports UNSUPPORTED_INPUT when bytes are a different known container', async () => {
    const provider = makeSharpImageProvider();
    const bytes = await pngBytes({ width: 120, height: 90, seed: 14 });
    await expect(
      provider.resizeTo({
        bytes,
        declaredFormat: 'JPG',
        targetDims: { width: 60, height: 45 },
        targetPath: dir.pathOf('mismatch.jpg'),
      }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_INPUT' });
  });

  it('refuses to overwrite an existing output (OUTPUT_COLLISION)', async () => {
    const provider = makeSharpImageProvider();
    const bytes = await jpegBytes({ width: 160, height: 120, seed: 15 });
    const target = await dir.write('exists.jpg', Buffer.from([1, 2, 3]));
    await expect(
      provider.resizeTo({
        bytes,
        declaredFormat: 'JPG',
        targetDims: { width: 80, height: 60 },
        targetPath: target,
      }),
    ).rejects.toMatchObject({ code: 'OUTPUT_COLLISION' });
  });

  it('leaves no temp files behind after success', async () => {
    const provider = makeSharpImageProvider();
    const bytes = await jpegBytes({ width: 100, height: 100, seed: 16 });
    const target = dir.pathOf('clean.jpg');
    await provider.resizeTo({
      bytes,
      declaredFormat: 'JPG',
      targetDims: { width: 50, height: 50 },
      targetPath: target,
    });
    const { readdir } = await import('node:fs/promises');
    const files = await readdir(dir.path);
    expect(files.sort()).toEqual(['clean.jpg']);
  });
});
