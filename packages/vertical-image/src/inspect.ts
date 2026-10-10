// Verifier-owned source/output inspection utilities. The oracle and the
// semantic verifier read image facts through this module — independently of
// the provider adapter's execution path — so verification re-derives post
// state from the files on disk. Both use the platform decoder (sharp); the
// independence that matters is in the checks, not in reimplementing a JPEG
// decoder.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { Sha256Hex } from '@shun/contracts';
import sharp, { type Metadata } from 'sharp';
import { readExifCaptureDate } from './exif.ts';

export interface SourceFacts {
  width: number;
  height: number;
  captureDate: string | null;
}

export function sha256Hex(bytes: Buffer): Sha256Hex {
  return createHash('sha256').update(bytes).digest('hex');
}

function factsFromMetadata(meta: Metadata): SourceFacts {
  const width = meta.width ?? 0;
  const height = meta.height ?? 0;
  // Baked orientation swaps the pixel grid for orientations 5..8.
  const swapped = meta.orientation !== undefined && meta.orientation >= 5 && meta.orientation <= 8;
  return {
    width: swapped ? height : width,
    height: swapped ? width : height,
    captureDate: meta.exif ? readExifCaptureDate(meta.exif) : null,
  };
}

/** Decodes image bytes strictly enough to establish dimensions and EXIF date. */
export async function inspectBytes(bytes: Buffer): Promise<SourceFacts> {
  const meta = await sharp(bytes, { failOn: 'error' }).metadata();
  return factsFromMetadata(meta);
}

export async function inspectFile(path: string): Promise<SourceFacts> {
  return inspectBytes(await readFile(path));
}

export interface RgbaPixels {
  data: Uint8ClampedArray;
  width: number;
  height: number;
}

/**
 * Decodes image bytes into full-resolution RGBA pixels (ssim.js consumes
 * 4-channel data). Byte-based by design: on Windows, letting libvips open
 * files itself leaves handles open that block later writes/deletes.
 */
export async function decodeRgbaBytes(bytes: Buffer): Promise<RgbaPixels> {
  const { data, info } = await sharp(bytes, { failOn: 'error' })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  return {
    data: new Uint8ClampedArray(data.buffer, data.byteOffset, data.length),
    width: info.width,
    height: info.height,
  };
}
