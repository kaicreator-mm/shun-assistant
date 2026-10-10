// Shared test fixtures: deterministic noise images (real decodable bytes)
// and standard environment facts.
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnvironmentFacts } from '@shun/contracts';
import sharp from 'sharp';

/** Deterministic xorshift PRNG so test bytes are reproducible. */
export function seededRand(seed: number): () => number {
  let s = seed >>> 0;
  if (s === 0) {
    s = 0x9e3779b9;
  }
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 4294967296;
  };
}

/**
 * Photographic-style synthetic scene: smooth gradient base, soft radial
 * blobs, mild grain. High-frequency pure noise is deliberately avoided —
 * it is the JPEG worst case and would not represent user photos.
 */
export function sceneRgb(width: number, height: number, seed: number): Buffer {
  const buf = Buffer.alloc(width * height * 3);
  const rand = seededRand(seed);
  const blobs = Array.from({ length: 7 }, () => ({
    cx: rand() * width,
    cy: rand() * height,
    rad: (0.15 + rand() * 0.3) * width,
    color: [30 + rand() * 200, 30 + rand() * 200, 30 + rand() * 200] as const,
  }));
  const grainAmp = 4;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 3;
      let r = 60 + (x / width) * 120;
      let g = 70 + (y / height) * 100;
      let b = 90 + 30 * Math.sin((x + y) / 53);
      for (const blob of blobs) {
        const dx = x - blob.cx;
        const dy = y - blob.cy;
        const d2 = (dx * dx + dy * dy) / (blob.rad * blob.rad);
        if (d2 < 1) {
          const t = 0.35 * (1 - d2) * (1 - d2);
          r += t * (blob.color[0] - r);
          g += t * (blob.color[1] - g);
          b += t * (blob.color[2] - b);
        }
      }
      const n = (rand() - 0.5) * grainAmp * 2;
      buf[i] = Math.max(0, Math.min(255, r + n));
      buf[i + 1] = Math.max(0, Math.min(255, g + n));
      buf[i + 2] = Math.max(0, Math.min(255, b + n));
    }
  }
  return buf;
}

export interface ImageSpec {
  width: number;
  height: number;
  seed: number;
  captureDate?: string;
}

export async function jpegBytes(spec: ImageSpec): Promise<Buffer> {
  let pipeline = sharp(sceneRgb(spec.width, spec.height, spec.seed), {
    raw: { width: spec.width, height: spec.height, channels: 3 },
  });
  if (spec.captureDate) {
    pipeline = pipeline.withMetadata({ exif: { IFD0: { DateTimeOriginal: spec.captureDate } } });
  }
  return pipeline.jpeg({ quality: 94 }).toBuffer();
}

export async function pngBytes(spec: ImageSpec): Promise<Buffer> {
  let pipeline = sharp(sceneRgb(spec.width, spec.height, spec.seed), {
    raw: { width: spec.width, height: spec.height, channels: 3 },
  });
  if (spec.captureDate) {
    pipeline = pipeline.withMetadata({ exif: { IFD0: { DateTimeOriginal: spec.captureDate } } });
  }
  return pipeline.png().toBuffer();
}

export interface FixtureDir {
  path: string;
  cleanup(): Promise<void>;
  write(name: string, bytes: Buffer): Promise<string>;
  /** Path inside the fixture dir without creating the file. */
  pathOf(name: string): string;
}

export async function fixtureDir(prefix: string): Promise<FixtureDir> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  return {
    path,
    pathOf(name: string): string {
      return join(path, name);
    },
    async write(name: string, bytes: Buffer): Promise<string> {
      await writeFile(join(path, name), bytes);
      return join(path, name);
    },
    async cleanup(): Promise<void> {
      await rm(path, { recursive: true, force: true });
    },
  };
}

export async function ensureDir(path: string): Promise<string> {
  await mkdir(path, { recursive: true });
  return path;
}

export function testFacts(overrides: Partial<EnvironmentFacts> = {}): EnvironmentFacts {
  return {
    environmentId: 'env-test-local-win',
    backendKind: 'LOCAL_WINDOWS',
    os: 'Windows 11 Pro 10.0.26100',
    arch: 'X64',
    observationRevision: 'obs-test-0001',
    runtimeCapabilities: ['sharp-i0'],
    privilegeMode: 'STANDARD_USER',
    guiSession: true,
    filesystemCapabilities: ['read', 'write'],
    networkPolicy: 'OFFLINE',
    resources: { cpuCores: 8, memoryMb: 16384, freeDiskMb: 512000 },
    ...overrides,
  };
}
