import sharp from 'sharp';
import { describe, expect, it } from 'vitest';
import { readExifCaptureDate } from '../src/exif.ts';
import { pngBytes } from './helpers.ts';

describe('readExifCaptureDate', () => {
  it('reads DateTimeOriginal from a sharp-written EXIF blob', async () => {
    const bytes = await sharp({
      create: { width: 8, height: 8, channels: 3, background: '#123456' },
    })
      .withMetadata({ exif: { IFD0: { DateTimeOriginal: '2023:08:15 07:30:00' } } })
      .jpeg()
      .toBuffer();
    const meta = await sharp(bytes).metadata();
    expect(meta.exif).toBeDefined();
    expect(readExifCaptureDate(meta.exif ?? Buffer.alloc(0))).toBe('2023:08:15 07:30:00');
  });

  it('reads the date from a PNG eXIf chunk', async () => {
    const bytes = await pngBytes({
      width: 8,
      height: 8,
      seed: 7,
      captureDate: '2019:01:02 03:04:05',
    });
    const meta = await sharp(bytes).metadata();
    expect(meta.exif).toBeDefined();
    expect(readExifCaptureDate(meta.exif ?? Buffer.alloc(0))).toBe('2019:01:02 03:04:05');
  });

  it('returns null for absent or malformed EXIF', () => {
    expect(readExifCaptureDate(Buffer.alloc(0))).toBeNull();
    expect(readExifCaptureDate(Buffer.from('not exif data'))).toBeNull();
    expect(readExifCaptureDate(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]))).toBeNull();
  });
});
