import { describe, expect, it } from 'vitest';
import { sniffContainer } from '../src/sniff.ts';

describe('sniffContainer', () => {
  it('detects JPEG magic bytes', () => {
    expect(sniffContainer(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]))).toBe('JPEG');
  });

  it('detects PNG signature', () => {
    expect(
      sniffContainer(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00])),
    ).toBe('PNG');
  });

  it('detects GIF, BMP and TIFF containers', () => {
    expect(sniffContainer(Buffer.from(`GIF89a${'x'.repeat(8)}`, 'latin1'))).toBe('GIF');
    expect(sniffContainer(Buffer.from(`BM${'x'.repeat(8)}`, 'latin1'))).toBe('BMP');
    expect(sniffContainer(Buffer.from(`II*\u0000${'x'.repeat(8)}`, 'latin1'))).toBe('TIFF');
    expect(sniffContainer(Buffer.from(`MM\u0000*${'x'.repeat(8)}`, 'latin1'))).toBe('TIFF');
  });

  it('detects WEBP and ISOBMFF families', () => {
    const webp = Buffer.from('RIFF' + '\u0000\u0000\u0000\u0000' + 'WEBP' + 'VP8 ', 'latin1');
    expect(sniffContainer(webp)).toBe('WEBP');
    const heic = Buffer.from(`\u0000\u0000\u0000\u0000ftypheic${'x'.repeat(8)}`, 'latin1');
    expect(sniffContainer(heic)).toBe('HEIC');
    const avif = Buffer.from(`\u0000\u0000\u0000\u0000ftypavif${'x'.repeat(8)}`, 'latin1');
    expect(sniffContainer(avif)).toBe('AVIF');
  });

  it('reports UNKNOWN for corrupt or alien bytes', () => {
    expect(sniffContainer(Buffer.from('not an image at all'))).toBe('UNKNOWN');
    expect(sniffContainer(Buffer.alloc(0))).toBe('UNKNOWN');
  });
});
