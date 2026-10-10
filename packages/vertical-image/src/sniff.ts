// Magic-byte container sniffing for C-001 inputs. The declared format is
// authoritative; sniffing decides whether undecodable bytes are a *different*
// supported container (UNSUPPORTED_INPUT) or genuinely corrupt data
// (DECODE_FAILED).

export type ImageContainer =
  | 'JPEG'
  | 'PNG'
  | 'GIF'
  | 'WEBP'
  | 'BMP'
  | 'TIFF'
  | 'AVIF'
  | 'HEIC'
  | 'UNKNOWN';

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

function ascii(bytes: Buffer, start: number, end: number): string {
  return bytes.toString('latin1', start, end);
}

export function sniffContainer(bytes: Buffer): ImageContainer {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return 'JPEG';
  }
  if (bytes.length >= PNG_SIGNATURE.length && PNG_SIGNATURE.every((b, i) => bytes[i] === b)) {
    return 'PNG';
  }
  if (bytes.length >= 6 && ascii(bytes, 0, 3) === 'GIF') {
    return 'GIF';
  }
  if (bytes.length >= 12 && ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 12) === 'WEBP') {
    return 'WEBP';
  }
  if (bytes.length >= 2 && ascii(bytes, 0, 2) === 'BM') {
    return 'BMP';
  }
  if (
    bytes.length >= 4 &&
    (ascii(bytes, 0, 4) === 'II*\u0000' || ascii(bytes, 0, 4) === 'MM\u0000*')
  ) {
    return 'TIFF';
  }
  if (bytes.length >= 12 && ascii(bytes, 4, 8) === 'ftyp') {
    const brand = ascii(bytes, 8, 12);
    return brand.startsWith('av') ? 'AVIF' : 'HEIC';
  }
  return 'UNKNOWN';
}
