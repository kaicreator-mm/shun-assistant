// Minimal EXIF/TIFF walker for one purpose: reading the capture date
// (DateTimeOriginal, tag 0x9003) from an EXIF blob. Real cameras place the
// tag in the Exif SubIFD; sharp-written EXIF places it in IFD0 — both
// layouts are handled by walking the IFD0 -> ExifIFD pointer chain.

const TAG_DATETIME_ORIGINAL = 0x9003;
const TAG_EXIF_IFD_POINTER = 0x8769;
const TYPE_ASCII = 2;
const MAX_IFD_ENTRIES = 512;
const MAX_IFD_DEPTH = 3;

function readAsciiValue(
  exif: Buffer,
  tiffStart: number,
  entry: number,
  little: boolean,
): string | null {
  const type = little ? exif.readUInt16LE(entry + 2) : exif.readUInt16BE(entry + 2);
  if (type !== TYPE_ASCII) {
    return null;
  }
  const count = little ? exif.readUInt32LE(entry + 4) : exif.readUInt32BE(entry + 4);
  const valueOffset = little ? exif.readUInt32LE(entry + 8) : exif.readUInt32BE(entry + 8);
  const dataAt = count <= 4 ? entry + 8 : tiffStart + valueOffset;
  if (count === 0 || dataAt + count > exif.length) {
    return null;
  }
  const value = exif
    .toString('latin1', dataAt, dataAt + count)
    .replaceAll('\u0000', '')
    .trim();
  return value.length > 0 ? value : null;
}

/**
 * Extracts the capture date string (e.g. "2024:05:01 10:20:30") from an EXIF
 * blob, or null when the blob is absent/malformed or carries no
 * DateTimeOriginal. Absence is a normal outcome: PNG sources usually have no
 * capture date and the preservation requirement only applies "when present".
 */
export function readExifCaptureDate(exif: Buffer): string | null {
  // TIFF field offsets are relative to the TIFF header, which sits after the
  // optional 6-byte "Exif\0\0" alignement block.
  let tiffStart = 0;
  if (exif.length >= 6 && exif.toString('latin1', 0, 4) === 'Exif') {
    tiffStart = 6;
  }
  if (exif.length < tiffStart + 8) {
    return null;
  }
  const bo = exif.toString('latin1', tiffStart, tiffStart + 2);
  const little = bo === 'II';
  if (!little && bo !== 'MM') {
    return null;
  }
  const u16 = (p: number) =>
    little ? exif.readUInt16LE(tiffStart + p) : exif.readUInt16BE(tiffStart + p);
  const u32 = (p: number) =>
    little ? exif.readUInt32LE(tiffStart + p) : exif.readUInt32BE(tiffStart + p);
  if (u16(2) !== 42) {
    return null;
  }
  const visited = new Set<number>();
  const visit = (ifdOffset: number, depth: number): string | null => {
    if (depth > MAX_IFD_DEPTH || visited.has(ifdOffset)) {
      return null;
    }
    visited.add(ifdOffset);
    if (ifdOffset <= 0 || tiffStart + ifdOffset + 2 > exif.length) {
      return null;
    }
    const entryCount = u16(ifdOffset);
    if (entryCount > MAX_IFD_ENTRIES) {
      return null;
    }
    for (let i = 0; i < entryCount; i++) {
      const entry = tiffStart + ifdOffset + 2 + i * 12;
      if (entry + 12 > exif.length) {
        return null;
      }
      const tag = u16(ifdOffset + 2 + i * 12);
      if (tag === TAG_DATETIME_ORIGINAL) {
        const value = readAsciiValue(exif, tiffStart, entry, little);
        if (value) {
          return value;
        }
      }
      if (tag === TAG_EXIF_IFD_POINTER) {
        const nested = visit(u32(ifdOffset + 2 + i * 12 + 8), depth + 1);
        if (nested) {
          return nested;
        }
      }
    }
    return null;
  };
  return visit(u32(4), 0);
}
