// minizip.mjs — minimal stored-zip builder for malicious-archive fixtures.
// Only used by negative scenarios (crafted hostile archives); the positive
// pipeline always consumes real vendor artifacts.
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * @param {Array<{name: string, data: Buffer, symlink?: boolean}>} entries
 */
export function buildStoredZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const crc = crc32(entry.data);
    const size = entry.data.length;
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0, 6);
    lfh.writeUInt16LE(0, 8);
    lfh.writeUInt16LE(0, 10);
    lfh.writeUInt16LE(0x2100, 12);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(size, 18);
    lfh.writeUInt32LE(size, 22);
    lfh.writeUInt16LE(name.length, 26);
    lfh.writeUInt16LE(0, 28);
    locals.push(lfh, name, entry.data);

    const madeBy = entry.symlink ? (3 << 8) | 20 : 20;
    const externalAttrs = entry.symlink ? (0xa1ff << 16) >>> 0 : 0;
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(madeBy, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0, 8);
    cdh.writeUInt16LE(0, 10);
    cdh.writeUInt16LE(0, 12);
    cdh.writeUInt16LE(0x2100, 14);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(size, 20);
    cdh.writeUInt32LE(size, 24);
    cdh.writeUInt16LE(name.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE(externalAttrs, 38);
    cdh.writeUInt32LE(offset, 42);
    centrals.push(cdh, name);
    offset += 30 + name.length + size;
  }
  const centralStart = offset;
  let centralSize = 0;
  for (const b of centrals) centralSize += b.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralStart, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, ...centrals, eocd]);
}

export async function writeMaliciousZip(path, entries) {
  const buffer = buildStoredZip(entries);
  await writeFile(path, buffer);
  return {
    path,
    sizeBytes: buffer.length,
    sha256: createHash('sha256').update(buffer).digest('hex'),
  };
}

/** Flip one byte in the middle of a file to produce a tampered copy. */
export async function writeTamperedCopy(sourcePath, destPath) {
  const { readFile } = await import('node:fs/promises');
  const bytes = await readFile(sourcePath);
  const mid = bytes.length >> 1;
  bytes[mid] ^= 0xff;
  await writeFile(destPath, bytes);
  return {
    path: destPath,
    sizeBytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    flippedOffset: mid,
  };
}
