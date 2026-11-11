import { createHash } from 'node:crypto';

/**
 * Minimal synthetic PE image builder for dependency-closure tests. Produces
 * a structurally valid (but of course non-executable) PE32+ or PE32 image
 * whose import table names exactly the DLLs requested, optionally with a
 * delay-load import directory. Evidence scripts reuse this so the fixture
 * bytes stay byte-identical between unit tests and host evidence.
 */
export interface SynthPeOptions {
  /** DLL names placed in the standard import directory. */
  readonly imports: readonly string[];
  /** DLL names placed in the delay-load import directory (index 13). */
  readonly delayImports?: readonly string[];
  /** COFF machine type; defaults to AMD64 (0x8664). */
  readonly machine?: number;
  /** Optional-header magic; defaults to PE32+ (0x20b). */
  readonly magic?: 0x20b | 0x10b;
}

const DOS_SIZE = 0x40;
const PE32_PLUS_MAGIC = 0x20b;
const OPT_HEADER_SIZE_PE32_PLUS = 240; // 112 fixed fields + 16 directories × 8
const OPT_HEADER_SIZE_PE32 = 224; // 96 fixed fields + 16 directories × 8
const SECTION_RVA = 0x1000;
const SECTION_RAW = 0x400;

export function buildSynthPe(options: SynthPeOptions): Buffer {
  const machine = options.machine ?? 0x8664;
  const pe32Plus = (options.magic ?? PE32_PLUS_MAGIC) === PE32_PLUS_MAGIC;
  const optHeaderSize = pe32Plus ? OPT_HEADER_SIZE_PE32_PLUS : OPT_HEADER_SIZE_PE32;
  const thunkSize = pe32Plus ? 8 : 4;
  const delayNames = options.delayImports ?? [];

  const importDirBytes = (options.imports.length + 1) * 20;
  const delayDirBytes = delayNames.length > 0 ? (delayNames.length + 1) * 32 : 0;
  const thunkArrayBytes = (count: number) => (count + 1) * thunkSize;
  const allNames = [...options.imports, ...delayNames];
  const hintNameBytes = allNames.reduce((sum, name) => sum + 3 + name.length, 0);
  const nameBytes = allNames.reduce((sum, name) => sum + name.length + 1, 0);
  const sectionDataSize =
    importDirBytes +
    delayDirBytes +
    thunkArrayBytes(options.imports.length) +
    (delayNames.length > 0 ? thunkArrayBytes(delayNames.length) : 0) +
    hintNameBytes +
    nameBytes +
    64;

  const image = Buffer.alloc(SECTION_RAW + sectionDataSize);
  // DOS header.
  image.write('MZ', 0, 'latin1');
  image.writeUInt32LE(DOS_SIZE, 0x3c);
  // PE signature + COFF header.
  const peOffset = DOS_SIZE;
  image.write('PE\0\0', peOffset, 'latin1');
  const coff = peOffset + 4;
  image.writeUInt16LE(machine, coff);
  image.writeUInt16LE(1, coff + 2); // one section
  image.writeUInt16LE(optHeaderSize, coff + 16);
  image.writeUInt16LE(0x2022, coff + 18); // DLL | LARGE_ADDRESS_AWARE
  // Optional header.
  const opt = coff + 20;
  image.writeUInt16LE(pe32Plus ? PE32_PLUS_MAGIC : 0x10b, opt);
  image.writeUInt32LE(SECTION_RVA + sectionDataSize, opt + 56); // SizeOfImage
  image.writeUInt32LE(SECTION_RAW, opt + 60); // SizeOfHeaders
  image.writeUInt16LE(3, opt + 68); // console subsystem
  image.writeUInt32LE(16, opt + (pe32Plus ? 108 : 92)); // NumberOfRvaAndSizes
  const directories = opt + (pe32Plus ? 112 : 96);
  const fileToRva = (fileOffset: number) => SECTION_RVA + (fileOffset - SECTION_RAW);

  // Single-section layout: import dir, delay dir, thunk arrays, hint/name
  // blobs, bare DLL-name pool.
  let cursor = SECTION_RAW;
  const importDirFile = cursor;
  cursor += importDirBytes;
  const delayDirFile = cursor;
  cursor += delayDirBytes;
  const importThunkFile = cursor;
  cursor += thunkArrayBytes(options.imports.length);
  const delayThunkFile = cursor;
  cursor += delayNames.length > 0 ? thunkArrayBytes(delayNames.length) : 0;
  const hintNamesFile = cursor;
  cursor += hintNameBytes;
  const namesFile = cursor;

  const nameOffsets = new Map<string, number>();
  let nameCursor = namesFile;
  for (const name of allNames) {
    nameOffsets.set(name, nameCursor);
    image.write(name, nameCursor, 'latin1');
    nameCursor += name.length + 1;
  }
  const hintOffsets = new Map<string, number>();
  let hintCursor = hintNamesFile;
  for (const name of allNames) {
    hintOffsets.set(name, hintCursor);
    image.writeUInt16LE(0, hintCursor); // hint
    image.write(name, hintCursor + 2, 'latin1');
    hintCursor += 3 + name.length;
  }
  const writeThunkArray = (base: number, names: readonly string[]) => {
    let at = base;
    for (const name of names) {
      const rva = fileToRva(hintOffsets.get(name) ?? 0);
      if (pe32Plus) image.writeBigUInt64LE(BigInt(rva), at);
      else image.writeUInt32LE(rva, at);
      at += thunkSize;
    }
  };
  writeThunkArray(importThunkFile, options.imports);
  if (delayNames.length > 0) writeThunkArray(delayThunkFile, delayNames);
  for (let index = 0; index < options.imports.length; index += 1) {
    const at = importDirFile + index * 20;
    image.writeUInt32LE(fileToRva(importThunkFile), at); // OriginalFirstThunk
    image.writeUInt32LE(fileToRva(nameOffsets.get(options.imports[index] ?? '') ?? 0), at + 12);
    image.writeUInt32LE(fileToRva(importThunkFile), at + 16); // FirstThunk
  }
  if (delayNames.length > 0) {
    for (let index = 0; index < delayNames.length; index += 1) {
      const at = delayDirFile + index * 32;
      image.writeUInt32LE(1, at); // grAttrs = dlattrRva
      image.writeUInt32LE(fileToRva(nameOffsets.get(delayNames[index] ?? '') ?? 0), at + 4);
      image.writeUInt32LE(fileToRva(delayThunkFile), at + 12); // pIAT
      image.writeUInt32LE(fileToRva(delayThunkFile), at + 16); // pINT
    }
  }
  if (options.imports.length > 0) {
    image.writeUInt32LE(fileToRva(importDirFile), directories + 8);
    image.writeUInt32LE(importDirBytes, directories + 12);
  }
  if (delayNames.length > 0) {
    image.writeUInt32LE(fileToRva(delayDirFile), directories + 13 * 8);
    image.writeUInt32LE(delayDirBytes, directories + 13 * 8 + 4);
  }
  // Section table.
  const sectionTable = opt + optHeaderSize;
  image.write('.rdata\0\0', sectionTable, 'latin1');
  image.writeUInt32LE(sectionDataSize, sectionTable + 8); // VirtualSize
  image.writeUInt32LE(SECTION_RVA, sectionTable + 12); // VirtualAddress
  image.writeUInt32LE(sectionDataSize, sectionTable + 16); // SizeOfRawData
  image.writeUInt32LE(SECTION_RAW, sectionTable + 20); // PointerToRawData
  return image;
}

export function synthPeSha256(options: SynthPeOptions): string {
  return createHash('sha256').update(buildSynthPe(options)).digest('hex');
}
