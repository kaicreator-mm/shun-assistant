// Real image Provider adapter for the C-001 reference journey: sharp (libvips)
// as an I0 library-class provider. Decode is format-strict (magic bytes must
// match the declared format), resize uses Lanczos3 onto the exact shared
// target dimensions, JPEG/PNG output is format-preserving, and the capture
// date is explicitly merged back into the output EXIF (sharp's metadata
// keep-flags alone do not reliably round-trip DateTimeOriginal through a
// resize pipeline).
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import sharp, { type Metadata } from 'sharp';
import { readExifCaptureDate } from './exif.ts';
import {
  type BindingView,
  type ImageProvider,
  ImageProviderError,
  type ResizeOutcome,
  type ResizeRequest,
} from './provider.ts';
import { sniffContainer } from './sniff.ts';

export const SHARP_ADAPTER_ID = 'adapter.sharp-i0';
export const SHARP_BINDING_ID = 'binding-image-sharp-i0-local';
export const SHARP_PROVIDER_ID = 'provider.image.sharp';

/** JPEG encoder quality for the reference journey; fixed before execution. */
export const SHARP_JPEG_QUALITY = 94;

/** Keep in sync with the sharp entry in package.json. */
export const SHARP_DEPENDENCY_VERSION = '0.35.5';

function providerVersion(): string {
  const vips = sharp.versions.vips ?? 'unknown';
  return `sharp@${SHARP_DEPENDENCY_VERSION}+libvips-${vips}`;
}

export function sharpBindingView(): BindingView {
  return {
    bindingId: SHARP_BINDING_ID,
    providerId: SHARP_PROVIDER_ID,
    providerVersion: providerVersion(),
    adapterId: SHARP_ADAPTER_ID,
    interfaceClass: 'I0',
    verifierId: 'verifier.image-c001',
    environmentRequirements: { backendKind: 'LOCAL_WINDOWS' },
    unsupportedFormats: [],
  };
}

interface DecodedSource {
  width: number;
  height: number;
  captureDate: string | null;
}

async function decodeDeclared(
  bytes: Buffer,
  declaredFormat: 'JPG' | 'PNG',
  bindingId: string,
): Promise<DecodedSource> {
  const expected = declaredFormat === 'JPG' ? 'JPEG' : 'PNG';
  const container = sniffContainer(bytes);
  if (container !== expected) {
    throw new ImageProviderError(
      container === 'UNKNOWN' ? 'DECODE_FAILED' : 'UNSUPPORTED_INPUT',
      bindingId,
      `declared ${declaredFormat} but bytes are ${container}`,
    );
  }
  let meta: Metadata;
  try {
    meta = await sharp(bytes, { failOn: 'error' }).metadata();
  } catch (cause) {
    throw new ImageProviderError(
      'DECODE_FAILED',
      bindingId,
      `${declaredFormat} decode failed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  if (meta.width === undefined || meta.height === undefined) {
    throw new ImageProviderError('DECODE_FAILED', bindingId, 'decoder returned no dimensions');
  }
  // Baked orientation swaps the pixel grid for orientations 5..8.
  const swapped = meta.orientation !== undefined && meta.orientation >= 5 && meta.orientation <= 8;
  const captureDate = meta.exif ? readExifCaptureDate(meta.exif) : null;
  return {
    width: swapped ? meta.height : meta.width,
    height: swapped ? meta.width : meta.height,
    captureDate,
  };
}

/**
 * Runs the sharp pipeline to encoded bytes. Truncation/corruption that only
 * surfaces at full decode time (sharp metadata() is header-only and
 * optimistic) is classified as DECODE_FAILED — the input did not decode.
 */
async function encodePipeline(
  pipeline: ReturnType<typeof sharp>,
  declaredFormat: 'JPG' | 'PNG',
  bindingId: string,
): Promise<Buffer> {
  try {
    return declaredFormat === 'JPG'
      ? await pipeline.jpeg({ quality: SHARP_JPEG_QUALITY, mozjpeg: true }).toBuffer()
      : await pipeline.png({ compressionLevel: 6 }).toBuffer();
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new ImageProviderError(
      'DECODE_FAILED',
      bindingId,
      `${declaredFormat} decode/encode failed: ${message}`,
    );
  }
}

/** Creates the real sharp-backed ImageProvider for one binding view. */
export function makeSharpImageProvider(binding: BindingView = sharpBindingView()): ImageProvider {
  return {
    binding,
    async resizeTo(request: ResizeRequest): Promise<ResizeOutcome> {
      const source = await decodeDeclared(request.bytes, request.declaredFormat, binding.bindingId);
      const pipeline = sharp(request.bytes, { failOn: 'error' })
        .rotate()
        .resize(request.targetDims.width, request.targetDims.height, {
          fit: 'fill',
          kernel: 'lanczos3',
        });
      if (source.captureDate) {
        // Explicit merge: keep the input EXIF and pin the original capture
        // date (metadataPolicy.preserveCaptureDate). rotate() above bakes the
        // pixel orientation, so no orientation tag pinning is needed.
        pipeline.withExifMerge({ IFD0: { DateTimeOriginal: source.captureDate } });
      }
      const encoded = await encodePipeline(pipeline, request.declaredFormat, binding.bindingId);

      if (existsSync(request.targetPath)) {
        throw new ImageProviderError(
          'OUTPUT_COLLISION',
          binding.bindingId,
          `output already exists: ${request.targetPath}`,
        );
      }
      try {
        // 'wx' fails with EEXIST when the destination appeared meanwhile —
        // collision-safe without ever overwriting an existing file.
        await writeFile(request.targetPath, encoded, { flag: 'wx' });
      } catch (cause) {
        throw new ImageProviderError(
          'OUTPUT_COLLISION',
          binding.bindingId,
          `could not create output ${request.targetPath}: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
      return {
        captureDate: source.captureDate,
        width: request.targetDims.width,
        height: request.targetDims.height,
        byteLength: encoded.length,
      };
    },
  };
}
