// ImageProvider seam for the C-001 vertical. The vertical owns this adapter
// port (not the shared resolver): candidates handed to the executor are
// already trust-screened upstream; the vertical only ranks them and executes.
import type { EnvironmentRequirements, InterfaceClass } from '@shun/contracts';
import type { Dims } from './dims.ts';

export type ImageFormat = 'JPG' | 'PNG';

/** Provider/binding facts the vertical needs for ranking and receipts. */
export interface BindingView {
  bindingId: string;
  providerId: string;
  /** Exact provider identity string (e.g. "sharp@0.35.5+libvips-1.16.0"). */
  providerVersion: string;
  adapterId: string;
  interfaceClass: InterfaceClass;
  verifierId: string;
  environmentRequirements: EnvironmentRequirements;
  /** Formats this provider refuses; the executor routes around them. */
  unsupportedFormats: readonly ImageFormat[];
}

export type ProviderFailureCode =
  | 'DECODE_FAILED'
  | 'UNSUPPORTED_INPUT'
  | 'OUTPUT_COLLISION'
  | 'OUTPUT_VERIFY_FAILED';

/** Typed provider failure. Never represents a caller contract violation. */
export class ImageProviderError extends Error {
  readonly code: ProviderFailureCode;
  readonly bindingId: string;

  constructor(code: ProviderFailureCode, bindingId: string, message: string) {
    super(message);
    this.name = 'ImageProviderError';
    this.code = code;
    this.bindingId = bindingId;
  }
}

export interface ResizeRequest {
  bytes: Buffer;
  declaredFormat: ImageFormat;
  /** Exact encoded target dimensions (shared scaledDims math). */
  targetDims: Dims;
  /** Collision-safe destination path; the file must not exist yet. */
  targetPath: string;
}

export interface ResizeOutcome {
  /** Capture date the provider merged into the output, if any. */
  captureDate: string | null;
  width: number;
  height: number;
  byteLength: number;
}

/**
 * One real image Provider adapter (I0 library class for the reference
 * journey). Implementations decode the declared-format bytes, resize to the
 * exact target dimensions, encode format-preserving output with the capture
 * date preserved, and write it collision-safe to targetPath.
 */
export interface ImageProvider {
  readonly binding: BindingView;
  resizeTo(request: ResizeRequest): Promise<ResizeOutcome>;
}
