// Deterministic resize-dimension math shared by the provider adapter, the
// precommitted oracle and the verifier (C-001). Both the executed output and
// the lossless reference MUST land on exactly these dimensions so the SSIM
// oracle compares same-size images.

export interface Dims {
  width: number;
  height: number;
}

/**
 * Target dimensions for a shrink-to-long-edge resize. Never upscales: an
 * image whose long edge is already within the bound keeps its exact size.
 * Rounding that overshoots the bound is clamped back onto it so the
 * "longest edge <= maxLongEdgePx" invariant holds by construction.
 */
export function scaledDims(width: number, height: number, maxLongEdgePx: number): Dims {
  const longEdge = Math.max(width, height);
  if (longEdge <= maxLongEdgePx) {
    return { width, height };
  }
  const scale = maxLongEdgePx / longEdge;
  let w = Math.max(1, Math.round(width * scale));
  let h = Math.max(1, Math.round(height * scale));
  if (Math.max(w, h) > maxLongEdgePx) {
    if (w >= h) {
      w = maxLongEdgePx;
    } else {
      h = maxLongEdgePx;
    }
  }
  return { width: w, height: h };
}
