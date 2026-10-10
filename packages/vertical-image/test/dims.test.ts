import { describe, expect, it } from 'vitest';
import { scaledDims } from '../src/dims.ts';

describe('scaledDims', () => {
  it('shrinks landscape to the exact long-edge bound', () => {
    expect(scaledDims(4000, 3000, 1600)).toEqual({ width: 1600, height: 1200 });
  });

  it('shrinks portrait to the exact long-edge bound', () => {
    expect(scaledDims(3000, 4000, 1600)).toEqual({ width: 1200, height: 1600 });
  });

  it('keeps dimensions when the long edge is already within the bound (no upscale)', () => {
    expect(scaledDims(1200, 800, 1600)).toEqual({ width: 1200, height: 800 });
    expect(scaledDims(1600, 900, 1600)).toEqual({ width: 1600, height: 900 });
  });

  it('handles odd aspect ratios deterministically and never exceeds the bound', () => {
    for (const [w, h] of [
      [3999, 2371],
      [1801, 3599],
      [1921, 1081],
      [777, 1599],
      [2401, 1601],
    ] as const) {
      const out = scaledDims(w, h, 1600);
      expect(Math.max(out.width, out.height)).toBeLessThanOrEqual(1600);
      expect(out.width).toBeGreaterThanOrEqual(1);
      expect(out.height).toBeGreaterThanOrEqual(1);
    }
  });

  it('is deterministic', () => {
    expect(scaledDims(3999, 2371, 1600)).toEqual(scaledDims(3999, 2371, 1600));
  });
});
