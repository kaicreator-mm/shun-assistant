// Capability revision comparison for binding support windows (L2 §4.3).
// Revisions in the frozen reference registry use the `r<N>` form; anything
// else cannot be ordered and fails closed instead of guessing.
const R_REVISION = /^[rR](\d+)$/;

export function revisionOrder(revision: string): number | undefined {
  const match = R_REVISION.exec(revision);
  return match ? Number(match[1]) : undefined;
}

/** True when `revision` lies inside the inclusive `[min, max?]` support window. */
export function revisionInRange(revision: string, range: { min: string; max?: string }): boolean {
  const rev = revisionOrder(revision);
  const min = revisionOrder(range.min);
  if (rev === undefined || min === undefined || rev < min) return false;
  if (range.max !== undefined) {
    const max = revisionOrder(range.max);
    if (max === undefined || rev > max) return false;
  }
  return true;
}
