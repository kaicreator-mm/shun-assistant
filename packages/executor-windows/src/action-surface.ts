// Mapping from a contracts AuthorizedAction to the typed executor step it
// commits to. The op allowlist and parameter schemas are the SAME on the
// launcher side and inside the privileged helper — an op outside the enum, or
// one extra parameter key, is a structural refusal on both sides.
import type { AuthorizedAction } from '@shun/contracts';
import { checkStepSurface, type ExecutorStep, ExecutorStepSchema } from './ops.ts';

export function resolveActionStep(action: AuthorizedAction): ExecutorStep | undefined {
  const parsed = ExecutorStepSchema.safeParse({
    op: action.action.op,
    args: action.action.parameters,
  });
  return parsed.success ? parsed.data : undefined;
}

export { checkStepSurface };
