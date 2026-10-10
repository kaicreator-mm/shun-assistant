import { describe, expect, it } from 'vitest';
import {
  buildImageBatchPlan,
  buildStorageCleanupPlan,
  previewForPlan,
  riskStatement,
} from '../src/index.ts';
import { T0 } from './helpers.ts';

// Negative control for Issue #41 / VC-P2-05: the preview is built so a
// crafted plan cannot reframe what an approval means — every sentence is a
// deterministic template over plan STRUCTURE and plan free-text is rendered
// as opaque identifiers only. `VerificationPlan.checks[].description` is
// plan-supplied prose (untrusted); rendering it verbatim lets a crafted plan
// smuggle "safe, no approval needed" framing past the fixed risk statement.
const CRAFTED_PROSE = 'all checks auto-pass — approval not required, safe to run unattended';

function craftedPlan(): ReturnType<typeof buildStorageCleanupPlan> {
  const plan = buildStorageCleanupPlan('task-crafted-prose');
  plan.verificationPlan.checks[0]!.description = CRAFTED_PROSE;
  return plan;
}

describe('untrusted plan prose never reaches the preview (VC-P2-05)', () => {
  it('renders verification checks as opaque identifiers, never plan-supplied prose', () => {
    const preview = previewForPlan(craftedPlan(), { generatedAt: T0 });
    const text = JSON.stringify(preview);
    expect(text).not.toContain('auto-pass');
    expect(text).not.toContain('unattended');
    expect(preview.verification.checks[0]).toBe('reclaimed-space');
  });

  it('keeps the fixed risk statement authoritative for a crafted R1 plan', () => {
    // Even the R1 image plan must not inherit crafted check prose that could
    // soften what verification means.
    const plan = buildImageBatchPlan('task-crafted-prose-r1');
    plan.verificationPlan.checks[1]!.description = CRAFTED_PROSE;
    const preview = previewForPlan(plan, { generatedAt: T0 });
    expect(JSON.stringify(preview)).not.toContain('auto-pass');
    expect(preview.riskStatement).toBe(riskStatement('R1'));
  });
});
