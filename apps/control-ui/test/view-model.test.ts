import { describe, expect, it } from 'vitest';
// Cross-package import is deliberate: the fallback table in the UI must cover
// the control-api's closed error taxonomy, and this test enforces it.
import { CONTROL_ERROR_CODES } from '../../control-api/src/errors.ts';
import {
  decisionGuard,
  FALLBACK_MESSAGES,
  failureLines,
  fallbackFor,
  localOnlyBadge,
  previewBlocks,
  progressLines,
  recoveryLines,
  residueLines,
  STATE_LABELS,
  stateLabel,
  stateTone,
  taskCard,
} from '../public/view-model.js';

const snapshotBase = {
  taskId: 'task-1',
  title: 'Clean up the DemoApp cache leftovers',
  state: 'AWAITING_AUTHORIZATION',
  revision: 3,
  createdAt: '2026-10-10T08:00:00.000Z',
  updatedAt: '2026-10-10T08:00:00.000Z',
  progress: [
    { at: '2026-10-10T08:00:00.000Z', state: 'RECEIVED', note: 'Goal received.' },
    { at: '2026-10-10T08:00:00.000Z', state: 'AWAITING_AUTHORIZATION', note: 'Approval required.' },
  ],
  approval: {
    approvalId: 'approval-task-1',
    status: 'PENDING',
    summary: 'Shun wants to delete 6 regenerable files.',
    planHash: 'a'.repeat(64),
    expiresAt: '2026-10-10T08:15:00.000Z',
  },
  localOnly: { enforced: true, externalDisclosure: 'FORBIDDEN' },
};

const previewBase = {
  taskId: 'task-1',
  planHash: 'a'.repeat(64),
  capabilityId: 'system.storage.diagnose_bounded_action',
  riskClass: 'R2',
  riskStatement:
    'Destructive or potentially harmful operation. It requires a plan, this preview, a recovery ' +
    'disposition, and your explicit approval (or an equally specific durable policy) before ' +
    'anything runs, followed by verification.',
  actions: [
    {
      actionId: 'action-cleanup-001',
      op: 'file.delete',
      description: 'Step `action-cleanup-001` runs `file.delete` with no special permissions.',
      requiredPrivilege: 'NONE',
      network: { allowed: false },
    },
  ],
  verification: {
    summary: 'After execution Shun verifies the outcome.',
    checks: ['reclaimed-space'],
  },
  recovery: { summary: 'If something interrupts this task, Shun reconciles before retrying.' },
  requiresExplicitApproval: true,
  policySnapshotRevision: 'pol-snap-2026-10-10-a',
  generatedAt: '2026-10-10T08:00:00.000Z',
};

describe('predictable fallback: every typed error code has a human sentence', () => {
  it('covers the full control-api error taxonomy', () => {
    for (const code of CONTROL_ERROR_CODES) {
      const message = FALLBACK_MESSAGES[code];
      expect(message, `missing fallback for ${code}`).toBeTruthy();
      expect(message?.length).toBeGreaterThan(10);
    }
  });

  it('never throws on unknown codes and still says nothing was changed', () => {
    const message = fallbackFor('SOME_FUTURE_CODE');
    expect(message).toContain('Nothing was changed');
  });
});

describe('task state rendering', () => {
  it('labels all 13 reference task states', () => {
    const states = [
      'RECEIVED',
      'INTERPRETING',
      'CLARIFICATION',
      'RESOLVING',
      'PLANNED',
      'AWAITING_AUTHORIZATION',
      'EXECUTING',
      'VERIFYING',
      'LIFECYCLE_RECONCILIATION',
      'SUCCEEDED',
      'FAILED',
      'CANCELLED',
      'NEEDS_INTERVENTION',
    ];
    expect(Object.keys(STATE_LABELS).sort()).toEqual([...states].sort());
    for (const state of states) expect(stateLabel(state)).not.toBe(state);
  });

  it('unknown state falls back to the raw value, not a crash', () => {
    expect(stateLabel('SOME_FUTURE_STATE')).toBe('SOME_FUTURE_STATE');
    expect(stateTone('SOME_FUTURE_STATE')).toBe('neutral');
  });

  it('renders the approval-pending card with a warn tone', () => {
    const card = taskCard(snapshotBase);
    expect(card.stateLabel).toBe('Waiting for your approval');
    expect(card.tone).toBe('warn');
    expect(card.detailLine).toContain('approval pending');
  });
});

describe('preview rendering and decision guard (misleading-preview prevention)', () => {
  it('always shows the fixed risk statement first, bound to the plan hash', () => {
    const blocks = previewBlocks(previewBase);
    expect(blocks.riskStatement).toContain('Destructive');
    expect(blocks.requiresExplicitApproval).toBe(true);
    expect(blocks.planHash).toBe(previewBase.planHash);
    expect(blocks.bullets.length).toBeGreaterThanOrEqual(3);
  });

  it('blocks the decision when the displayed plan hash is not the approval’s', () => {
    const guard = decisionGuard({
      previewPlanHash: 'b'.repeat(64),
      approvalPlanHash: 'a'.repeat(64),
      enteredPlanHash: 'b'.repeat(64),
    });
    expect(guard.allowed).toBe(false);
    expect(guard.reason).toContain('plan changed');
  });

  it('blocks the decision when the entered hash drifted from what was shown', () => {
    const guard = decisionGuard({
      previewPlanHash: 'a'.repeat(64),
      approvalPlanHash: 'a'.repeat(64),
      enteredPlanHash: 'c'.repeat(64),
    });
    expect(guard.allowed).toBe(false);
    expect(guard.reason).toContain('reload the preview');
  });

  it('allows the decision only when all three hashes agree', () => {
    const guard = decisionGuard({
      previewPlanHash: 'a'.repeat(64),
      approvalPlanHash: 'a'.repeat(64),
      enteredPlanHash: 'a'.repeat(64),
    });
    expect(guard).toEqual({ allowed: true, reason: '' });
  });
});

describe('recovery and failure usability', () => {
  it('explains an uncertain destructive state and demands reconciliation first', () => {
    const lines = recoveryLines({
      ...snapshotBase,
      recovery: {
        classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        detail: 'The journal stopped inside the execution window.',
        reconciled: false,
      },
    });
    expect(lines[0]).toContain('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(lines[0]).toContain('reconcile');
    expect(lines[0]).toContain('Not reconciled yet.');
  });

  it('reports failed verification honestly', () => {
    const lines = failureLines({
      ...snapshotBase,
      failure: {
        code: 'QUALITY_ORACLE_FAILED',
        message: 'The result was produced but failed semantic verification.',
      },
    });
    expect(lines[0]).toContain('failed semantic verification');
    expect(lines[0]).toContain('QUALITY_ORACLE_FAILED');
  });
});

describe('progress and residue readability', () => {
  it('renders progress steps with labels and notes', () => {
    const lines = progressLines(snapshotBase);
    expect(lines).toHaveLength(2);
    expect(lines[0]?.label).toBe('Received');
    expect(lines[1]?.note).toBe('Approval required.');
  });

  it('renders residue as a readable summary with protected-file assurance', () => {
    const lines = residueLines({
      taskId: 'task-1',
      generatedAt: '2026-10-10T08:00:00.000Z',
      headline: 'Found 6 leftover items in 3 groups (~76.2 MB).',
      groups: [{ label: 'Regenerable cache files', count: 4, readableBytes: '~65.0 MB' }],
      protectedUntouchedCount: 1,
      detailAvailable: true,
    });
    expect(lines[0]).toContain('6 leftover items');
    expect(lines.some((line) => line.includes('never touched'))).toBe(true);
    expect(lines.some((line) => line.includes('~65.0 MB'))).toBe(true);
  });
});

describe('local-only disclosure badge', () => {
  it('discloses local-only enforcement and externalDisclosure honestly', () => {
    expect(localOnlyBadge(snapshotBase)).toBe('Local only — nothing leaves this computer');
    expect(
      localOnlyBadge({
        ...snapshotBase,
        localOnly: { enforced: false, externalDisclosure: 'POLICY_CONTROLLED' },
      }),
    ).toBe('External disclosure: POLICY_CONTROLLED');
  });
});
