import { describe, expect, it } from 'vitest';
import {
  AUTHORITY_POLARITIES,
  LOCALES,
  STRINGS,
  type StringEntry,
  stringsAudit,
  t,
} from '../../../../apps/control-ui/public/v03/strings.js';
import {
  APPROVED_TEMPLATE_IDS,
  advisoryView,
  buildStepOutcome,
  consentView,
  currentStepModel,
  historyModel,
  outcomeStatusView,
  refusalView,
  replayGuard,
  scopeContentGuard,
  scopeSummary,
  userDecisionRelay,
} from '../../../../apps/control-ui/public/v03/view-model.js';
import {
  APPROVED_STEP_TEMPLATES,
  type StepSpec,
} from '../../../../packages/domain-computer/src/guided/guided-contract.ts';

/** A catalog shape is the exported record; mutations in negative tests keep it. */
type Catalog = Record<string, Record<string, StringEntry>>;

/** Guarded accessors: noUncheckedIndexedAccess makes direct indexing optional. */
function bucket(locale: 'en' | 'zh'): Record<string, StringEntry> {
  const found = STRINGS[locale];
  if (!found) throw new Error(`missing locale bucket ${locale}`);
  return found;
}

function entry(locale: 'en' | 'zh', key: string): StringEntry {
  const found = bucket(locale)[key];
  if (!found) throw new Error(`missing entry ${locale}/${key}`);
  return found;
}

const NOW = 2_000;
const TEMPLATE_BY_ID = new Map(
  APPROVED_STEP_TEMPLATES.map((template) => [template.templateId, template]),
);

function makeStep(templateId: string, overrides: Partial<StepSpec> = {}): StepSpec {
  const template = TEMPLATE_BY_ID.get(templateId);
  if (!template) throw new Error(`unknown template ${templateId}`);
  return {
    schema: 'shun.guided.step-spec.v1',
    journeyId: 'journey-01',
    taskId: 'task-01',
    stepId: 'guided:step-01',
    caseRef: { snapshotId: 'snapshot-01', digest: 'a'.repeat(64) },
    eligibilityCode: 'GUIDED_STEP_ELIGIBLE',
    templateRef: {
      artifactId: template.templateId,
      version: template.version,
      digest: template.digest,
    },
    kind: template.kind,
    titleKey: template.titleKey,
    formSchema: template.formSchema,
    allowedEvents: template.allowedEvents,
    evidenceRefs: [],
    issuedAtUnixMs: 1_000,
    validUntilUnixMs: 60_000,
    ...overrides,
  };
}

function outcomeFor(
  step: StepSpec,
  fieldId: string,
  value: string | boolean,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema: 'shun.guided.step-outcome.v1',
    journeyId: step.journeyId,
    taskId: step.taskId,
    stepId: step.stepId,
    caseRef: { snapshotId: step.caseRef.snapshotId, digest: step.caseRef.digest },
    event: 'USER_SUBMIT',
    source: 'USER',
    sourceRef: 'ui:session-01',
    answers: [{ fieldId, value }],
    evidenceRefs: [],
    occurredAtUnixMs: 2_500,
    ...overrides,
  };
}

/** Exact key names that must never appear anywhere in UI-produced objects. */
const FORBIDDEN_AUTHORITY_KEYS = [
  'grant',
  'grants',
  'approval',
  'approvals',
  'permit',
  'authorization',
];

function collectKeys(value: unknown): string[] {
  if (value === null || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap((item) => collectKeys(item));
  return Object.entries(value).flatMap(([key, item]) => [key, ...collectKeys(item)]);
}

function assertNoAuthorityShape(value: unknown): void {
  const keys = collectKeys(value);
  for (const forbidden of FORBIDDEN_AUTHORITY_KEYS) {
    expect(keys, `forbidden authority key "${forbidden}" leaked`).not.toContain(forbidden);
  }
}

/**
 * Test-side semantic oracle: per polarity and locale, anchor vocabulary the
 * human sentence must contain. This is deliberately NOT part of the shipped
 * catalog — the gate on CN/EN authorization semantics lives here, so an
 * in-catalog edit cannot weaken it.
 */
const ANCHORS: Record<string, Record<string, string[]>> = {
  APPROVE: { en: ['approv'], zh: ['批准'] },
  REFUSE: {
    en: ['refus', 'never', 'expired', 'replay', 'cannot', 'not ', 'block'],
    zh: ['拒绝', '绝不', '不会', '已过期', '不能', '不是', '阻止'],
  },
  UNKNOWN: { en: ['unknown'], zh: ['未知'] },
  PAUSED: { en: ['paus'], zh: ['暂停'] },
  SCOPE: { en: ['scope', 'folder', 'root'], zh: ['范围', '根目录', '文件夹'] },
  CONSENT: {
    en: ['approv', 'consent', 'grant', 'decision', 'relay'],
    zh: ['批准', '同意', '授权', '决定', '转发'],
  },
};

function anchorProblems(catalog: Catalog): string[] {
  const problems: string[] = [];
  for (const locale of LOCALES) {
    const bucket = catalog[locale] ?? {};
    for (const [key, entry] of Object.entries(bucket)) {
      if (!entry.authorityRelevant) continue;
      const anchors = ANCHORS[entry.polarity ?? '']?.[locale] ?? [];
      const hit = anchors.some((anchor) => entry.text.toLowerCase().includes(anchor.toLowerCase()));
      if (!hit) problems.push(`${locale}/${key}: no ${entry.polarity} anchor in "${entry.text}"`);
    }
  }
  return problems;
}

describe('T10 CN/EN string catalog: parity and authority semantics', () => {
  it('ships both locales with identical key sets and passes the structural audit', () => {
    expect([...LOCALES]).toEqual(['en', 'zh']);
    const enKeys = Object.keys(bucket('en')).sort();
    const zhKeys = Object.keys(bucket('zh')).sort();
    expect(enKeys.length).toBeGreaterThan(20);
    expect(zhKeys).toEqual(enKeys);
    expect(stringsAudit(STRINGS)).toEqual({ ok: true });
  });

  it('carries the same authorityRelevant flag and polarity for every key in both locales', () => {
    for (const key of Object.keys(bucket('en'))) {
      const en = entry('en', key);
      const zh = entry('zh', key);
      expect(zh.authorityRelevant).toBe(en.authorityRelevant);
      if (en.authorityRelevant) {
        expect(en.polarity, `authority key ${key} needs a polarity`).toBeDefined();
        expect(zh.polarity).toBe(en.polarity);
        expect(AUTHORITY_POLARITIES).toContain(en.polarity);
      } else {
        expect(en.polarity).toBeUndefined();
        expect(zh.polarity).toBeUndefined();
      }
      expect(en.text.length).toBeGreaterThan(0);
      expect(zh.text.length).toBeGreaterThan(0);
    }
  });

  it('keeps CN and EN authorization wording semantically pinned (anchor oracle)', () => {
    expect(anchorProblems(STRINGS)).toEqual([]);
  });

  it('refuses a catalog whose locales drift apart structurally (negative)', () => {
    const { 'step.approve': _dropped, ...zhWithoutApprove } = bucket('zh');
    const missingZhKey: Catalog = { en: bucket('en'), zh: zhWithoutApprove };
    const audit = stringsAudit(missingZhKey);
    expect(audit.ok).toBe(false);
    if (!audit.ok) {
      expect(audit.code).toBe('STRINGS_AUDIT_REFUSED');
      expect(audit.problems.length).toBeGreaterThan(0);
    }

    const flippedPolarity: Catalog = {
      en: bucket('en'),
      zh: {
        ...bucket('zh'),
        'step.approve': { ...entry('zh', 'step.approve'), polarity: 'REFUSE' },
      },
    };
    expect(stringsAudit(flippedPolarity).ok).toBe(false);
  });

  it('refuses CN/EN authorization semantic drift: swapped approve/refuse text (negative)', () => {
    // Structure alone cannot catch this: keep each key's polarity marker but
    // swap the human text, and only the anchor oracle must flag it.
    const zhApprove = entry('zh', 'step.approve');
    const zhRefuse = entry('zh', 'step.refuse');
    const drifted: Catalog = {
      en: bucket('en'),
      zh: {
        ...bucket('zh'),
        'step.approve': { ...zhApprove, text: zhRefuse.text },
        'step.refuse': { ...zhRefuse, text: zhApprove.text },
      },
    };
    expect(stringsAudit(drifted)).toEqual({ ok: true });
    const problems = anchorProblems(drifted);
    expect(problems.length).toBeGreaterThan(0);
    expect(problems.some((problem) => problem.startsWith('zh/step.approve'))).toBe(true);
    expect(problems.some((problem) => problem.startsWith('zh/step.refuse'))).toBe(true);
    // The shipped catalog itself must stay clean.
    expect(anchorProblems(STRINGS)).toEqual([]);
  });

  it('fails closed on an unbound locale or missing key; never guesses another language', () => {
    const unbound = t('fr', 'step.approve');
    expect(unbound.ok).toBe(false);
    if (!unbound.ok) expect(unbound.code).toBe('LOCALE_UNBOUND');

    const missing = t('en', 'step.approve.does-not-exist');
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.code).toBe('KEY_MISSING');

    // No silent cross-locale fallback: the ZH sentence must be its own text,
    // not a copy of the EN sentence.
    const en = t('en', 'step.approve');
    const zh = t('zh', 'step.approve');
    expect(en.ok).toBe(true);
    expect(zh.ok).toBe(true);
    if (en.ok && zh.ok) expect(zh.text).not.toBe(en.text);
  });
});

describe('T10 current guided step rendering (real StepSpec)', () => {
  it('renders the real select-root StepSpec fields without approval affordance', () => {
    const step = makeStep('shun.guided.select-root');
    const model = currentStepModel(step, NOW);
    expect(model.status).toBe('CURRENT');
    if (model.status !== 'CURRENT') return;
    expect(model.journeyId).toBe('journey-01');
    expect(model.taskId).toBe('task-01');
    expect(model.stepId).toBe('guided:step-01');
    expect(model.templateId).toBe('shun.guided.select-root');
    expect(model.templateVersion).toBe('1.0.0');
    expect(model.templateDigest).toBe(TEMPLATE_BY_ID.get('shun.guided.select-root')?.digest);
    expect(model.kind).toBe('ASK');
    expect(model.validUntilUnixMs).toBe(60_000);
    expect(model.fields).toHaveLength(1);
    expect(model.fields[0]).toMatchObject({ id: 'selectedRoot', type: 'TEXT', required: true });
    expect(model.requiresExplicitApproval).toBe(false);
    assertNoAuthorityShape(model);
  });

  it('marks only REVIEW_EFFECT steps as requiring explicit approval (R2)', () => {
    const review = currentStepModel(makeStep('shun.guided.review-plan'), NOW);
    expect(review.status).toBe('CURRENT');
    if (review.status === 'CURRENT') expect(review.requiresExplicitApproval).toBe(true);
    const inspect = currentStepModel(makeStep('shun.guided.inspect-scope'), NOW);
    if (inspect.status === 'CURRENT') expect(inspect.requiresExplicitApproval).toBe(false);
  });

  it('refuses an expired step instead of rendering it as actionable', () => {
    const model = currentStepModel(makeStep('shun.guided.select-root'), 60_001);
    expect(model).toMatchObject({ status: 'REFUSED', code: 'STEP_EXPIRED', success: false });
    expect(outcomeStatusView(model.status).success).toBe(false);
  });

  it('refuses forged or malformed StepSpec shapes (negative)', () => {
    const wrongSchema = currentStepModel(
      { ...makeStep('shun.guided.select-root'), schema: 'shun.guided.step-spec.v2' },
      NOW,
    );
    expect(wrongSchema).toMatchObject({ status: 'REFUSED', code: 'STEP_SPEC_INVALID' });

    const missingDigest = currentStepModel(
      makeStep('shun.guided.select-root', {
        templateRef: { artifactId: 'shun.guided.select-root', version: '1.0.0', digest: '' },
      }),
      NOW,
    );
    expect(missingDigest).toMatchObject({ status: 'REFUSED', code: 'STEP_SPEC_INVALID' });

    const badCaseRef = currentStepModel(
      makeStep('shun.guided.select-root', { caseRef: { snapshotId: 's', digest: 'nothex' } }),
      NOW,
    );
    expect(badCaseRef).toMatchObject({ status: 'REFUSED', code: 'STEP_SPEC_INVALID' });

    const notAnObject = currentStepModel(undefined, NOW);
    expect(notAnObject).toMatchObject({ status: 'REFUSED', code: 'STEP_SPEC_INVALID' });
  });

  it('refuses templates outside the approved catalog and pins the catalog to T05 (negative)', () => {
    const forged = currentStepModel(
      makeStep('shun.guided.select-root', {
        templateRef: {
          artifactId: 'shun.guided.grant-everything',
          version: '1.0.0',
          digest: 'c'.repeat(64),
        },
      }),
      NOW,
    );
    expect(forged).toMatchObject({ status: 'REFUSED', code: 'TEMPLATE_UNKNOWN' });

    expect(APPROVED_TEMPLATE_IDS).toHaveLength(APPROVED_STEP_TEMPLATES.length);
    for (const template of APPROVED_STEP_TEMPLATES) {
      expect(APPROVED_TEMPLATE_IDS).toContain(template.templateId);
    }
  });

  it('renders an explicit UNKNOWN when the clock cannot be established', () => {
    const model = currentStepModel(makeStep('shun.guided.select-root'), Number.NaN);
    expect(model).toMatchObject({ status: 'UNKNOWN', code: 'CLOCK_UNKNOWN', success: false });
    expect(outcomeStatusView(model.status).success).toBe(false);
  });
});

describe('T10 selected-root scope fence', () => {
  it('shows exactly the selected root; NONE and UNKNOWN are honest', () => {
    const selected = scopeSummary({ selectedRootRef: 'C:\\Users\\15549\\Pictures' }, 'en');
    expect(selected).toMatchObject({ status: 'SELECTED', root: 'C:\\Users\\15549\\Pictures' });

    expect(scopeSummary({}, 'zh').status).toBe('NONE');
    expect(scopeSummary({ selectedRootRef: '' }, 'en').status).toBe('UNKNOWN');
    expect(scopeSummary({ selectedRootRef: 42 }, 'zh').status).toBe('UNKNOWN');
  });

  it('refuses to render content outside the selected root (negative)', () => {
    const root = 'C:\\Users\\15549\\Pictures';
    expect(scopeContentGuard(root, [root, root])).toEqual({ allowed: true });
    const refused = scopeContentGuard(root, [root, 'D:\\Elsewhere']);
    expect(refused).toMatchObject({ allowed: false, code: 'OUTSIDE_SCOPE_REFUSED' });
    expect(scopeContentGuard('', [root]).allowed).toBe(false);
    expect(scopeContentGuard(undefined, []).allowed).toBe(false);
  });

  it('refuses scope and consent rendering without a locale binding (negative)', () => {
    for (const badLocale of ['fr', '', 'zh-CN', 'EN', 'en_US']) {
      const scope = scopeSummary({ selectedRootRef: 'C:\\x' }, badLocale);
      expect(scope).toMatchObject({ status: 'REFUSED', code: 'LOCALE_UNBOUND' });
      const consent = consentView(badLocale);
      expect(consent.ok).toBe(false);
      if (!consent.ok) expect(consent.code).toBe('LOCALE_UNBOUND');
    }
    const consent = consentView('en');
    expect(consent.ok).toBe(true);
    if (consent.ok) {
      expect(consent.lines).toHaveLength(3);
      expect(consent.lines.some((line) => line.includes('explicit approval'))).toBe(true);
    }
    const zhConsent = consentView('zh');
    if (zhConsent.ok) {
      expect(zhConsent.lines.some((line) => line.includes('明确批准'))).toBe(true);
    }
  });
});

describe('T10 explicit R2 approval relay (the UI is not a grant source)', () => {
  const reviewStep = makeStep('shun.guided.review-plan');
  const continueChoice = 'continue-to-independent-approval';

  it('emits a frozen relay envelope for a confirmed human decision, bound to the step', () => {
    const result = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice),
      decision: 'APPROVE',
      confirmed: true,
      nowUnixMs: NOW,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const relay = result.relay;
    expect(relay.kind).toBe('USER_DECISION_RELAY');
    expect(relay.humanApproval).toBe(true);
    expect(relay.authorityClaimed).toBe(false);
    expect(relay.decision).toBe('APPROVE');
    expect(relay.relayedVia).toBe('/api');
    expect(relay.stepId).toBe(reviewStep.stepId);
    expect(relay.stepDigest).toBe(reviewStep.templateRef.digest);
    expect(relay.caseRef).toEqual(reviewStep.caseRef);
    expect(relay.outcome.answers).toEqual([{ fieldId: 'continue', value: continueChoice }]);
    expect(Object.isFrozen(relay)).toBe(true);
    assertNoAuthorityShape(relay);
  });

  it('refuses an unconfirmed approval: nothing is ever auto-approved (negative)', () => {
    const result = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice),
      decision: 'APPROVE',
      confirmed: false,
      nowUnixMs: NOW,
    });
    expect(result).toMatchObject({ ok: false, code: 'EXPLICIT_CONFIRMATION_REQUIRED' });

    const programmatic = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice),
      decision: 'APPROVE',
      confirmed: 'yes',
      nowUnixMs: NOW,
    });
    expect(programmatic.ok).toBe(false);
  });

  it('refuses an outcome that smuggles a forged grant or approval (negative)', () => {
    for (const [key, value] of [
      ['grant', { approved: true }],
      ['approval', true],
      ['permit', 'all'],
      ['authorization', 'granted'],
    ] as const) {
      const forged = outcomeFor(reviewStep, 'continue', continueChoice, { [key]: value });
      const result = userDecisionRelay({
        step: reviewStep,
        outcome: forged,
        decision: 'APPROVE',
        confirmed: true,
        nowUnixMs: NOW,
      });
      expect(result).toMatchObject({ ok: false, code: 'EXTRA_KEYS_REFUSED' });
    }
  });

  it('reserves APPROVE for REVIEW_EFFECT steps and refuses expired or unknown decisions', () => {
    const rootStep = makeStep('shun.guided.select-root');
    const approvedAsk = userDecisionRelay({
      step: rootStep,
      outcome: outcomeFor(rootStep, 'selectedRoot', 'C:\\Users\\15549\\Pictures'),
      decision: 'APPROVE',
      confirmed: true,
      nowUnixMs: NOW,
    });
    expect(approvedAsk).toMatchObject({ ok: false, code: 'APPROVE_RESERVED_FOR_REVIEW_EFFECT' });

    // Refusing any current step is always a legal user decision.
    const refusedAsk = userDecisionRelay({
      step: rootStep,
      outcome: outcomeFor(rootStep, 'selectedRoot', 'C:\\Users\\15549\\Pictures'),
      decision: 'REFUSE',
      confirmed: true,
      nowUnixMs: NOW,
    });
    expect(refusedAsk.ok).toBe(true);

    const expired = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice),
      decision: 'APPROVE',
      confirmed: true,
      nowUnixMs: 60_001,
    });
    expect(expired).toMatchObject({ ok: false, code: 'STEP_EXPIRED' });

    const undecided = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice),
      decision: 'MAYBE',
      confirmed: true,
      nowUnixMs: NOW,
    });
    expect(undecided).toMatchObject({ ok: false, code: 'DECISION_UNKNOWN' });
  });

  it('binds the outcome to the current step and refuses mismatches (negative)', () => {
    const base = { decision: 'APPROVE', confirmed: true, nowUnixMs: NOW } as const;
    const wrongStepId = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice, { stepId: 'guided:other-step' }),
      ...base,
    });
    expect(wrongStepId).toMatchObject({ ok: false, code: 'OUTCOME_INVALID' });

    const wrongSource = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice, { source: 'HOST' }),
      ...base,
    });
    expect(wrongSource).toMatchObject({ ok: false, code: 'OUTCOME_INVALID' });

    const undeclaredField = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'grantMe', 'yes'),
      ...base,
    });
    expect(undeclaredField).toMatchObject({ ok: false, code: 'ANSWER_FIELD_UNDECLARED' });

    const wrongSchema = userDecisionRelay({
      step: reviewStep,
      outcome: {
        ...outcomeFor(reviewStep, 'continue', continueChoice),
        schema: 'shun.custom-outcome.v1',
      },
      ...base,
    });
    expect(wrongSchema).toMatchObject({ ok: false, code: 'OUTCOME_INVALID' });

    const wrongCase = userDecisionRelay({
      step: reviewStep,
      outcome: outcomeFor(reviewStep, 'continue', continueChoice, {
        caseRef: { snapshotId: 'snapshot-02', digest: 'b'.repeat(64) },
      }),
      ...base,
    });
    expect(wrongCase).toMatchObject({ ok: false, code: 'OUTCOME_INVALID' });
  });
});

describe('T10 replay fence (same StepOutcome submitted twice is refused)', () => {
  it('accepts the first submission and refuses the second as POSSIBLE_REPLAY', () => {
    const step = makeStep('shun.guided.review-plan');
    const outcome = outcomeFor(step, 'continue', 'continue-to-independent-approval');
    const seen: string[] = [];

    const first = replayGuard(seen, outcome);
    expect(first.allowed).toBe(true);
    if (first.allowed) seen.push(first.key);
    expect(seen[0]).toBe(`${step.stepId}|${step.caseRef.digest}`);

    const second = replayGuard(seen, outcome);
    expect(second).toMatchObject({ allowed: false, code: 'POSSIBLE_REPLAY' });
  });

  it('distinguishes different steps and refuses malformed identities', () => {
    const seen: string[] = [];
    const stepA = makeStep('shun.guided.review-plan', { stepId: 'guided:step-a' });
    const stepB = makeStep('shun.guided.review-plan', { stepId: 'guided:step-b' });
    expect(replayGuard(seen, outcomeFor(stepA, 'continue', 'x')).allowed).toBe(true);
    expect(replayGuard(seen, outcomeFor(stepB, 'continue', 'x')).allowed).toBe(true);

    const malformed = replayGuard(seen, { stepId: 'guided:step-c' });
    expect(malformed).toMatchObject({ allowed: false, code: 'OUTCOME_INVALID' });
  });
});

describe('T10 honest outcome display: REFUSED and UNKNOWN never render as success', () => {
  it('maps only an explicit ACCEPTED to success', () => {
    expect(outcomeStatusView('ACCEPTED')).toMatchObject({ success: true, tone: 'ok' });
    expect(outcomeStatusView('REJECTED')).toMatchObject({ success: false, tone: 'bad' });
    expect(outcomeStatusView('BLOCKED')).toMatchObject({ success: false, tone: 'bad' });
    for (const bogus of [undefined, null, '', 'ACCEPTED ', 'accepted', 42, 'UNKNOWN']) {
      expect(outcomeStatusView(bogus).success).toBe(false);
      expect(outcomeStatusView(bogus).tone).toBe('unknown');
    }
  });

  it('renders every typed refusal with a localized, never-successful sentence', () => {
    const codes = [
      'STEP_EXPIRED',
      'STEP_SPEC_INVALID',
      'TEMPLATE_UNKNOWN',
      'POSSIBLE_REPLAY',
      'OUTSIDE_SCOPE_REFUSED',
      'EXTRA_KEYS_REFUSED',
      'EXPLICIT_CONFIRMATION_REQUIRED',
      'LOCALE_UNBOUND',
      'ADVISORY_SCHEMA_REFUSED',
      'SOME_FUTURE_CODE',
    ];
    for (const locale of LOCALES) {
      for (const code of codes) {
        const view = refusalView(code, locale);
        expect(view.ok, `${code} must render for ${locale}`).toBe(true);
        if (!view.ok) continue;
        expect(view.success).toBe(false);
        expect(view.tone === 'bad' || view.tone === 'unknown').toBe(true);
        expect(view.text.length).toBeGreaterThan(0);
      }
    }
    const replay = refusalView('POSSIBLE_REPLAY', 'zh');
    if (replay.ok) expect(replay.text).toContain('拒绝');
    const future = refusalView('SOME_FUTURE_CODE', 'en');
    if (future.ok) {
      expect(future.tone).toBe('unknown');
      expect(future.text.toLowerCase()).toContain('unknown');
    }
    expect(refusalView('POSSIBLE_REPLAY', 'fr').ok).toBe(false);
  });

  it('keeps refused history entries non-successful (negative scan)', () => {
    const entries = [
      { at: 't1', status: 'ACCEPTED', stepId: 'guided:step-01' },
      { at: 't2', status: 'REJECTED', stepId: 'guided:step-01' },
      { at: 't3', status: 'BLOCKED', stepId: 'guided:step-02' },
      { at: 't4', status: 'POSSIBLE_REPLAY', stepId: 'guided:step-03' },
      { at: 't5', status: undefined, stepId: 'guided:step-04' },
    ];
    const model = historyModel(entries, 'en');
    expect(model.ok).toBe(true);
    if (!model.ok) return;
    expect(model.lines).toHaveLength(5);
    expect(model.lines[0]?.success).toBe(true);
    for (const line of model.lines.slice(1)) {
      expect(line.success, `${line.text} must not render as success`).toBe(false);
    }
    expect(model.lines[1]?.tone).toBe('bad');
    expect(model.lines[4]?.tone).toBe('unknown');
    expect(historyModel(entries, 'fr').ok).toBe(false);
    expect(
      historyModel('not-an-array' as unknown as Parameters<typeof historyModel>[0], 'en').ok,
    ).toBe(false);
  });
});

describe('T10 advisory fence: suggestions are never authority', () => {
  const advisory = {
    schema: 'shun.guided.advisory.v1',
    journeyId: 'journey-01',
    caseRef: { snapshotId: 'snapshot-01', digest: 'a'.repeat(64) },
    reasonCode: 'SCOPE_CLARIFICATION',
    explanation: 'The selected folder is ready for a read-only inspection.',
    evidenceRefs: ['host:scope:01'],
  };

  it('renders a well-formed advisory as text-only, authority-free suggestion', () => {
    const model = advisoryView(advisory);
    expect(model).toMatchObject({
      status: 'ADVISORY_ONLY',
      reasonCode: 'SCOPE_CLARIFICATION',
      authorityRelevant: false,
    });
    assertNoAuthorityShape(model);
  });

  it('refuses an advisory dressed up as authority (negative)', () => {
    for (const smuggled of [
      { ...advisory, grant: { approved: true } },
      { ...advisory, templateId: 'shun.guided.review-plan' },
      { ...advisory, approval: { status: 'APPROVED' } },
      { ...advisory, schema: 'shun.guided.advisory.v2' },
      { ...advisory, explanation: '' },
    ]) {
      expect(advisoryView(smuggled)).toMatchObject({
        status: 'REFUSED',
        code: 'ADVISORY_SCHEMA_REFUSED',
      });
    }
    expect(advisoryView(undefined).status).toBe('REFUSED');
  });
});

describe('T10 user answer envelope builder (no authority of its own)', () => {
  it('builds a USER_SUBMIT outcome bound to the step, without authority fields', () => {
    const step = makeStep('shun.guided.select-root');
    const built = buildStepOutcome({
      step,
      answers: [{ fieldId: 'selectedRoot', value: 'C:\\Users\\15549\\Pictures' }],
      sourceRef: 'ui:session-01',
      occurredAtUnixMs: 2_500,
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.outcome).toMatchObject({
      schema: 'shun.guided.step-outcome.v1',
      event: 'USER_SUBMIT',
      source: 'USER',
      stepId: step.stepId,
    });
    assertNoAuthorityShape(built.outcome);
  });

  it('refuses undeclared fields and malformed input (negative)', () => {
    const step = makeStep('shun.guided.select-root');
    expect(
      buildStepOutcome({
        step,
        answers: [{ fieldId: 'grantMe', value: 'yes' }],
        sourceRef: 'ui:session-01',
        occurredAtUnixMs: 2_500,
      }),
    ).toMatchObject({ ok: false, code: 'ANSWER_FIELD_UNDECLARED' });
    const badAnswers = {
      step,
      answers: 'yes',
      sourceRef: 'ui:session-01',
      occurredAtUnixMs: 2_500,
    } as unknown as Parameters<typeof buildStepOutcome>[0];
    expect(buildStepOutcome(badAnswers)).toMatchObject({ ok: false, code: 'ANSWERS_INVALID' });
    expect(
      buildStepOutcome({
        step: { broken: true },
        answers: [],
        sourceRef: 'ui:session-01',
        occurredAtUnixMs: 2_500,
      }),
    ).toMatchObject({ ok: false, code: 'STEP_SPEC_INVALID' });
  });
});
