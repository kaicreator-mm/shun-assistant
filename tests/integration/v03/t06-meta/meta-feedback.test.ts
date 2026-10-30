import { describe, expect, it, vi } from 'vitest';
import {
  META_FEEDBACK_SCOPE,
  createMetaFeedbackAdapter,
  type MetaFeedbackAuthorization,
  type MetaFeedbackHostPort,
  type MetaFeedbackSelection,
} from '../../../../packages/domain-computer/src/feedback/meta-feedback.ts';

const NOW = '2026-10-30T00:00:00.000Z';
const SELECTION: MetaFeedbackSelection = {
  selected: true,
  caseRef: 'case-01',
  sourceRevision: 'revision-07',
  rating: 'NOT_HELPFUL',
  category: 'MISSING_STEP',
  correction: 'MISSING_CONSTRAINT',
};

function authorization(selection: MetaFeedbackSelection = SELECTION): MetaFeedbackAuthorization {
  return {
    status: 'AUTHORIZED',
    scope: META_FEEDBACK_SCOPE,
    candidateId: 'meta-candidate-01',
    caseRef: selection.caseRef,
    sourceRevision: selection.sourceRevision,
    sourceDigest: 'a'.repeat(64),
    evidenceOwnerRef: 'subject-01',
    operatorSubjectRef: 'subject-01',
    operatorId: 'operator-01',
    consentRef: 'consent-01',
    consentRevision: 'consent-rev-04',
    consentExpiresAt: '2026-10-30T00:05:00.000Z',
    authorizationRevision: 'auth-rev-02',
    currentnessRef: 'currentness-01',
    selection,
  };
}

function harness(options: {
  authorization?: unknown;
  result?: unknown;
  authorizeError?: boolean;
  workflowError?: boolean;
} = {}) {
  const authorizeCurrentFeedback = vi.fn(async (_input: Parameters<MetaFeedbackHostPort['authorizeCurrentFeedback']>[0]) => {
    if (options.authorizeError) throw new Error('private consent detail');
    return options.authorization ?? authorization();
  });
  const runMetaFeedbackWorkflow = vi.fn(async (_input: Parameters<MetaFeedbackHostPort['runMetaFeedbackWorkflow']>[0]) => {
    if (options.workflowError) throw new Error('private store detail');
    return options.result ?? {
      status: 'SHADOW_STORED',
      candidateRef: 'meta-candidate-01',
      candidateDigest: 'b'.repeat(64),
      active: false,
    };
  });
  const host: MetaFeedbackHostPort = { authorizeCurrentFeedback, runMetaFeedbackWorkflow };
  const adapter = createMetaFeedbackAdapter(host, () => NOW);
  return { adapter, authorizeCurrentFeedback, runMetaFeedbackWorkflow };
}

describe('T06 opt-in redacted Meta feedback Shadow adapter', () => {
  it('does not parse, construct or send a payload when feedback is not selected', async () => {
    const h = harness();
    expect(await h.adapter.submit({
      selected: false,
      rawPrompt: 'PRIVATE_PROMPT_SENTINEL',
      rawAnswer: 'PRIVATE_ANSWER_SENTINEL',
      secret: 'PRIVATE_SECRET_SENTINEL',
    })).toEqual({ status: 'NOT_SELECTED' });
    expect(h.authorizeCurrentFeedback).not.toHaveBeenCalled();
    expect(h.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
  });

  it('sends only the allowlisted selection to Host and stores a frozen future-build Shadow candidate', async () => {
    const h = harness();
    expect(await h.adapter.submit(SELECTION)).toEqual({
      status: 'STORED_SHADOW',
      candidateRef: 'meta-candidate-01',
      candidateDigest: 'b'.repeat(64),
      active: false,
    });
    expect(h.authorizeCurrentFeedback).toHaveBeenCalledWith({
      scope: META_FEEDBACK_SCOPE,
      caseRef: 'case-01',
      sourceRevision: 'revision-07',
      selection: SELECTION,
    });
    const call = h.runMetaFeedbackWorkflow.mock.calls[0]?.[0];
    expect(call).toBeDefined();
    if (!call) throw new Error('expected Host workflow call');
    expect(Object.isFrozen(call.candidate)).toBe(true);
    expect(Object.isFrozen(call.candidate.feedback)).toBe(true);
    expect(call.candidate).toMatchObject({
      kind: 'META_FEEDBACK',
      lifecycle: 'FUTURE_BUILD_SHADOW',
      active: false,
      source: { caseRef: 'case-01', revision: 'revision-07', sha256: 'a'.repeat(64) },
      feedback: {
        rating: 'NOT_HELPFUL',
        category: 'MISSING_STEP',
        correction: 'MISSING_CONSTRAINT',
      },
      provenance: {
        operatorId: 'operator-01',
        operatorSubjectRef: 'subject-01',
        consentRef: 'consent-01',
      },
    });
    expect(JSON.stringify(call)).not.toMatch(/PRIVATE_|rawPrompt|rawAnswer|secret|password|C:\\\\|\\/home\\//i);
  });

  it('rejects extra raw fields and path-shaped identifiers before any Host call', async () => {
    const h = harness();
    for (const input of [
      { ...SELECTION, rawPrompt: 'PRIVATE_PROMPT_SENTINEL' },
      { ...SELECTION, answer: 'PRIVATE_ANSWER_SENTINEL' },
      { ...SELECTION, credential: 'PRIVATE_SECRET_SENTINEL' },
      { ...SELECTION, caseRef: 'C:\\\\Users\\\\person\\\\secret.txt' },
      { ...SELECTION, sourceRevision: '/home/person/private' },
    ]) {
      expect(await h.adapter.submit(input)).toMatchObject({
        status: 'REFUSED',
        code: 'FEEDBACK_INPUT_INVALID',
      });
    }
    expect(h.authorizeCurrentFeedback).not.toHaveBeenCalled();
    expect(h.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
  });

  it('rejects cross-user evidence, missing operator attribution and wrong consent scope', async () => {
    const cases = [
      { ...authorization(), evidenceOwnerRef: 'subject-other' },
      { ...authorization(), operatorId: '' },
      { ...authorization(), scope: 'META_FEEDBACK_ACTIVATE' },
      { ...authorization(), consentRef: '' },
    ];
    const h = harness();
    for (const value of cases) {
      const local = harness({ authorization: value });
      expect(await local.adapter.submit(SELECTION)).toMatchObject({
        status: 'REFUSED',
        code: 'FEEDBACK_AUTHORIZATION_INVALID',
      });
      expect(local.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
    }
    expect(h.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
  });

  it('rejects stale consent and authorization bound to another selection', async () => {
    const stale = harness({
      authorization: { ...authorization(), consentExpiresAt: '2026-10-29T23:59:59.000Z' },
    });
    expect(await stale.adapter.submit(SELECTION)).toMatchObject({
      status: 'REFUSED',
      code: 'FEEDBACK_AUTHORIZATION_INVALID',
    });
    const drifted = harness({
      authorization: { ...authorization(), selection: { ...SELECTION, category: 'OTHER' } },
    });
    expect(await drifted.adapter.submit(SELECTION)).toMatchObject({
      status: 'REFUSED',
      code: 'FEEDBACK_AUTHORIZATION_INVALID',
    });
    expect(stale.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
    expect(drifted.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
  });

  it('does not claim success when the Host returns an activated or malformed candidate', async () => {
    for (const result of [
      { status: 'SHADOW_STORED', candidateRef: 'meta-candidate-01', candidateDigest: 'b'.repeat(64), active: true },
      { status: 'ACTIVE', candidateRef: 'meta-candidate-01', candidateDigest: 'b'.repeat(64), active: true },
      { status: 'SHADOW_STORED', candidateRef: 'another-candidate', candidateDigest: 'b'.repeat(64), active: false },
    ]) {
      const h = harness({ result });
      expect(await h.adapter.submit(SELECTION)).toEqual({
        status: 'UNKNOWN',
        code: 'HOST_RESULT_UNVERIFIABLE',
      });
    }
  });

  it('returns UNKNOWN when Host persistence may have committed before a lost response', async () => {
    const h = harness({ workflowError: true });
    expect(await h.adapter.submit(SELECTION)).toEqual({
      status: 'UNKNOWN',
      code: 'HOST_OUTCOME_UNKNOWN',
    });
    expect(h.runMetaFeedbackWorkflow).toHaveBeenCalledTimes(1);
  });

  it('fails closed when current consent cannot be resolved', async () => {
    const h = harness({ authorizeError: true });
    expect(await h.adapter.submit(SELECTION)).toEqual({
      status: 'REFUSED',
      code: 'FEEDBACK_AUTHORITY_UNAVAILABLE',
    });
    expect(h.runMetaFeedbackWorkflow).not.toHaveBeenCalled();
  });
});
