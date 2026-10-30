/**
 * Shun v0.3 bounded Guided Journey contracts.
 *
 * This is a domain-owned one-step subset. It intentionally does not import
 * the non-exported/draft DomainHarness guided-journey proposal and does not
 * create a generic form engine or a second workflow lifecycle.
 */
export type GuidedEvent =
  | 'USER_SUBMIT'
  | 'SKIP'
  | 'BACK'
  | 'PAUSE'
  | 'RESUME'
  | 'OBSERVATION_RECEIPT';

export type GuidedStepKind = 'ASK' | 'INSPECT' | 'REVIEW_EFFECT';
export type GuidedFieldKind = 'TEXT' | 'CHOICE' | 'CONFIRM';

export interface CaseRef {
  readonly snapshotId: string;
  readonly digest: string;
}

export interface ChoiceOption {
  readonly id: string;
  readonly labelKey: string;
  readonly eligible: true;
}

export type FormField =
  | {
      readonly id: string;
      readonly type: 'TEXT';
      readonly labelKey: string;
      readonly required: boolean;
      readonly maxLength: number;
    }
  | {
      readonly id: string;
      readonly type: 'CHOICE';
      readonly labelKey: string;
      readonly required: boolean;
      readonly options: readonly ChoiceOption[];
    }
  | {
      readonly id: string;
      readonly type: 'CONFIRM';
      readonly labelKey: string;
      readonly required: boolean;
    };

export interface FormSchema {
  readonly fields: readonly FormField[];
}

export interface StepTemplate {
  readonly templateId: string;
  readonly version: '1.0.0';
  readonly digest: string;
  readonly kind: GuidedStepKind;
  readonly titleKey: string;
  readonly formSchema: FormSchema;
  readonly allowedEvents: readonly GuidedEvent[];
}

export interface ChoiceCatalog {
  readonly privacyRoute: readonly ChoiceOption[];
  readonly planReview: readonly ChoiceOption[];
}

/**
 * Host-only observation envelope. sourceRef/revision/caseRef/evidenceRefs
 * must be supplied by the trusted Host composition root, never by UI/model.
 */
export interface HostGuidedObservation {
  readonly schema: 'shun.guided.host-observation.v1';
  readonly taskId: string;
  readonly journeyId: string;
  readonly sourceRef: string;
  readonly revision: string;
  readonly caseRef: CaseRef;
  readonly observedAtUnixMs: number;
  readonly validUntilUnixMs: number;
  readonly evidenceRefs: readonly string[];
  readonly selectedRootRef?: string;
  readonly externalDisclosureRequired?: boolean;
  /** Acknowledgement of seeing a notice only; never external-data consent. */
  readonly privacyNoticeAcknowledged?: boolean;
  /** Host-issued preview identity; never an approval or Effect permit. */
  readonly actionPreviewRef?: string;
}

export interface GuidedGoalSemantic {
  readonly schema: 'shun.goal-semantic.v1';
  readonly taskId: string;
  readonly goalContract: {
    readonly taskId: string;
    readonly objective: string;
  };
  readonly capabilityId: string;
  readonly capabilityRevision: string;
  readonly provenance: {
    readonly resolverRevision: string;
  };
}

export type GuidedGoalSemanticSelection =
  | { readonly status: 'SELECTED'; readonly semantic: GuidedGoalSemantic }
  | {
      readonly status: 'NOT_READY';
      readonly normalization: { readonly failureCode: string; readonly detail?: string };
    }
  | { readonly status: 'REJECTED'; readonly code: string; readonly detail?: string };

export interface StepSpec {
  readonly schema: 'shun.guided.step-spec.v1';
  readonly journeyId: string;
  readonly taskId: string;
  readonly stepId: string;
  readonly caseRef: CaseRef;
  readonly eligibilityCode: string;
  readonly templateRef: {
    readonly artifactId: string;
    readonly version: string;
    readonly digest: string;
  };
  readonly kind: GuidedStepKind;
  readonly titleKey: string;
  readonly formSchema: FormSchema;
  readonly allowedEvents: readonly GuidedEvent[];
  readonly evidenceRefs: readonly string[];
  readonly capabilityRef?: {
    readonly capabilityId: string;
    readonly revision: string;
    readonly resolverRevision: string;
  };
  readonly actionPreviewRef?: string;
  readonly issuedAtUnixMs: number;
  readonly validUntilUnixMs: number;
}

export interface StepOutcome {
  readonly schema: 'shun.guided.step-outcome.v1';
  readonly journeyId: string;
  readonly taskId: string;
  readonly stepId: string;
  readonly caseRef: CaseRef;
  readonly event: GuidedEvent;
  readonly source: 'USER' | 'HOST';
  readonly sourceRef: string;
  readonly answers: readonly {
    readonly fieldId: string;
    readonly value: string | boolean;
  }[];
  readonly evidenceRefs: readonly string[];
  readonly occurredAtUnixMs: number;
}

export interface GuidedAdvisory {
  readonly schema: 'shun.guided.advisory.v1';
  readonly journeyId: string;
  readonly caseRef: CaseRef;
  readonly reasonCode: string;
  readonly explanation: string;
  readonly evidenceRefs: readonly string[];
}

/** Fixed user-facing choices; selecting either option never grants disclosure or execution authority. */
export const GUIDED_CHOICE_CATALOG: ChoiceCatalog = Object.freeze({
  privacyRoute: Object.freeze([
    Object.freeze({
      id: 'keep-local',
      labelKey: 'guided.privacyNotice.keepLocal',
      eligible: true as const,
    }),
    Object.freeze({
      id: 'show-disclosure-preview',
      labelKey: 'guided.privacyNotice.showPreview',
      eligible: true as const,
    }),
  ]),
  planReview: Object.freeze([
    Object.freeze({
      id: 'continue-to-independent-approval',
      labelKey: 'guided.reviewPlan.continue',
      eligible: true as const,
    }),
    Object.freeze({
      id: 'return-to-edit',
      labelKey: 'guided.reviewPlan.back',
      eligible: true as const,
    }),
  ]),
});

export const APPROVED_STEP_TEMPLATES: readonly StepTemplate[] = Object.freeze([
  Object.freeze({
    templateId: 'shun.guided.select-root',
    version: '1.0.0' as const,
    digest: '302be72afe19223915035e1c565bf438de28b51af65d3b8fcac880069e98bc0e',
    kind: 'ASK' as const,
    titleKey: 'guided.selectRoot.title',
    formSchema: Object.freeze({
      fields: Object.freeze([
        Object.freeze({
          /** Untrusted user path candidate; Host must canonicalize and re-observe before use. */
          id: 'selectedRoot',
          type: 'TEXT' as const,
          labelKey: 'guided.selectRoot.path',
          required: true,
          maxLength: 1024,
        }),
      ]),
    }),
    allowedEvents: Object.freeze(['USER_SUBMIT', 'BACK', 'PAUSE', 'RESUME'] as const),
  }),
  Object.freeze({
    templateId: 'shun.guided.clarify-goal',
    version: '1.0.0' as const,
    digest: '6571cfe6eb3214713d1246dada9d1ff435b99b9e9b2aebab5b6ef060fae45e58',
    kind: 'ASK' as const,
    titleKey: 'guided.clarifyGoal.title',
    formSchema: Object.freeze({
      fields: Object.freeze([
        Object.freeze({
          id: 'clarification',
          type: 'TEXT' as const,
          labelKey: 'guided.clarifyGoal.detail',
          required: true,
          maxLength: 256,
        }),
      ]),
    }),
    allowedEvents: Object.freeze(['USER_SUBMIT', 'BACK', 'PAUSE', 'RESUME'] as const),
  }),
  Object.freeze({
    templateId: 'shun.guided.privacy-notice',
    version: '1.0.0' as const,
    digest: '2818ffb61d2bbf8e5a199248b1e615a04b373d754b36e457e0b2b30436471ff0',
    kind: 'ASK' as const,
    titleKey: 'guided.privacyNotice.title',
    formSchema: Object.freeze({
      fields: Object.freeze([
        Object.freeze({
          id: 'privacyRoute',
          type: 'CHOICE' as const,
          labelKey: 'guided.privacyNotice.route',
          required: true,
          options: GUIDED_CHOICE_CATALOG.privacyRoute,
        }),
      ]),
    }),
    allowedEvents: Object.freeze(['USER_SUBMIT', 'BACK', 'PAUSE', 'RESUME'] as const),
  }),
  Object.freeze({
    templateId: 'shun.guided.review-plan',
    version: '1.0.0' as const,
    digest: 'fd91e725aa76bb66a31424a2c46f961c6869c7ffc92f969f3a9c50b7a8f11cfc',
    kind: 'REVIEW_EFFECT' as const,
    titleKey: 'guided.reviewPlan.title',
    formSchema: Object.freeze({
      fields: Object.freeze([
        Object.freeze({
          id: 'continue',
          type: 'CHOICE' as const,
          labelKey: 'guided.reviewPlan.action',
          required: true,
          options: GUIDED_CHOICE_CATALOG.planReview,
        }),
      ]),
    }),
    allowedEvents: Object.freeze(['USER_SUBMIT', 'BACK', 'PAUSE', 'RESUME'] as const),
  }),
  Object.freeze({
    templateId: 'shun.guided.inspect-scope',
    version: '1.0.0' as const,
    digest: 'd6bc68bf5956fa2ef2d0374b87e293b9ea1e315d7d313f796d0f7fe061860f4d',
    kind: 'INSPECT' as const,
    titleKey: 'guided.inspectScope.title',
    formSchema: Object.freeze({ fields: Object.freeze([]) }),
    allowedEvents: Object.freeze(['OBSERVATION_RECEIPT', 'BACK', 'PAUSE', 'RESUME'] as const),
  }),
]);

export function findApprovedStepTemplate(templateId: string): StepTemplate | undefined {
  return APPROVED_STEP_TEMPLATES.find((template) => template.templateId === templateId);
}
