/**
 * Shun v0.3 Business Domain Package — opt-in meta feedback (R03-INT).
 * One bounded intent whose governed external Effect persists an opt-in
 * FUTURE_BUILD_SHADOW candidate through the trusted durable Host store;
 * the sealed capability never carries consent, provenance or promotion.
 */
export const MODULE_ID = 'shun.business.meta@v0.3.0';
export const PACKAGE_KIND = 'business';
export const ABI_VERSION = 'v08-business-abi/1';
export const ENDPOINTS = [{ endpointId: 'business:shun-meta', kind: 'business-policy' }];
export const INTENT_TYPES = ['submitMetaFeedback'];
export const EFFECT_TYPES = ['effect:meta-feedback'];

const FEEDBACK_FIELDS = ['caseRef', 'sourceRevision', 'rating', 'category'];
const fromEvent = {};
for (const field of FEEDBACK_FIELDS) fromEvent[field] = { source: 'event', path: ['payload', field] };
fromEvent.correction = { source: 'event', path: ['payload', 'correction'] };
const definition = {
  workflowKey: 'shun-meta', initialState: 'ready', initialContext: {},
  guards: [],
  states: [
    { stateKey: 'ready', transitions: [{
      transitionKey: 'submit-feedback',
      trigger: { kind: 'event', eventType: 'META_FEEDBACK_REQUESTED' },
      targetState: 'ready',
      effectIntents: [{
        effectType: 'effect:meta-feedback',
        inputFrom: fromEvent,
        idempotencyKeyFrom: { template: 'meta:{caseRef}' },
      }],
    }] },
  ],
};
const decisionSchema = {
  isValid(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    return !!value.decision && typeof value.decision.outcome === 'string' &&
      !!value.event && typeof value.event.type === 'string';
  },
};
export function getPolicy() {
  return {
    packageId: MODULE_ID,
    policyId: 'shun-meta-feedback',
    domainId: 'shun',
    workflowDefinition: definition,
    decisionSchema,
    governanceSemantics: { hardInvariants: [] },
    initialStateKey: 'ready', initialContext: {},
    rules: {
      'rule:meta-feedback': {
        ruleId: 'rule:meta-feedback',
        eventType: 'META_FEEDBACK_REQUESTED',
        payloadFromInput: {
          caseRef: 'caseRef',
          sourceRevision: 'sourceRevision',
          rating: 'rating',
          category: 'category',
          correction: 'correction',
        },
      },
    },
    intentBindings: {
      submitMetaFeedback: {
        trigger: { kind: 'event', eventType: 'META_FEEDBACK_REQUESTED' },
        ruleId: 'rule:meta-feedback',
        roles: ['requester'],
      },
    },
    effectBindings: {
      'effect:meta-feedback': {
        semantics: 'non-idempotent',
        resource: { key: 'meta', operation: 'meta.submitFeedback' },
        external: { permitTtlMs: 60_000, await: 'terminal' },
        handler: async ({ input, resources }) => {
          if (!resources || typeof resources.call !== 'function') {
            throw new Error('K_RESOURCES_REQUIRED');
          }
          const submission = {
            selected: true,
            caseRef: input.caseRef,
            sourceRevision: input.sourceRevision,
            rating: input.rating,
            category: input.category,
          };
          if (input.correction !== undefined && input.correction !== null) {
            submission.correction = input.correction;
          }
          return resources.call('meta', 'meta.submitFeedback', submission);
        },
      },
    },
  };
}
