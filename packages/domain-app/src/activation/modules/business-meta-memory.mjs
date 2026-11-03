/**
 * Shun v0.3 Business Domain Package — read-only cross-Case Meta shared
 * experience query (R03C, #288). One bounded read intent whose governed
 * INTERNAL effect (no Permit surface, no external dispatch) asks the selected
 * K's sealed read-only Meta-memory capability for privacy-minimized verified
 * experiences through the trusted durable Host store (#285 contract:
 * targetCaseRef, capabilityId, optional taskClass, bounded limit — no tags).
 *
 * The result is advisoryOnly data: no Permit, grant, approval, executable
 * action, policy mutation or Shadow promotion is minted here. Feedback writes
 * remain in the separate effectful meta-feedback module pair.
 */
export const MODULE_ID = 'shun.business.meta-memory@v0.3.0';
export const PACKAGE_KIND = 'business';
export const ABI_VERSION = 'v08-business-abi/1';
export const ENDPOINTS = [{ endpointId: 'business:shun-meta-memory', kind: 'business-policy' }];
export const INTENT_TYPES = ['querySharedExperiences'];
export const EFFECT_TYPES = ['effect:meta-shared-query'];

const fromEvent = {
  targetCaseRef: { source: 'event', path: ['payload', 'targetCaseRef'] },
  capabilityId: { source: 'event', path: ['payload', 'capabilityId'] },
  taskClass: { source: 'event', path: ['payload', 'taskClass'] },
  limit: { source: 'event', path: ['payload', 'limit'] },
};
const definition = {
  workflowKey: 'shun-meta-memory', initialState: 'ready', initialContext: {},
  guards: [],
  states: [
    { stateKey: 'ready', transitions: [{
      transitionKey: 'shared-query',
      trigger: { kind: 'event', eventType: 'META_SHARED_QUERY_REQUESTED' },
      targetState: 'ready',
      effectIntents: [{
        effectType: 'effect:meta-shared-query',
        inputFrom: fromEvent,
        idempotencyKeyFrom: { template: 'meta-shared:{targetCaseRef}:{capabilityId}' },
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
    policyId: 'shun-meta-shared-query',
    domainId: 'shun',
    workflowDefinition: definition,
    decisionSchema,
    governanceSemantics: { hardInvariants: [] },
    initialStateKey: 'ready', initialContext: {},
    rules: {
      'rule:meta-shared-query': {
        ruleId: 'rule:meta-shared-query',
        eventType: 'META_SHARED_QUERY_REQUESTED',
        payloadFromInput: {
          targetCaseRef: 'targetCaseRef',
          capabilityId: 'capabilityId',
          taskClass: 'taskClass',
          limit: 'limit',
        },
      },
    },
    intentBindings: {
      querySharedExperiences: {
        trigger: { kind: 'event', eventType: 'META_SHARED_QUERY_REQUESTED' },
        ruleId: 'rule:meta-shared-query',
        roles: ['requester'],
      },
    },
    effectBindings: {
      // Internal effect on purpose: no `external` config — the kernel mints
      // NO Effect Permit and dispatches the sealed handler in-process. The
      // capability module is BUILD-selected with externalEffect:false.
      'effect:meta-shared-query': {
        semantics: 'read-only',
        resource: { key: 'meta-memory', operation: 'meta.querySharedExperiences' },
        handler: async ({ input, resources }) => {
          if (!resources || typeof resources.call !== 'function') {
            throw new Error('K_RESOURCES_REQUIRED');
          }
          const query = {
            targetCaseRef: input.targetCaseRef,
            capabilityId: input.capabilityId,
          };
          if (input.taskClass !== undefined && input.taskClass !== null) {
            query.taskClass = input.taskClass;
          }
          if (input.limit !== undefined && input.limit !== null) {
            query.limit = input.limit;
          }
          return resources.call('meta-memory', 'meta.querySharedExperiences', query);
        },
      },
    },
  };
}
