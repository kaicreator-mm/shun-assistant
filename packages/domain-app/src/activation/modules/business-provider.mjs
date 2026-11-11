/**
 * Shun v0.3 Business Domain Package — curated Provider first use (R03-INT,
 * R03C #288 Host-global repair). One bounded intent triggering the pinned
 * provider's genuine first use through the selected K's external Effect gate.
 * The event payload carries ONLY the Host-issued requestRef: the sealed
 * capability and the trusted Host chain own signature/staging/one-time
 * request authority; no caller taskId, path, args or privilege is accepted.
 */
export const MODULE_ID = 'shun.business.provider@v0.3.0';
export const PACKAGE_KIND = 'business';
export const ABI_VERSION = 'v08-business-abi/1';
export const ENDPOINTS = [{ endpointId: 'business:shun-provider', kind: 'business-policy' }];
export const INTENT_TYPES = ['submitProviderFirstUse'];
export const EFFECT_TYPES = ['effect:provider-first-use'];

const fromEvent = {
  requestRef: { source: 'event', path: ['payload', 'requestRef'] },
};
const definition = {
  workflowKey: 'shun-provider', initialState: 'ready', initialContext: {},
  guards: [],
  states: [
    { stateKey: 'ready', transitions: [{
      transitionKey: 'first-use',
      trigger: { kind: 'event', eventType: 'PROVIDER_FIRST_USE_REQUESTED' },
      targetState: 'ready',
      effectIntents: [{
        effectType: 'effect:provider-first-use',
        inputFrom: fromEvent,
        idempotencyKeyFrom: { template: 'provider:{requestRef}' },
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
    policyId: 'shun-provider-first-use',
    domainId: 'shun',
    workflowDefinition: definition,
    decisionSchema,
    governanceSemantics: { hardInvariants: [] },
    initialStateKey: 'ready', initialContext: {},
    rules: {
      'rule:provider-first-use': {
        ruleId: 'rule:provider-first-use',
        eventType: 'PROVIDER_FIRST_USE_REQUESTED',
        payloadFromInput: { requestRef: 'requestRef' },
      },
    },
    intentBindings: {
      submitProviderFirstUse: {
        trigger: { kind: 'event', eventType: 'PROVIDER_FIRST_USE_REQUESTED' },
        ruleId: 'rule:provider-first-use',
        roles: ['requester'],
      },
    },
    effectBindings: {
      'effect:provider-first-use': {
        semantics: 'non-idempotent',
        resource: { key: 'provider', operation: 'provider.firstUse' },
        external: { permitTtlMs: 60_000, await: 'terminal' },
        handler: async ({ input, resources }) => {
          if (!resources || typeof resources.call !== 'function') {
            throw new Error('K_RESOURCES_REQUIRED');
          }
          return resources.call('provider', 'provider.firstUse', { requestRef: input.requestRef });
        },
      },
    },
  };
}
