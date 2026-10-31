/**
 * Shun v0.3 Business Domain Package — goal interpretation.
 * Runtime K/S are selected from the real public DomainHarness v0.10.3
 * Domain Packages. Business policy declares ONLY the one bounded Goal intent
 * and its governed external Effect; it cannot mint approval or a K Permit.
 */
export const MODULE_ID = 'shun.business.goal@v0.3.0';
export const PACKAGE_KIND = 'business';
export const ABI_VERSION = 'v08-business-abi/1';
export const ENDPOINTS = [{ endpointId: 'business:shun-goal', kind: 'business-policy' }];
export const INTENT_TYPES = ['goal-interpret'];
export const EFFECT_TYPES = ['effect:goal-interpret'];

const fromEvent = {
  llmRequest: { source: 'event', path: ['payload', 'llmRequest'] },
  approvalRef: { source: 'event', path: ['payload', 'approvalRef'] },
  currentnessRef: { source: 'event', path: ['payload', 'currentnessRef'] },
  // Kernel admission consumes this safe-token field for the idempotency
  // fence; the effect handler forwards only the three C-contract fields.
  idempotencyToken: { source: 'event', path: ['payload', 'idempotencyToken'] },
};
const definition = {
  workflowKey: 'shun-goal', initialState: 'ready', initialContext: {},
  guards: [],
  states: [
    { stateKey: 'ready', transitions: [{
      transitionKey: 'interpret',
      trigger: { kind: 'event', eventType: 'GOAL_INTERPRET_REQUESTED' },
      targetState: 'ready',
      effectIntents: [{
        effectType: 'effect:goal-interpret', inputFrom: fromEvent,
        // The idempotency token is the Host-issued request id (safe-token
        // charset); namespace-carrying refs would fail Kernel admission.
        idempotencyKeyFrom: { template: 'goal:{idempotencyToken}' },
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
    policyId: 'shun-goal-interpret',
    domainId: 'shun',
    workflowDefinition: definition,
    decisionSchema,
    governanceSemantics: { hardInvariants: [] },
    initialStateKey: 'ready', initialContext: {},
    rules: {
      'rule:goal-interpret': {
        ruleId: 'rule:goal-interpret',
        eventType: 'GOAL_INTERPRET_REQUESTED',
        payloadFromInput: {
          llmRequest: 'llmRequest',
          approvalRef: 'approvalRef',
          currentnessRef: 'currentnessRef',
          idempotencyToken: 'idempotencyToken',
        },
      },
    },
    intentBindings: {
      'goal-interpret': {
        trigger: { kind: 'event', eventType: 'GOAL_INTERPRET_REQUESTED' },
        ruleId: 'rule:goal-interpret',
        roles: ['requester'],
      },
    },
    effectBindings: {
      'effect:goal-interpret': {
        semantics: 'non-idempotent',
        resource: { key: 'llm', operation: 'interpretGoal' },
        external: { permitTtlMs: 60_000, await: 'terminal' },
        handler: async ({ input, resources }) => {
          if (!resources || typeof resources.call !== 'function') {
            throw new Error('K_RESOURCES_REQUIRED');
          }
          // References are not approvals. The trusted Host adapter MUST
          // resolve them against durable consent/ActionController policy.
          return resources.call('llm', 'interpretGoal', {
            llmRequest: input.llmRequest,
            currentnessRef: input.currentnessRef,
            approvalRef: input.approvalRef,
          });
        },
      },
    },
  };
}
