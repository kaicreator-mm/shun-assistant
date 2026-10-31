/**
 * v0.3 T11 — Shun-owned Business Domain Package for the real selected-K
 * Windows effect journey.
 * =====================================================================
 *
 * One Business whose GOVERNED effect binding declares `external`: the
 * selected Kernel mints a live Effect Permit scoped to `windows:windows.execute`
 * before the T01 Windows Host adapter may dispatch. The permitless PROBE
 * binding is the negative witness: the same sealed route WITHOUT an
 * `external` declaration must be typed-refused with ZERO adapter dispatch.
 *
 * The handler forwards EXACTLY the three T01 payload fields (actionRef /
 * planRef / grantRef): the effectId comes exclusively from the K dispatch
 * context, never from caller JSON. Imports nothing — sealed capabilities are
 * reached only through the kernel-owned `resources` port.
 *
 * Kernel ABI: v08-business-abi/1 — endpoint export `getPolicy()`.
 */
export const MODULE_ID = 'business-windows-journey@v030.1.0.0';
export const PACKAGE_KIND = 'business';
export const ABI_VERSION = 'v08-business-abi/1';
export const ENDPOINTS = [{ endpointId: 'business:windows-journey', kind: 'business-policy' }];

export const INTENT_TYPES = ['submitWindowsAction', 'submitUnpermittedWindowsProbe'];
export const EFFECT_TYPES = ['effect:windows-execute', 'effect:unpermitted-probe'];

/** Full workflow field projection: every rule sees every declared field. */
const WORKFLOW_RULE_FIELDS = {
  payloadFromInput: { actionRef: 'actionRef', planRef: 'planRef', grantRef: 'grantRef', taskId: 'taskId' },
};
const ACTION_INPUT_FROM = {
  actionRef: { source: 'event', path: ['payload', 'actionRef'] },
  planRef: { source: 'event', path: ['payload', 'planRef'] },
  grantRef: { source: 'event', path: ['payload', 'grantRef'] },
};

function makeDefinition() {
  return {
    workflowKey: 'windows-journey',
    initialState: 'open',
    initialContext: {},
    guards: [],
    states: [
      {
        // Self-loop: each submission is its own occurrence on the same thread.
        stateKey: 'open',
        transitions: [
          {
            transitionKey: 'run-windows-action',
            trigger: { kind: 'event', eventType: 'WINDOWS_ACTION_REQUESTED' },
            targetState: 'open',
            effectIntents: [
              {
                effectType: 'effect:windows-execute',
                inputFrom: ACTION_INPUT_FROM,
                idempotencyKeyFrom: { template: 'win:{actionRef}' },
              },
            ],
          },
          {
            transitionKey: 'probe-unpermitted',
            trigger: { kind: 'event', eventType: 'WINDOWS_PROBE_REQUESTED' },
            targetState: 'open',
            effectIntents: [{ effectType: 'effect:unpermitted-probe', inputFrom: ACTION_INPUT_FROM }],
          },
        ],
      },
      { stateKey: 'closed', kind: 'final' },
    ],
  };
}

const decisionSchema = {
  isValid(value) {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    const decision = value.decision;
    const event = value.event;
    if (typeof decision !== 'object' || decision === null || Array.isArray(decision)) return false;
    if (typeof event !== 'object' || event === null || Array.isArray(event)) return false;
    return typeof decision.outcome === 'string' && typeof event.type === 'string';
  },
};

export function getPolicy() {
  return {
    packageId: MODULE_ID,
    policyId: 'windows-journey',
    domainId: 'windows',
    workflowDefinition: makeDefinition(),
    decisionSchema,
    governanceSemantics: { hardInvariants: [] },
    initialStateKey: 'open',
    initialContext: {},
    rules: {
      'rule:windows-action': {
        ruleId: 'rule:windows-action',
        eventType: 'WINDOWS_ACTION_REQUESTED',
        ...WORKFLOW_RULE_FIELDS,
      },
      'rule:windows-probe': {
        ruleId: 'rule:windows-probe',
        eventType: 'WINDOWS_PROBE_REQUESTED',
        ...WORKFLOW_RULE_FIELDS,
      },
    },
    intentBindings: {
      submitWindowsAction: {
        trigger: { kind: 'event', eventType: 'WINDOWS_ACTION_REQUESTED' },
        ruleId: 'rule:windows-action',
        roles: ['requester'],
      },
      submitUnpermittedWindowsProbe: {
        trigger: { kind: 'event', eventType: 'WINDOWS_PROBE_REQUESTED' },
        ruleId: 'rule:windows-probe',
        roles: ['requester'],
      },
    },
    effectBindings: {
      // GOVERNED external effect: `external` makes the Kernel mint a live
      // permit scoped to windows:windows.execute before the dispatch, and
      // await:'terminal' refuses any non-terminal adapter ACK.
      'effect:windows-execute': {
        semantics: 'non-idempotent',
        resource: { key: 'windows', operation: 'windows.execute' },
        external: { permitTtlMs: 3_600_000, await: 'terminal' },
        handler: async ({ input, resources }) => {
          if (resources === undefined || typeof resources.call !== 'function') {
            throw new Error('effect:windows-execute requires the kernel resources port');
          }
          // EXACT T01 payload shape: the K dispatch context owns effectId.
          return resources.call('windows', 'windows.execute', {
            actionRef: input.actionRef,
            planRef: input.planRef,
            grantRef: input.grantRef,
          });
        },
      },
      // PERMITLESS negative: same sealed route, NO `external` declaration —
      // the K→C gate must refuse before the adapter with zero dispatch.
      'effect:unpermitted-probe': {
        semantics: 'idempotent',
        resource: { key: 'windows', operation: 'windows.execute' },
        handler: async ({ input, resources }) => {
          if (resources === undefined || typeof resources.call !== 'function') {
            throw new Error('effect:unpermitted-probe requires the kernel resources port');
          }
          return resources.call('windows', 'windows.execute', {
            actionRef: input.actionRef,
            planRef: input.planRef,
            grantRef: input.grantRef,
          });
        },
      },
    },
  };
}
