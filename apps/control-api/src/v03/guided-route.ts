/**
 * Host-backed Guided State / Decision HTTP seam. The trusted composition
 * creates the port; untrusted HTTP can only read state or relay an answer.
 * No route can mint a grant, consent, Kernel Permit or effect command.
 */
import type {
  GuidedDecisionReceipt,
  HostGuidedService,
} from '../../../../packages/domain-host/src/guided/host-guided-service.ts';

export type V03GuidedPort = Pick<HostGuidedService, 'state' | 'decide'>;

export interface V03GuidedRoute {
  state(): ReturnType<V03GuidedPort['state']>;
  decide(raw: unknown): GuidedDecisionReceipt;
  httpStatus(result: GuidedDecisionReceipt): number;
}

export function createV03GuidedRoute(port: V03GuidedPort): V03GuidedRoute {
  if (!port || typeof port.state !== 'function' || typeof port.decide !== 'function') {
    throw new TypeError('V03_GUIDED_HOST_UNAVAILABLE');
  }
  const state = port.state.bind(port);
  const decide = port.decide.bind(port);
  return Object.freeze({
    state,
    decide,
    httpStatus(result: GuidedDecisionReceipt) {
      switch (result.status) {
        case 'RECORDED':
          return 200;
        case 'STALE':
          return 409;
        case 'REFUSED':
          return 422;
        case 'UNKNOWN':
          return 503;
      }
    },
  });
}
