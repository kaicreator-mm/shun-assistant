/**
 * T09 — v0.3 Control API side seam in front of the single trusted gateway.
 *
 * This is the HTTP-layer mapping ONLY: it hands bounded request input to the
 * T09 `ControlApiGateway` (packages/domain-app/src/api/gateway.ts) and maps
 * receipts to HTTP statuses. It does NOT import or call the production
 * interpreter (apps/control-api/src/cloud-interpret.ts) and does not touch
 * server.ts: T11 owns the single-writer route integration that constructs
 * the gateway over the real selected facade. There is no raw facade send and
 * no second admission path here.
 */
import type {
  ControlApiGateway,
  SendReceipt,
} from '../../../../packages/domain-app/src/api/gateway.ts';

export interface V03GatewayRouteDeps {
  /** The single trusted gateway (T11 binds the real facade into it). */
  readonly gateway: ControlApiGateway;
}

export interface V03GatewayRoute {
  submit(rawInput: unknown): Promise<SendReceipt>;
  /** HTTP status mapping for a settled receipt (200 sent / 422 refused). */
  httpStatus(receipt: SendReceipt): number;
}

const SENT_HTTP_STATUS = 200;
const REFUSED_HTTP_STATUS = 422;
const ROUTE_CONFIG_REFUSED = 'V03_GATEWAY_ROUTE_CONFIGURATION_REFUSED';

/**
 * Build the frozen v0.3 gateway route over the injected trusted gateway.
 * Unknown gateway shapes refuse at construction; the route never exposes a
 * raw send and never accepts approval/grant object content (references only,
 * enforced inside the gateway's pre-send validation).
 */
export function createV03GatewayRoute(deps: V03GatewayRouteDeps): V03GatewayRoute {
  try {
    const rawSubmit = deps?.gateway?.submit;
    if (typeof rawSubmit !== 'function') throw new Error(ROUTE_CONFIG_REFUSED);
    const submit = rawSubmit.bind(deps.gateway);
    return Object.freeze({
      submit(rawInput: unknown): Promise<SendReceipt> {
        return submit(rawInput);
      },
      httpStatus(receipt: SendReceipt): number {
        return receipt.status === 'SENT' ? SENT_HTTP_STATUS : REFUSED_HTTP_STATUS;
      },
    }) satisfies V03GatewayRoute;
  } catch {
    throw new TypeError(ROUTE_CONFIG_REFUSED);
  }
}
