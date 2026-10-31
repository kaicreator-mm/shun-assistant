// Local control-surface HTTP API (T08, L2 §12).
//
// Non-authoritative by construction: no route accepts or returns grant
// material, no route constructs an AuthorizedAction, and approval decisions
// are relayed to the backend (which fronts the Action Controller). The server
// binds loopback only and rejects non-loopback Host headers (local-only
// disclosure), and serves the static control-ui directory when configured.

import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { extname, normalize, resolve, sep } from 'node:path';
import { GoalRequestSchema } from '@shun/contracts';
import { buildDeepSeekGoalDisclosure } from '@shun/llm-remote';
import type { RecipeRegistrationResult } from '@shun/resolver';
import {
  collectWindowsReadonlyDiagnosis,
  collectWindowsSystemInventory,
  suggestReadonlyOptimizations,
} from '@shun/vertical-system';
import { z } from 'zod';
import type { ControlApiGateway } from '../../../packages/domain-app/src/api/gateway.ts';
import { MINIMUM_SENDER_DEADLINE_BUDGET_MS } from '../../../packages/domain-host/src/cloud/openai-host.ts';
import type { CloudInterpretPort } from './cloud-interpret.ts';
import {
  CONTROL_ERROR_CODES,
  ControlError,
  type ControlErrorCode,
  httpStatusForCode,
} from './errors.ts';
import type { ControlBackend } from './ports.ts';
import type { AuthorizedInventoryRecipeResult } from './recipe-inventory-run.ts';
import { createV03GatewayRoute, type V03GatewayRoute } from './v03/gateway-route.ts';
import {
  createV03GuidedRoute,
  type V03GuidedPort,
  type V03GuidedRoute,
} from './v03/guided-route.ts';

export const CONTROL_API_REVISION = 'shun.control-api/0.1';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

const DecisionBodySchema = z.strictObject({
  approved: z.boolean(),
  planHash: z.string().regex(/^[0-9a-f]{64}$/, 'planHash must be a lowercase sha-256 hex digest'),
  reason: z.string().min(1).optional(),
});

// Preview only: browser JSON cannot mint trusted broker consent, approve a
// cloud send, choose another provider endpoint or carry authorization material.
const CloudDisclosurePreviewSchema = z.strictObject({
  goalText: z.string().min(1).max(8192),
});

const ClarificationBodySchema = z.strictObject({
  answer: z.string().min(1),
});

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

export interface ControlServerOptions {
  backend: ControlBackend;
  /** Trusted backend-only candidate writer; browser never selects its source. */
  saveBuiltinInventoryCandidate?: () => RecipeRegistrationResult;
  /** Explicit RealStorage-only, never browser-supplied R0 authority. */
  executeBuiltinInventoryRecipe?: () => Promise<AuthorizedInventoryRecipeResult>;
  /** Trusted local SQLite reader; cannot be configured through HTTP. */
  readBuiltinInventoryCandidate?: () =>
    | {
        ok: true;
        saved: boolean;
        state: 'PERSISTED_CANDIDATE_ONLY' | 'NOT_SAVED';
        recipeId: string;
        revisionSha256: string | null;
        executionAuthorized: false;
        modelCalls: 0;
      }
    | { ok: false; code: 'RECIPE_READ_UNAVAILABLE' };
  /** Trusted process composition; never configured by an HTTP request. */
  cloud?: CloudInterpretPort;
  /**
   * T11 — the trusted v0.3 single-domain gateway over the selected K-gated
   * DomainApp facade. The composition root injects either the built gateway
   * or a lazy factory (so importing this server module never pays for a
   * DomainHarness activation); never an HTTP request. The server exposes ONLY
   * the T09 `ControlApiGateway.submit` admission surface — never a raw send.
   */
  v03Gateway?: ControlApiGateway | (() => ControlApiGateway);
  /** Trusted process-side selected Guided Host state, never created from HTTP. */
  v03Guided?: V03GuidedPort;
  /** Directory with the static control-ui app; omitted = API only. */
  uiDir?: string;
  /** Loopback host only; anything else is a construction-time refusal. */
  host?: string;
  port?: number;
  maxBodyBytes?: number;
}

export interface ControlServerHandle {
  server: Server;
  /** Listen on the configured (or an ephemeral) port and return the bound port. */
  start(): Promise<number>;
  close(): Promise<void>;
  readonly host: string;
  readonly port: number | undefined;
}

export function createControlServer(options: ControlServerOptions): ControlServerHandle {
  const host = options.host ?? '127.0.0.1';
  if (!LOOPBACK_HOSTS.has(host)) {
    // Local-only control surface (Issue #19): a non-loopback bind is refused
    // before the server ever exists — this is not a runtime option.
    throw new ControlError(
      'LOCAL_ONLY_VIOLATION',
      `Control surface refuses to bind “${host}”; only loopback (127.0.0.1) is allowed.`,
    );
  }
  const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
  const uiRoot = options.uiDir ? resolve(options.uiDir) : undefined;

  // The v0.3 gateway route is resolved lazily and at most once: a lazy
  // factory is invoked on the first v0.3 submission, so importing or starting
  // the server never performs a DomainHarness activation. A factory that
  // refuses configuration stays a typed 503 on the route (fail closed),
  // never a crash of the whole surface.
  let v03Route: V03GatewayRoute | undefined;
  let v03RouteRefused = false;
  const v03RouteFor = (): V03GatewayRoute | undefined => {
    if (v03Route !== undefined || v03RouteRefused) return v03Route;
    if (options.v03Gateway === undefined) return undefined;
    try {
      const gateway =
        typeof options.v03Gateway === 'function' ? options.v03Gateway() : options.v03Gateway;
      v03Route = createV03GatewayRoute({ gateway });
    } catch {
      v03RouteRefused = true;
    }
    return v03Route;
  };

  const v03GuidedRoute: V03GuidedRoute | undefined =
    options.v03Guided === undefined ? undefined : createV03GuidedRoute(options.v03Guided);

  const server = createServer((req, res) => {
    handle(options.backend, req, res, {
      host,
      uiRoot,
      maxBodyBytes,
      saveBuiltinInventoryCandidate: options.saveBuiltinInventoryCandidate,
      executeBuiltinInventoryRecipe: options.executeBuiltinInventoryRecipe,
      readBuiltinInventoryCandidate: options.readBuiltinInventoryCandidate,
      cloud: options.cloud,
      v03RouteFor,
      v03GuidedRoute,
    }).catch((error: unknown) => {
      respondError(res, error);
    });
  });

  return {
    server,
    host,
    port: options.port,
    start: () =>
      new Promise<number>((resolvePort, rejectPort) => {
        server.once('error', rejectPort);
        const port = options.port ?? 0;
        server.listen(port, host === 'localhost' ? '127.0.0.1' : host, () => {
          const address = server.address();
          resolvePort(typeof address === 'object' && address ? address.port : port);
        });
      }),
    close: () =>
      new Promise<void>((resolveClose, rejectClose) => {
        // Tests (and fast local clients) hold keep-alive sockets; idle ones
        // must not stall close(). Anything still open once 'close' fires is
        // torn down deterministically.
        server.closeIdleConnections?.();
        server.close((error) => {
          server.closeAllConnections?.();
          if (error) rejectClose(error);
          else resolveClose();
        });
      }),
  };
}

interface RouteContext {
  host: string;
  cloud?: CloudInterpretPort;
  uiRoot?: string;
  maxBodyBytes: number;
  saveBuiltinInventoryCandidate?: ControlServerOptions['saveBuiltinInventoryCandidate'];
  executeBuiltinInventoryRecipe?: ControlServerOptions['executeBuiltinInventoryRecipe'];
  readBuiltinInventoryCandidate?: ControlServerOptions['readBuiltinInventoryCandidate'];
  v03RouteFor: () => V03GatewayRoute | undefined;
  v03GuidedRoute?: V03GuidedRoute;
}

/**
 * Same-origin + JSON gate for mutating requests (CSRF_REFUSED, fail closed):
 * anything that is not this server's own http origin, and any content type a
 * plain HTML form can send (urlencoded / multipart / text/plain), is refused
 * before a route can act on it. Non-browser clients that omit Origin entirely
 * (curl, tests) still pass the Origin arm — the content-type arm holds.
 */
function assertSameOriginJsonMutation(req: IncomingMessage): void {
  const origin = req.headers.origin;
  if (origin !== undefined) {
    const own = `http://${(req.headers.host ?? '').toLowerCase()}`;
    if (origin.toLowerCase() !== own) {
      throw new ControlError(
        'CSRF_REFUSED',
        `Cross-site mutation from “${origin}” is refused; the control surface only accepts ` +
          'mutations from its own loopback origin.',
      );
    }
  }
  const mediaType = (req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (mediaType !== 'application/json') {
    throw new ControlError(
      'CSRF_REFUSED',
      'Mutating requests must declare a JSON body (content-type: application/json); ' +
        'form-encodable content types are refused (cross-site request protection).',
    );
  }
}

async function handle(
  backend: ControlBackend,
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RouteContext,
): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
  const method = req.method ?? 'GET';

  // Defense in depth behind the loopback bind: a Host header that is not
  // loopback means the request was crafted to look like another origin.
  const rawHost = (req.headers.host ?? '').toLowerCase();
  const hostHeader = rawHost.startsWith('[')
    ? rawHost.slice(1, rawHost.indexOf(']'))
    : (rawHost.split(':')[0] ?? '');
  if (!LOOPBACK_HOSTS.has(hostHeader)) {
    throw new ControlError(
      'LOCAL_ONLY_VIOLATION',
      `Non-loopback Host “${req.headers.host}” is refused.`,
    );
  }

  // CSRF protection for the loopback control surface (Issue #41, VC-P1-04).
  // A loopback bind alone is not CSRF protection: cross-site form posts and
  // no-cors fetches are CORS "simple requests" that reach this server without
  // any preflight, and a hostile web page can aim them at 127.0.0.1. Every
  // mutation must therefore (a) come from this server's own origin — browsers
  // attach Origin to every cross-site request, and sandboxed frames send
  // "null" — and (b) declare a JSON body, which no form-encodable content
  // type can. GET/HEAD stay open: they never mutate.
  if (method !== 'GET' && method !== 'HEAD') {
    assertSameOriginJsonMutation(req);
  }

  if (!url.pathname.startsWith('/api/')) {
    if (ctx.uiRoot && method === 'GET') return serveStatic(ctx.uiRoot, url.pathname, res);
    throw new ControlError('NOT_FOUND', `No route for ${method} ${url.pathname}`);
  }

  const segments = url.pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  // segments[0] === 'api'
  const resource = segments[1];
  const id = segments[2];
  const action = segments[3];

  if (method === 'GET' && url.pathname === '/api/health') {
    const meta = backend.meta();
    return respondJson(res, 200, {
      ok: true,
      api: CONTROL_API_REVISION,
      // This is an actual model egress posture, not the loopback bind rule.
      // A remote model can be enabled even while Goal task execution is demo.
      localOnly: ctx.cloud?.status().enabled !== true,
      loopbackOnly: true,
      cloudMode: ctx.cloud?.status().enabled === true ? 'REMOTE_OPT_IN' : 'DISABLED',
      // Simulation disclosure (Issue #41, VC-P2-06): the UI renders a
      // prominent banner from this so the demo backend cannot pass as the
      // real Action Controller.
      simulated: meta.simulated,
      policy: meta.policy,
    });
  }

  // T08 J0: a genuine LOCAL read-only Windows OS observation, not the
  // scripted ControlBackend demo and not a cloud/provider capability. The
  // response contains aggregate memory/disk/CPU facts only; never names,
  // file paths, credentials or arbitrary command output. No HTTP input is
  // forwarded into the trusted T06 system-inventory collector.
  if (method === 'GET' && url.pathname === '/api/system/inventory') {
    const observed = collectWindowsSystemInventory();
    if (!observed.ok) {
      return respondJson(res, 503, {
        ok: false,
        code: 'LIVE_SYSTEM_INVENTORY_UNAVAILABLE',
      });
    }
    return respondJson(res, 200, {
      ok: true,
      source: 'LIVE_WINDOWS_LOCAL_READONLY',
      localOnly: true,
      externalDisclosures: [],
      snapshot: observed.snapshot,
      suggestions: suggestReadonlyOptimizations(observed),
    });
  }

  // T08 C07: existing T06 deterministic Windows diagnosis. Caller cannot
  // select processes, commands, files or a script; no ActionController/Recipe
  // execution is claimed. All observations stay local and no model is invoked.
  if (method === 'GET' && url.pathname === '/api/system/diagnosis') {
    if (url.search) {
      return respondJson(res, 400, { ok: false, code: 'DIAGNOSIS_INPUT_REFUSED' });
    }
    const observed = collectWindowsReadonlyDiagnosis();
    if (!observed.ok) {
      return respondJson(res, 503, { ok: false, code: 'LIVE_DIAGNOSIS_UNAVAILABLE' });
    }
    return respondJson(res, 200, {
      ok: true,
      source: 'LIVE_WINDOWS_LOCAL_READONLY',
      report: observed.report,
      recipeExecuted: false,
      cloudCalls: 0,
    });
  }

  // T08 C01 — Actual T01 disclosure projection, shown locally BEFORE any
  // trusted private IPC gesture. This route performs NO outbound I/O and has
  // no access to consent issuer, credential, ledger or transport.
  if (method === 'POST' && url.pathname === '/api/cloud/disclosure-preview') {
    const parsed = CloudDisclosurePreviewSchema.safeParse(
      await readJsonBody(req, ctx.maxBodyBytes),
    );
    if (!parsed.success) {
      return respondJson(res, 400, { error: { code: 'DISCLOSURE_PREVIEW_INVALID' } });
    }
    const disclosure = buildDeepSeekGoalDisclosure(parsed.data.goalText);
    if (!disclosure) {
      return respondJson(res, 400, { error: { code: 'DISCLOSURE_PREVIEW_INVALID' } });
    }
    return respondJson(res, 200, {
      ok: true,
      status: 'LOCAL_PREVIEW_ONLY',
      projectionJson: disclosure.projectionJson,
      sha256: disclosure.sha256,
      consentIssued: false,
      cloudSendAllowed: false,
      privateBrokerReady: false,
    });
  }

  // T08 C06: bounded real SQLite lookup of the fixed built-in Recipe ONLY.
  // Neither caller-provided hashes nor arbitrary source can be read or run.
  if (method === 'GET' && url.pathname === '/api/recipes/builtin/system-inventory') {
    if (!ctx.readBuiltinInventoryCandidate) {
      return respondJson(res, 503, { ok: false, code: 'RECIPE_STORAGE_UNAVAILABLE' });
    }
    const result = ctx.readBuiltinInventoryCandidate();
    if (!result.ok) {
      return respondJson(res, 503, { ok: false, code: result.code });
    }
    return respondJson(res, 200, result);
  }

  // T08 C05: one fixed local candidate from #195, not arbitrary Recipe
  // source, and not a browser-issued action grant. Refuse Demo/absent Host.
  if (method === 'POST' && url.pathname === '/api/recipes/builtin/system-inventory/save') {
    if (!ctx.saveBuiltinInventoryCandidate) {
      return respondJson(res, 503, { ok: false, code: 'RECIPE_STORAGE_UNAVAILABLE' });
    }
    const body = await readJsonBody(req, ctx.maxBodyBytes);
    if (
      !body ||
      typeof body !== 'object' ||
      Array.isArray(body) ||
      Object.keys(body).length !== 0
    ) {
      return respondJson(res, 400, { ok: false, code: 'RECIPE_INPUT_REFUSED' });
    }
    const saved = ctx.saveBuiltinInventoryCandidate();
    if (!saved.ok) return respondJson(res, 503, { ok: false, code: saved.code });
    return respondJson(res, 200, saved);
  }

  // T08 C07R: only the real host can execute a previously saved immutable
  // fixed Recipe, and only after the REAL T02 R0 durable-policy + effect gate.
  // Caller never supplies a SHA, plan, approval, grant, code or OS arguments.
  if (method === 'POST' && url.pathname === '/api/recipes/builtin/system-inventory/run') {
    if (!ctx.executeBuiltinInventoryRecipe) {
      return respondJson(res, 503, { ok: false, code: 'RECIPE_EXECUTION_UNAVAILABLE' });
    }
    const body = await readJsonBody(req, ctx.maxBodyBytes);
    if (
      !body ||
      typeof body !== 'object' ||
      Array.isArray(body) ||
      Object.keys(body).length !== 0
    ) {
      return respondJson(res, 400, { ok: false, code: 'RECIPE_INPUT_REFUSED' });
    }
    const outcome = await ctx.executeBuiltinInventoryRecipe();
    if (!outcome.ok) {
      return respondJson(res, 409, outcome);
    }
    return respondJson(res, 200, outcome);
  }

  // A true REMOTE model action is available only after trusted process
  // composition. Neither this route nor its input can create cloud consent:
  // C02's real native interactive dialog must approve each exact projection.
  if (method === 'GET' && url.pathname === '/api/cloud/status') {
    return respondJson(res, 200, {
      ...(ctx.cloud?.status() ?? {
        enabled: false,
        provider: 'deepseek',
        model: 'deepseek-flash',
        osConsentRequired: true,
      }),
      tasksSimulated: backend.meta().simulated,
    });
  }

  if (method === 'POST' && url.pathname === '/api/cloud/interpret') {
    const parsed = CloudDisclosurePreviewSchema.safeParse(
      await readJsonBody(req, ctx.maxBodyBytes),
    );
    if (!parsed.success) {
      return respondJson(res, 400, { error: { code: 'CLOUD_GOAL_INVALID' } });
    }
    if (!ctx.cloud?.status().enabled) {
      return respondJson(res, 503, { error: { code: 'CLOUD_UNAVAILABLE' } });
    }
    // T11 (Amendment R1): the absolute request deadline is computed on the
    // trusted side — never from HTTP input — using the same window the T04
    // Host binding requires for a fresh request (consent window + pre-send
    // floor). The interpreter rechecks it at the final pre-send boundary.
    const result = await ctx.cloud.interpretGoal({
      goalText: parsed.data.goalText,
      deadlineUnixMs: Date.now() + MINIMUM_SENDER_DEADLINE_BUDGET_MS,
    });
    if (!result.ok) {
      return respondJson(res, result.code === 'CONSENT_DECLINED' ? 409 : 503, {
        error: { code: result.code },
      });
    }
    return respondJson(res, 200, result);
  }

  // R02 Guided routes operate solely on trusted Host-owned durable state.
  // They never accept a grant, full approval payload or Kernel Permit from
  // the caller. Decisions are atomic single-use acknowledgement records.
  if (method === 'GET' && url.pathname === '/api/v03/guided/state') {
    if (!ctx.v03GuidedRoute) {
      return respondJson(res, 503, { ok: false, code: 'V03_GUIDED_UNAVAILABLE' });
    }
    return respondJson(res, 200, ctx.v03GuidedRoute.state());
  }
  if (method === 'POST' && url.pathname === '/api/v03/guided/decision') {
    if (!ctx.v03GuidedRoute) {
      return respondJson(res, 503, { ok: false, code: 'V03_GUIDED_UNAVAILABLE' });
    }
    const result = ctx.v03GuidedRoute.decide(await readJsonBody(req, ctx.maxBodyBytes));
    return respondJson(res, ctx.v03GuidedRoute.httpStatus(result), result);
  }

  // T11 — the single v0.3 submission surface. Bounded JSON in, one T09
  // ControlApiGateway admission out: the gateway fully validates the
  // submission BEFORE the selected DomainApp facade is ever touched, so a
  // refused submission performs zero `send` calls and can never reserve a K
  // journal entry. The route never exposes a raw send and never accepts
  // approval or grant object content (references only, enforced in-gateway).
  if (method === 'POST' && url.pathname === '/api/v03/gateway/submit') {
    const route = ctx.v03RouteFor();
    if (route === undefined) {
      return respondJson(res, 503, { ok: false, code: 'V03_GATEWAY_UNAVAILABLE' });
    }
    const body = await readJsonBody(req, ctx.maxBodyBytes);
    const receipt = await route.submit(body);
    return respondJson(res, route.httpStatus(receipt), receipt);
  }

  if (resource === 'tasks') {
    if (method === 'POST' && !id) {
      const body = await readJsonBody(req, ctx.maxBodyBytes);
      const parsed = GoalRequestSchema.safeParse(body);
      if (!parsed.success) {
        throw new ControlError('TASK_INVALID_BODY', firstIssue(parsed.error.issues));
      }
      const { taskId } = await backend.submitGoal(parsed.data);
      const snapshot = await backend.taskSnapshot(taskId);
      return respondJson(res, 201, snapshot);
    }
    if (method === 'GET' && !id) {
      return respondJson(res, 200, { tasks: await backend.listTasks() });
    }
    if (method === 'GET' && id && !action) {
      const snapshot = await backend.taskSnapshot(id);
      if (!snapshot) throw new ControlError('TASK_NOT_FOUND', `No task “${id}”.`);
      return respondJson(res, 200, snapshot);
    }
    if (method === 'GET' && id && action === 'preview') {
      const preview = await backend.taskPreview(id);
      if (!preview)
        throw new ControlError('PREVIEW_NOT_AVAILABLE', `Task “${id}” has no plan to preview yet.`);
      return respondJson(res, 200, preview);
    }
    if (method === 'GET' && id && action === 'residue') {
      const detail = url.searchParams.get('detail') === 'true';
      const residue = await backend.residueSummary(id, detail);
      if (!residue)
        throw new ControlError('TASK_NOT_FOUND', `Task “${id}” has no residue summary.`);
      return respondJson(res, 200, residue);
    }
    if (method === 'POST' && id && action === 'cancel') {
      return respondOutcome(res, await backend.cancelTask(id));
    }
    if (method === 'POST' && id && action === 'clarification') {
      const parsed = ClarificationBodySchema.safeParse(await readJsonBody(req, ctx.maxBodyBytes));
      if (!parsed.success)
        throw new ControlError('TASK_INVALID_BODY', firstIssue(parsed.error.issues));
      return respondOutcome(res, await backend.answerClarification(id, parsed.data.answer));
    }
    if (method === 'POST' && id && action === 'recovery') {
      return respondOutcome(res, await backend.reconcileTask(id));
    }
    if (method === 'POST' && id && action === 'retry') {
      return respondOutcome(res, await backend.retryTask(id));
    }
  }

  if (resource === 'approvals') {
    if (method === 'GET' && !id) {
      return respondJson(res, 200, { approvals: await backend.pendingApprovals() });
    }
    if (method === 'GET' && id && !action) {
      const found = await backend.approvalWithPreview(id);
      if (!found) throw new ControlError('APPROVAL_NOT_FOUND', `No approval “${id}”.`);
      return respondJson(res, 200, found);
    }
    if (method === 'POST' && id && action === 'decision') {
      const parsed = DecisionBodySchema.safeParse(await readJsonBody(req, ctx.maxBodyBytes));
      if (!parsed.success)
        throw new ControlError('TASK_INVALID_BODY', firstIssue(parsed.error.issues));
      return respondOutcome(
        res,
        await backend.decideApproval({
          approvalId: id,
          approved: parsed.data.approved,
          seenPlanHash: parsed.data.planHash,
          reason: parsed.data.reason,
        }),
      );
    }
  }

  if (resource === 'evidence' && method === 'GET' && id) {
    // Re-join in case the ref contained a slash (/api/evidence/local:residue/item-001).
    const ref = segments.slice(2).join('/');
    return respondOutcome(res, await backend.evidence(ref));
  }

  throw new ControlError('NOT_FOUND', `No route for ${method} ${url.pathname}`);
}

function respondOutcome(
  res: ServerResponse,
  outcome: { ok: true; value: unknown } | { ok: false; code: string; detail: string },
): void {
  if (outcome.ok) {
    respondJson(res, 200, outcome.value);
    return;
  }
  const known = CONTROL_ERROR_CODES.includes(outcome.code as ControlErrorCode);
  const status = known ? httpStatusForCode(outcome.code as ControlErrorCode) : 409;
  respondJson(res, status, { error: { code: outcome.code, detail: outcome.detail } });
}

function respondJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body, null, 2));
}

function respondError(res: ServerResponse, error: unknown): void {
  if (error instanceof ControlError) {
    respondJson(res, error.status, { error: { code: error.code, detail: error.message } });
    return;
  }
  respondJson(res, 500, { error: { code: 'INTERNAL', detail: String(error) } });
}

function firstIssue(issues: { path: (string | number | symbol)[]; message: string }[]): string {
  const issue = issues[0];
  const path = issue ? issue.path.map(String).join('.') : '';
  return issue ? `${path ? `${path}: ` : ''}${issue.message}` : 'invalid body';
}

async function readJsonBody(req: IncomingMessage, maxBodyBytes: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > maxBodyBytes)
      throw new ControlError('BODY_TOO_LARGE', `Body exceeds ${maxBodyBytes} bytes.`);
    chunks.push(chunk as Buffer);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) throw new ControlError('INVALID_JSON_BODY', 'Request body must be JSON.');
  try {
    return JSON.parse(text);
  } catch {
    throw new ControlError('INVALID_JSON_BODY', 'Request body is not valid JSON.');
  }
}

async function serveStatic(uiRoot: string, pathname: string, res: ServerResponse): Promise<void> {
  const decoded = decodeURIComponent(pathname);
  // Fail closed on traversal segments BEFORE any normalization: win32
  // normalize() silently collapses "/../x" to "\x", which would erase the
  // attack instead of refusing it (same rule as contracts pathWithin).
  if (decoded.split(/[\\/]/).includes('..')) {
    throw new ControlError('LOCAL_ONLY_VIOLATION', 'Path escapes the control UI root.');
  }
  const relative = normalize(decoded).replace(/^([/\\])+/, '');
  const target = resolve(uiRoot, relative === '' ? 'index.html' : relative);
  // Traversal guard: the resolved path must stay inside the UI root.
  if (target !== uiRoot && !target.startsWith(uiRoot + sep)) {
    throw new ControlError('LOCAL_ONLY_VIOLATION', 'Path escapes the control UI root.');
  }
  const file =
    existsSync(target) && statSync(target).isFile() ? target : resolve(uiRoot, 'index.html');
  if (!existsSync(file)) throw new ControlError('NOT_FOUND', 'Control UI is not available.');
  const mime = MIME[extname(file)] ?? 'application/octet-stream';
  res.writeHead(200, { 'content-type': mime, 'cache-control': 'no-store' });
  createReadStream(file).pipe(res);
}
