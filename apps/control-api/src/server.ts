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
import type { GoalRequest } from '@shun/contracts';
import { GoalRequestSchema } from '@shun/contracts';
import { z } from 'zod';
import {
  CONTROL_ERROR_CODES,
  ControlError,
  type ControlErrorCode,
  httpStatusForCode,
} from './errors.ts';
import type { ControlBackend } from './ports.ts';

export const CONTROL_API_REVISION = 'shun.control-api/0.1';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

const DecisionBodySchema = z.strictObject({
  approved: z.boolean(),
  planHash: z.string().regex(/^[0-9a-f]{64}$/, 'planHash must be a lowercase sha-256 hex digest'),
  reason: z.string().min(1).optional(),
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

  const server = createServer((req, res) => {
    handle(options.backend, req, res, { host, uiRoot, maxBodyBytes }).catch((error: unknown) => {
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
  uiRoot?: string;
  maxBodyBytes: number;
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
    return respondJson(res, 200, {
      ok: true,
      api: CONTROL_API_REVISION,
      localOnly: true,
      policy: backend.meta().policy,
    });
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
