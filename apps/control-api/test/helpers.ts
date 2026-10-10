import { request as httpRequest } from 'node:http';
import type { GoalRequest } from '@shun/contracts';
import { createControlServer, DemoShunBackend } from '../src/index.ts';
import type { PolicyState } from '../src/ports.ts';
import type { ControlServerHandle } from '../src/server.ts';

export type ApiBody = unknown;

export interface ApiResponse {
  status: number;
  body: ApiBody;
}

export interface TestHarness {
  backend: DemoShunBackend;
  server: ControlServerHandle;
  baseUrl: string;
  setNow(instant: string): void;
  get(path: string): Promise<ApiResponse>;
  post(path: string, body?: unknown): Promise<ApiResponse>;
  /** Raw request with arbitrary headers (e.g. a forged non-loopback Host). */
  raw(path: string, headers: Record<string, string>): Promise<ApiResponse>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  policy?: PolicyState;
  maxBodyBytes?: number;
  uiDir?: string;
}

/** Fixed start instant for all tests; `setNow` moves the injected clock. */
export const T0 = '2026-10-10T08:00:00.000Z';

export async function startHarness(options: HarnessOptions = {}): Promise<TestHarness> {
  let now = T0;
  const backend = new DemoShunBackend({ clock: () => now, policy: options.policy });
  const server = createControlServer({
    backend,
    uiDir: options.uiDir,
    maxBodyBytes: options.maxBodyBytes,
  });
  const port = await server.start();
  const baseUrl = `http://127.0.0.1:${port}`;

  const call = async (method: string, path: string, body?: unknown): Promise<ApiResponse> => {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : undefined };
  };

  return {
    backend,
    server,
    baseUrl,
    setNow: (instant) => {
      now = instant;
    },
    get: (path) => call('GET', path),
    post: (path, body) => call('POST', path, body ?? {}),
    raw: (path, headers) =>
      new Promise((resolveRaw, rejectRaw) => {
        const req = httpRequest({ host: '127.0.0.1', port, path, headers }, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let body: unknown = text;
            try {
              body = text ? JSON.parse(text) : undefined;
            } catch {
              // non-JSON responses (e.g. static HTML) are passed through
            }
            resolveRaw({ status: res.statusCode ?? 0, body });
          });
        });
        req.on('error', rejectRaw);
        req.end();
      }),
    close: () => server.close(),
  };
}

/** A valid C-000 GoalRequest for the demo cleanup intent (R2 approval path). */
export function cleanupGoalRequest(overrides: Partial<GoalRequest> = {}): GoalRequest {
  return {
    taskId: 'req-cleanup-001',
    goal: 'clean up the DemoApp cache leftovers',
    objects: [{ kind: 'DIRECTORY', ref: 'C:\\Users\\demo\\AppData\\Local\\DemoApp' }],
    constraints: {},
    policyContext: {
      privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    },
    ...overrides,
  };
}

export function imageGoalRequest(overrides: Partial<GoalRequest> = {}): GoalRequest {
  return {
    taskId: 'req-images-001',
    goal: 'resize my holiday pictures',
    objects: [{ kind: 'DIRECTORY', ref: 'C:\\demo\\pictures' }],
    constraints: { format: 'JPG' },
    policyContext: {
      privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    },
    ...overrides,
  };
}
