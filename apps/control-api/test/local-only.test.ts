import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import type { TaskSnapshot } from '../src/index.ts';
import { createControlServer } from '../src/index.ts';
import { cleanupGoalRequest, imageGoalRequest, startHarness, type TestHarness } from './helpers.ts';

let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

describe('local-only disclosure (Issue #19 acceptance)', () => {
  it('refuses to bind a non-loopback host at construction time', () => {
    expect(() => createControlServer({ backend: h.backend, host: '0.0.0.0' })).toThrowError(
      /only loopback/,
    );
    expect(() => createControlServer({ backend: h.backend, host: '192.168.1.10' })).toThrowError(
      /LOCAL_ONLY_VIOLATION/,
    );
  });

  it('refuses requests whose Host header is not loopback (defense in depth)', async () => {
    const forged = await h.raw('/api/health', { host: 'control.example.net:80' });
    expect(forged.status).toBe(403);
    expect((forged.body as { error: { code: string } }).error.code).toBe('LOCAL_ONLY_VIOLATION');
  });

  it('health discloses the local-only posture', async () => {
    const health = (await h.get('/api/health')).body as { localOnly: boolean };
    expect(health.localOnly).toBe(true);
  });

  it('discloses local-only enforcement on the task snapshot for a local-only goal', async () => {
    const created = await h.post('/api/tasks', cleanupGoalRequest());
    const snapshot = created.body as TaskSnapshot;
    expect(snapshot.localOnly).toEqual({ enforced: true, externalDisclosure: 'FORBIDDEN' });
  });

  it('evidence endpoints resolve local refs only — never URLs or paths', async () => {
    const created = await h.post('/api/tasks', cleanupGoalRequest());
    const taskId = (created.body as TaskSnapshot).taskId;
    const residue = (await h.get(`/api/tasks/${taskId}/residue?detail=true`)).body as {
      items: { evidenceRef: string; path: string }[];
    };
    const first = residue.items[0]!.evidenceRef;
    const local = await h.get(`/api/evidence/${first}`);
    expect(local.status).toBe(200);
    expect((local.body as { ref: string }).ref).toBe(first);

    const url = await h.get('/api/evidence/https:%2F%2Fexample.net%2Fevidence.json');
    expect(url.status).toBe(400);
    expect((url.body as { error: { code: string } }).error.code).toBe('EVIDENCE_REF_INVALID');

    const traversal = await h.get('/api/evidence/local:../secrets');
    expect(traversal.status).toBe(400);
    expect((traversal.body as { error: { code: string } }).error.code).toBe('EVIDENCE_REF_INVALID');

    const missing = await h.get('/api/evidence/local:no-such-record');
    expect(missing.status).toBe(404);
    expect((missing.body as { error: { code: string } }).error.code).toBe('EVIDENCE_NOT_FOUND');
  });

  it('a non-local-only goal still records its declared externalDisclosure honestly', async () => {
    const created = await h.post(
      '/api/tasks',
      imageGoalRequest({
        policyContext: {
          privacyPolicy: { localOnly: false, externalDisclosure: 'POLICY_CONTROLLED' },
          environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
        },
      }),
    );
    const snapshot = created.body as TaskSnapshot;
    expect(snapshot.localOnly).toEqual({
      enforced: false,
      externalDisclosure: 'POLICY_CONTROLLED',
    });
  });
});

describe('static control UI hosting', () => {
  it('serves the UI directory, falls back to index.html, and refuses traversal', async () => {
    const uiDir = mkdtempSync(join(tmpdir(), 'shun-control-ui-'));
    writeFileSync(join(uiDir, 'index.html'), '<!doctype html><title>Shun Control</title>');
    const ui = await startHarness({ uiDir });
    try {
      const page = await fetch(`${ui.baseUrl}/`);
      expect(page.status).toBe(200);
      expect(await page.text()).toContain('Shun Control');
      const spa = await fetch(`${ui.baseUrl}/some/client/route`);
      expect(spa.status).toBe(200);
      // fetch() would canonicalize '/../' away, so probe the traversal guard
      // with a raw request carrying an encoded dot-dot segment.
      const traversal = await ui.raw('/..%2Fserver.ts', {});
      expect(traversal.status).toBe(403);
    } finally {
      await ui.close();
    }
  });
});
