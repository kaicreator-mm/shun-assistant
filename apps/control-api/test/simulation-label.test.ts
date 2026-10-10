import { describe, expect, it } from 'vitest';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

// Negative control for Issue #41 / VC-P2-06: the surface must prominently
// disclose that it runs DemoShunBackend — a scripted simulation, not the real
// Action Controller — so a user cannot mistake demo approvals for real-world
// authority. The disclosure has to be machine-readable (health/meta) so the
// UI can render a prominent banner from the actual backend posture.
describe('simulation disclosure (VC-P2-06)', () => {
  it('meta forces the backend to declare its simulation status', async () => {
    const h = await startHarness();
    try {
      expect(h.backend.meta().simulated).toBe(true);
    } finally {
      await h.close();
    }
  });

  it('health carries the simulation flag the UI banner renders', async () => {
    const h = await startHarness();
    try {
      await h.post('/api/tasks', cleanupGoalRequest()); // health is not task-dependent; exercise the API anyway
      const health = (await h.get('/api/health')).body as { simulated?: boolean };
      expect(health.simulated).toBe(true);
    } finally {
      await h.close();
    }
  });
});
