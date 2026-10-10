// Loop B happy paths: RETAIN policy keeps the provider; the lifecycle output
// is a contract-valid record with exact provenance.

import { JitLifecycleOutputSchema } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { INSTALL_DIR, installWorld, jitInput, run, VERSION } from './helpers.ts';

describe('JIT lifecycle — RETAIN happy path', () => {
  it('acquires from the official source, uses, verifies and retains the provider', async () => {
    const harness = buildHarness();
    installWorld(harness);

    const output = await run(harness, jitInput({ retention: 'RETAIN' }));

    expect(output).toMatchObject({
      taskId: 'task-2026-10-10-002',
      lifecycleState: {
        providerId: 'tool.pdftool',
        version: VERSION,
        state: 'RETAINED',
      },
      finalState: 'RETAINED',
    });
    const record = output as { provenance: Record<string, unknown>; r2Gate?: unknown };
    expect(record.provenance).toMatchObject({
      source: 'winget',
      official: true,
      version: VERSION,
      licenseDisposition: expect.stringContaining('MIT'),
    });
    // No removal happened: no R2 gate record, provider still on disk.
    expect(record.r2Gate).toBeUndefined();
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
    expect(harness.approval.requests).toHaveLength(0);
    // Lifecycle state was durably persisted before any decision.
    expect([...harness.store.records.values()][0]?.recordKind).toBe('lifecycle_record');
    // The observable gate trace never opened an R2 phase.
    expect(harness.traces.map((event) => event.kind)).not.toContain('R2_PLAN');
  });

  it('emits an output that parses against the frozen C-002 output schema', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const output = await run(harness, jitInput({ retention: 'RETAIN' }));
    expect(() => JitLifecycleOutputSchema.parse(output)).not.toThrow();
  });

  it('names the exact acquired version in the provenance record', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const output = (await run(harness, jitInput({ retention: 'RETAIN' }))) as {
      provenance: { version: string; hash?: string; signature?: string };
    };
    expect(output.provenance.version).toBe(VERSION);
    expect(output.provenance.hash).toBe(
      'b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1',
    );
    expect(output.provenance.signature).toContain('authenticode:');
  });

  it('refuses the benchmark envelope at the production entry point', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const envelope = {
      ...jitInput({ retention: 'RETAIN' }),
      preExistingUserAssets: [{ path: 'C:\\x.txt' }],
    };
    await expect(runJitLifecycle(envelope, harness.deps)).rejects.toMatchObject({
      name: 'ShunContractError',
    });
  });
});
