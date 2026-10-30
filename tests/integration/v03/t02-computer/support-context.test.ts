import { SupportContextResultSchema } from '@shun/vertical-support';
import { describe, expect, it, vi } from 'vitest';
import {
  COMPUTER_SUPPORT_CONTEXT_SCHEMA,
  collectLocalComputerSupportContext,
  minimizeComputerSupportFixture,
} from '../../../../packages/domain-computer/src/computer/support-context.ts';

const CANARY = 'SHUN_FAKE_API_KEY_123_SECRET_DO_NOT_EXPORT';
function rawObservation() {
  return {
    os: { name: 'Windows 11', build: '26200' },
    device: { model: 'Fixture workstation' },
    updates: { last_check: '2026-10-30' },
    env: {
      API_KEY: CANARY,
      PATH: 'C:\\fixture\\private\\documents',
    },
    processes: [
      {
        name: 'private-sensitive-process',
        command_line: `--token=${CANARY}`,
      },
    ],
    unrelated_document: `Unrelated private text: ${CANARY}`,
  };
}

describe('T02 B-040 local-only Computer Business adapter', () => {
  it('reuses the frozen B-040 minimizer and returns only the public local-only schema', () => {
    const result = minimizeComputerSupportFixture(rawObservation());
    expect(result.schema).toBe(COMPUTER_SUPPORT_CONTEXT_SCHEMA);
    expect(result.source).toBe('FIXTURE_ONLY');
    expect(result.result.report.schema).toBe('shun.support-context.v1');
    expect(result.result.localOnly).toBe(true);
    expect(result.result.externalDisclosures).toEqual([]);
    expect(SupportContextResultSchema.safeParse(result.result).success).toBe(true);
    expect(result.result.report.os.name).toBe('Windows 11');
    expect(result.result.report.device.model).toBe('Fixture workstation');
    expect(result.result.report.redactions).toEqual([
      { field: 'env[0].value', marker: '[REDACTED]' },
      { field: 'env[1].value', marker: '[REDACTED]' },
      { field: 'processes[0].name', marker: '[REDACTED]' },
      { field: 'processes[0].command_line', marker: '[REDACTED]' },
      { field: 'unrelated_document', marker: '[REDACTED]' },
    ]);
    expect(JSON.stringify(result)).not.toContain(CANARY);
    expect(JSON.stringify(result)).not.toContain('private-sensitive-process');
    expect(JSON.stringify(result)).not.toContain('C:\\fixture\\private');
    expect(result.result.report).not.toHaveProperty('env');
    expect(result.result.report).not.toHaveProperty('processes');
    expect(result.result.report).not.toHaveProperty('unrelated_document');
    expect(Object.isFrozen(result.result.report)).toBe(true);
  });

  it('redacts sensitive paths and credential-like tokens in allowed outbound fields', () => {
    const raw = rawObservation();
    raw.os.name = 'C:\\Users\\fixture\\private';
    raw.device.model = 'password-not-for-sharing';
    raw.updates.last_check = '-----BEGIN PRIVATE KEY-----';
    const result = minimizeComputerSupportFixture(raw);
    expect(result.result.report.os.name).toBe('[REDACTED]');
    expect(result.result.report.device.model).toBe('[REDACTED]');
    expect(result.result.report.updates.last_check).toBe('[REDACTED]');
    expect(result.result.report.redactions.map((item) => item.field)).toEqual(
      expect.arrayContaining(['os.name', 'device.model', 'updates.last_check']),
    );
    expect(JSON.stringify(result)).not.toContain('C:\\Users\\fixture');
    expect(JSON.stringify(result)).not.toContain('PRIVATE KEY');
  });

  it('rejects unknown fields, claimed authorities and malformed observation instead of forgiving them', () => {
    const extra = { ...rawObservation(), grant: { approved: true } };
    expect(() => minimizeComputerSupportFixture(extra)).toThrow('SUPPORT_CONTEXT_INVALID');
    expect(() => minimizeComputerSupportFixture(null)).toThrow('SUPPORT_CONTEXT_INVALID');
    expect(() =>
      minimizeComputerSupportFixture({
        ...rawObservation(),
        os: { name: 'Windows', build: '' },
      }),
    ).toThrow('SUPPORT_CONTEXT_INVALID');
    expect(() =>
      minimizeComputerSupportFixture({
        ...rawObservation(),
        externalDisclosures: ['https://example.invalid'],
      }),
    ).toThrow('SUPPORT_CONTEXT_INVALID');
  });

  it('never turns untrusted fixture data into actual Host provenance', () => {
    const result = minimizeComputerSupportFixture(rawObservation());
    expect(result.source).toBe('FIXTURE_ONLY');
    expect(result.source).not.toBe('ACTUAL_WINDOWS_HOST');
    expect(result).not.toHaveProperty('isHostAttested');
    expect(result).not.toHaveProperty('effectPermit');
    expect(result).not.toHaveProperty('approval');
    expect(result).not.toHaveProperty('grant');
  });

  it('uses no fetch/network channel for offline minimization', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('forbidden automatic disclosure');
    });
    try {
      const output = minimizeComputerSupportFixture(rawObservation());
      expect(output.result.externalDisclosures).toHaveLength(0);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('refuses actual collector entry on non-Windows hosts without any substitute', async () => {
    if (process.platform === 'win32') {
      // Actual collection on Windows is a separate explicit read-only Host gate.
      return;
    }
    await expect(collectLocalComputerSupportContext()).rejects.toThrow('WINDOWS_REQUIRED');
  });
});
