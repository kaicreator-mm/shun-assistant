import { describe, expect, it } from 'vitest';
import {
  collectWindowsSupportContext,
  minimizeSupportContext,
  SupportObservationSchema,
} from '../src/index.ts';

const fakeToken = 'SHUN_FAKE_TOKEN_DO_NOT_EXPORT_7a9f3';
const fakeKey =
  '-----BEGIN PRIVATE KEY-----\nSHUN_FAKE_PRIVATE_KEY_24c87\n-----END PRIVATE KEY-----';
const fakePath = String.raw`C:\Users\FixtureOwner\Private\secret-document.txt`;
const unrelated = 'SHUN_UNRELATED_DOCUMENT_TEXT_29fa0';
const canaries = [fakeToken, fakeKey, fakePath, unrelated] as const;

function fixture() {
  return {
    os: { name: 'Windows', build: 'fixture-26200' },
    device: { model: 'Fixture-PC' },
    updates: { last_check: 'fixture-date' },
    env: { API_TOKEN: fakeToken, USERPROFILE: fakePath },
    processes: [{ name: 'worker.exe', command_line: fakeKey }],
    unrelated_document: unrelated,
  };
}

function expectNoCanaries(value: unknown): void {
  const serialized = JSON.stringify(value);
  for (const forbidden of canaries) {
    expect(serialized).not.toContain(forbidden);
  }
  expect(serialized).not.toContain('SHUN_FAKE_PRIVATE_KEY_24c87');
}

describe('B-040 support-context minimization', () => {
  it('keeps only required structured sections and bounded auditable redaction markers', () => {
    const result = minimizeSupportContext(fixture());

    expect(result.localOnly).toBe(true);
    expect(result.externalDisclosures).toEqual([]);
    expect(result.report).toMatchObject({
      schema: 'shun.support-context.v1',
      os: { name: 'Windows', build: 'fixture-26200' },
      device: { model: 'Fixture-PC' },
      updates: { last_check: 'fixture-date' },
    });
    expect(result.report.redactions).toEqual([
      { field: 'env[0].value', marker: '[REDACTED]' },
      { field: 'env[1].value', marker: '[REDACTED]' },
      { field: 'processes[0].name', marker: '[REDACTED]' },
      { field: 'processes[0].command_line', marker: '[REDACTED]' },
      { field: 'unrelated_document', marker: '[REDACTED]' },
    ]);
    expectNoCanaries(result);
  });

  it('redacts every allowlisted outbound string when it becomes secret/path/unrelated-shaped', () => {
    const channels = [
      ['os.name', (base: ReturnType<typeof fixture>, value: string) => (base.os.name = value)],
      ['os.build', (base: ReturnType<typeof fixture>, value: string) => (base.os.build = value)],
      [
        'device.model',
        (base: ReturnType<typeof fixture>, value: string) => (base.device.model = value),
      ],
      [
        'updates.last_check',
        (base: ReturnType<typeof fixture>, value: string) => (base.updates.last_check = value),
      ],
    ] as const;

    for (const [field, set] of channels) {
      for (const canary of canaries) {
        const input = fixture();
        set(input, canary);
        const result = minimizeSupportContext(input);
        expectNoCanaries(result);
        expect(result.report.redactions).toContainEqual({ field, marker: '[REDACTED]' });
      }
    }
  });

  it('never copies attacker-controlled env key names into redaction metadata', () => {
    const input = { ...fixture(), env: { [fakeToken]: 'ordinary-value' } };
    const result = minimizeSupportContext(input);
    expectNoCanaries(result);
    expect(result.report.redactions).toContainEqual({
      field: 'env[0].value',
      marker: '[REDACTED]',
    });
  });

  it('strictly rejects unreviewed context fields instead of silently exporting them', () => {
    expect(
      SupportObservationSchema.safeParse({
        ...fixture(),
        browser_session: { cookie: 'secret' },
      }).success,
    ).toBe(false);
  });

  it('maps direct minimizer schema failures to bounded errors without attacker-controlled names', () => {
    let caught: unknown;
    try {
      minimizeSupportContext({ ...fixture(), [fakeToken]: 'value' });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe('SUPPORT_CONTEXT_INVALID: OBSERVATION');
    expect((caught as Error).message).not.toContain(fakeToken);
  });

  it('fails closed on malformed required sections', () => {
    expect(() => minimizeSupportContext({ ...fixture(), os: { name: '', build: '' } })).toThrow();
  });
});

describe('real Windows collector boundary', () => {
  it('runs the fixed System32 PowerShell path and returns local-only structured output', async () => {
    const calls: Array<{ file: string; args: readonly string[] }> = [];
    const result = await collectWindowsSupportContext({
      execFile: async (file, args) => {
        calls.push({ file, args });
        return {
          stdout: JSON.stringify({
            os: { name: 'Microsoft Windows 11 Pro', build: '26300' },
            device: { model: 'Test-PC' },
            updates: { last_check: '2026-10-11T00:00:00.000Z' },
          }),
          stderr: '',
        };
      },
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.file).toBe(
      String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
    );
    expect(calls[0]?.args).toContain('-NonInteractive');
    expect(calls[0]?.args.join(' ')).toContain('Get-CimInstance Win32_OperatingSystem');
    expect(calls[0]?.args.join(' ')).toContain('Get-HotFix');
    expect(result.localOnly).toBe(true);
    expect(result.externalDisclosures).toEqual([]);
    expect(result.report.redactions).toEqual([]);
  });

  it('maps stderr, invalid JSON and execution failures to bounded errors with no raw canaries', async () => {
    const probes = [
      () =>
        collectWindowsSupportContext({
          execFile: async () => ({ stdout: '{}', stderr: fakeToken }),
        }),
      () =>
        collectWindowsSupportContext({
          execFile: async () => ({ stdout: fakeKey, stderr: '' }),
        }),
      () =>
        collectWindowsSupportContext({
          execFile: async () => {
            throw new Error(fakePath);
          },
        }),
    ];

    for (const probe of probes) {
      let caught: unknown;
      try {
        await probe();
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(Error);
      expect((caught as Error).message).toContain('SUPPORT_COLLECTION_FAILED');
      for (const canary of canaries) {
        expect((caught as Error).message).not.toContain(canary);
      }
    }
  });
});
