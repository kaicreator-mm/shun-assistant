import { describe, expect, it } from 'vitest';
import {
  collectWindowsSupportContext,
  minimizeSupportContext,
  SupportObservationSchema,
} from '../src/index.ts';

const fakeToken = 'SHUN_FAKE_TOKEN_DO_NOT_EXPORT_7a9f3';
const fakeKey = '-----BEGIN PRIVATE KEY-----\nSHUN_FAKE_PRIVATE_KEY_24c87\n-----END PRIVATE KEY-----';
const fakePath = String.raw`C:\Users\FixtureOwner\Private\secret-document.txt`;
const unrelated = 'SHUN_UNRELATED_DOCUMENT_TEXT_29fa0';

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

describe('B-040 support-context minimization', () => {
  it('keeps only required structured sections and auditable redaction markers', () => {
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
      { field: 'env.API_TOKEN', marker: '[REDACTED]' },
      { field: 'env.USERPROFILE', marker: '[REDACTED]' },
      { field: 'processes[0].name', marker: '[REDACTED]' },
      { field: 'processes[0].command_line', marker: '[REDACTED]' },
      { field: 'unrelated_document', marker: '[REDACTED]' },
    ]);

    const serialized = JSON.stringify(result);
    for (const forbidden of [fakeToken, fakeKey, fakePath, unrelated, 'SHUN_FAKE_PRIVATE_KEY_24c87']) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it('strictly rejects unreviewed context fields instead of silently exporting them', () => {
    expect(
      SupportObservationSchema.safeParse({
        ...fixture(),
        browser_session: { cookie: 'secret' },
      }).success,
    ).toBe(false);
  });

  it('fails closed on malformed required sections', () => {
    expect(() => minimizeSupportContext({ ...fixture(), os: { name: '', build: '' } })).toThrow();
  });
});

describe('real Windows collector boundary', () => {
  it('runs a fixed local PowerShell shape and returns local-only structured output', async () => {
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
    expect(calls[0]?.file).toBe('powershell.exe');
    expect(calls[0]?.args).toContain('-NonInteractive');
    expect(calls[0]?.args.join(' ')).toContain('Get-CimInstance Win32_OperatingSystem');
    expect(calls[0]?.args.join(' ')).toContain('Get-HotFix');
    expect(result.localOnly).toBe(true);
    expect(result.externalDisclosures).toEqual([]);
    expect(result.report.redactions).toEqual([]);
  });

  it('refuses stderr and malformed collector output rather than degrading to partial success', async () => {
    await expect(
      collectWindowsSupportContext({
        execFile: async () => ({ stdout: '{}', stderr: 'access denied' }),
      }),
    ).rejects.toThrow('SUPPORT_COLLECTION_FAILED');

    await expect(
      collectWindowsSupportContext({
        execFile: async () => ({ stdout: 'not-json', stderr: '' }),
      }),
    ).rejects.toThrow('SUPPORT_COLLECTION_FAILED');
  });
});
