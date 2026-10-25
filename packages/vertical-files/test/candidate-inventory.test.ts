import { describe, expect, it } from 'vitest';
import { reportDuplicateCandidates } from '../src/candidate-inventory.ts';

const root = 'C:\\Approved\\Jobs';

function refused(input: unknown): void {
  expect(reportDuplicateCandidates(input)).toEqual({ ok: false, code: 'FILE_CANDIDATES_REFUSED' });
}

describe('T07 F02A metadata-only duplicate candidates', () => {
  it('groups only same-size candidates without claiming content or filesystem proof', () => {
    const result = reportDuplicateCandidates({
      scopeRoot: root,
      files: [
        { relativePath: 'other\\three.bin', sizeBytes: 4 },
        { relativePath: 'one.bin', sizeBytes: 4 },
        { relativePath: 'two.bin', sizeBytes: 9 },
      ],
    });
    expect(result).toMatchObject({
      ok: true,
      report: {
        status: 'REPORTED_METADATA_ONLY',
        trust: 'UNVERIFIED_INPUT',
        fileCount: 3,
        sameSizeCandidates: [{ sizeBytes: 4, relativePaths: ['one.bin', 'other\\three.bin'] }],
        filesystemObserved: false,
        duplicatesVerified: false,
        executionAuthorized: false,
        cloudDisclosure: false,
      },
    });
    if (!result.ok) return;
    expect(result.report.inputDigestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.report.pendingTrustedChecks).toContain('CONTENT_DIGEST_FROM_VERIFIED_HANDLES');
  });

  it('normalizes order, but digest is not a trusted content hash', () => {
    const files = [
      { relativePath: 'b.txt', sizeBytes: 7 },
      { relativePath: 'a.txt', sizeBytes: 7 },
    ];
    const left = reportDuplicateCandidates({ scopeRoot: root, files });
    const right = reportDuplicateCandidates({ scopeRoot: root, files: [...files].reverse() });
    expect(left).toEqual(right);
    expect(left.ok).toBe(true);
    if (left.ok) expect(left.report.duplicatesVerified).toBe(false);
  });

  it('refuses traversal, drive paths, UNC, DOS devices, Unicode alias and case collisions', () => {
    const forbidden = [
      '..\\outside.txt',
      '.\\inside.txt',
      'D:\\outside.txt',
      '\\\\host\\share\\x.txt',
      'folder\\CON.txt',
      'folder\\COM¹.txt',
      'folder\\trailing.\\child.txt',
      'folder\\rtl\u202esecret.txt',
      'folder\\\\child.txt',
    ];
    for (const relativePath of forbidden) {
      refused({ scopeRoot: root, files: [{ relativePath, sizeBytes: 12 }] });
    }
    refused({
      scopeRoot: root,
      files: [
        { relativePath: 'File.txt', sizeBytes: 1 },
        { relativePath: 'file.TXT', sizeBytes: 2 },
      ],
    });
  });

  it('refuses extra authority fields, getters, invalid sizes and excessive inventory', () => {
    const standard = { relativePath: 'a.txt', sizeBytes: 1 };
    const bad = [
      { ...standard, execute: true },
      { ...standard, sizeBytes: -1 },
      { ...standard, sizeBytes: Number.MAX_SAFE_INTEGER + 1 },
      { ...standard, sizeBytes: NaN },
      { ...standard, relativePath: 'x'.repeat(1100) },
    ];
    for (const file of bad) refused({ scopeRoot: root, files: [file] });

    refused({ scopeRoot: root, files: [], grant: true });
    refused({
      scopeRoot: root,
      files: Array.from({ length: 4097 }, (_, i) => ({
        relativePath: i.toString(),
        sizeBytes: i,
      })),
    });
    refused({
      scopeRoot: root,
      get files() {
        throw new Error('SECRET');
      },
    });
  });

  it('refuses own Symbol.iterator even if it yields over 4096 rows from length one', () => {
    const files = [{ relativePath: 'seed.txt', sizeBytes: 1 }];
    let invoked = false;
    Object.defineProperty(files, Symbol.iterator, {
      value: function* () {
        invoked = true;
        for (let i = 0; i < 4097; i++) {
          yield { relativePath: String(i), sizeBytes: i };
        }
      },
    });
    refused({ scopeRoot: root, files });
    expect(invoked).toBe(false);
  });

  it('refuses holes, getters, unexpected keys and proxied arrays or metadata', () => {
    const holes = new Array(1);
    refused({ scopeRoot: root, files: holes });
    const accessors = [{ relativePath: 'a.txt', sizeBytes: 1 }];
    Object.defineProperty(accessors, '0', {
      get() {
        throw new Error('NEVER_READ_UNTRUSTED_GETTER');
      },
    });
    refused({ scopeRoot: root, files: accessors });
    const extraKey = [{ relativePath: 'a.txt', sizeBytes: 1 }] as object[] & {
      unexpected?: boolean;
    };
    extraKey.unexpected = true;
    refused({ scopeRoot: root, files: extraKey });
    const original = [{ relativePath: 'a.txt', sizeBytes: 1 }];
    refused({ scopeRoot: root, files: new Proxy(original, {}) });
    refused({
      scopeRoot: root,
      files: [new Proxy({ relativePath: 'a.txt', sizeBytes: 1 }, {})],
    });
  });

  it('does not let callers corrupt subsequent reports or verified-state flags', () => {
    const input = {
      scopeRoot: root,
      files: [
        { relativePath: 'a.txt', sizeBytes: 3 },
        { relativePath: 'b.txt', sizeBytes: 3 },
      ],
    };
    const result = reportDuplicateCandidates(input);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(Object.isFrozen(result.report)).toBe(true);
    expect(Object.isFrozen(result.report.pendingTrustedChecks)).toBe(true);
    expect(Object.isFrozen(result.report.sameSizeCandidates)).toBe(true);
    expect(Object.isFrozen(result.report.sameSizeCandidates[0])).toBe(true);
    expect(Object.isFrozen(result.report.sameSizeCandidates[0]?.relativePaths)).toBe(true);
    expect(() => {
      (result.report as { duplicatesVerified: boolean }).duplicatesVerified = true;
    }).toThrow();
    expect(() => {
      (result.report.pendingTrustedChecks as unknown as string[]).splice(0, 1);
    }).toThrow();
    const next = reportDuplicateCandidates(input);
    expect(next).toEqual(result);
    if (next.ok) expect(next.report.duplicatesVerified).toBe(false);
  });
});
