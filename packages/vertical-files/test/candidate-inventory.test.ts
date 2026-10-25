import { describe, expect, it } from 'vitest';
import { reportDuplicateCandidates } from '../src/candidate-inventory.ts';

const root = 'C:\\Approved\\Jobs';

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
      expect(reportDuplicateCandidates({
        scopeRoot: root,
        files: [{ relativePath, sizeBytes: 12 }],
      })).toEqual({ ok: false, code: 'FILE_CANDIDATES_REFUSED' });
    }
    expect(reportDuplicateCandidates({
      scopeRoot: root,
      files: [
        { relativePath: 'File.txt', sizeBytes: 1 },
        { relativePath: 'file.TXT', sizeBytes: 2 },
      ],
    }).ok).toBe(false);
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
    for (const file of bad) {
      expect(reportDuplicateCandidates({ scopeRoot: root, files: [file] }).ok).toBe(false);
    }
    expect(reportDuplicateCandidates({ scopeRoot: root, files: [], grant: true }).ok).toBe(false);
    expect(reportDuplicateCandidates({
      scopeRoot: root,
      files: Array.from({ length: 4097 }, (_, i) => ({
        relativePath: String(i) + '.txt', sizeBytes: i,
      })),
    }).ok).toBe(false);
    expect(reportDuplicateCandidates({
      scopeRoot: root,
      get files() { throw new Error('SECRET'); },
    })).toEqual({ ok: false, code: 'FILE_CANDIDATES_REFUSED' });
  });
});
