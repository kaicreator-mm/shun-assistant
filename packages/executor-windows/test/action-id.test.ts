// Unit coverage for the caller-controlled actionId path-safety gate (review
// finding: contracts only floor actionId at z.string().min(1), and both
// backends splice it into run-directory names — `..\`-shaped ids could point
// launcher artifacts outside the workspace). Pure checks; the e2e refusals
// live in backend.test.ts / privileged-helper.test.ts.
import { describe, expect, it } from 'vitest';
import { ACTION_ID_PATTERN, ActionIdRefusedError, assertSafeActionId } from '../src/action-id.ts';

describe('assertSafeActionId (path-free identifier gate)', () => {
  it('accepts the plan/issue-shaped identifiers the authority mints', () => {
    expect(() => assertSafeActionId('act-9f2c1a0b')).not.toThrow();
    expect(() => assertSafeActionId('Act_2026.10-i15')).not.toThrow();
    expect(() => assertSafeActionId('a')).not.toThrow();
    expect(ACTION_ID_PATTERN.test('act-9f2c1a0b')).toBe(true);
  });

  it('rejects path separators and traversal shapes', () => {
    for (const evil of [
      '..\\..\\pwned',
      '../escape',
      'sub/dir',
      'sub\\dir',
      'act../../x',
      '..',
      '.',
    ]) {
      expect(() => assertSafeActionId(evil)).toThrow(ActionIdRefusedError);
    }
  });

  it('rejects drive/ADS specifiers, NTFS-illegal characters and control characters', () => {
    for (const evil of ['C:\\abs', 'C:drive', 'a:b', 'a<b', 'a>b', 'a"b', 'a|b', 'a?b', 'a*b']) {
      expect(() => assertSafeActionId(evil)).toThrow(ActionIdRefusedError);
    }
    expect(() => assertSafeActionId('act\u0000id')).toThrow(ActionIdRefusedError);
    expect(() => assertSafeActionId('act\nid')).toThrow(ActionIdRefusedError);
  });

  it('rejects empty and over-long ids with the typed refusal', () => {
    expect(() => assertSafeActionId('')).toThrow(ActionIdRefusedError);
    expect(() => assertSafeActionId('x'.repeat(129))).toThrow(ActionIdRefusedError);
    try {
      assertSafeActionId('..\\pwned');
      throw new Error('expected ActionIdRefusedError');
    } catch (e) {
      expect(e).toBeInstanceOf(ActionIdRefusedError);
      expect((e as ActionIdRefusedError).code).toBe('ACTION_ID_REFUSED');
      expect((e as ActionIdRefusedError).actionId).toBe('..\\pwned');
    }
  });
});
