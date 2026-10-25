import { describe, expect, it } from 'vitest';
import { describeUntrustedMutationRecovery } from '../src/recovery-disposition.ts';

describe('T07 F04A advisory-only interrupted file mutation classification', () => {
  it('never lets any reported journal state authorize mutation, retry or completion', () => {
    const cases = [
      ['ABSENT', 'TRUSTED_JOURNAL_READ'],
      ['STARTED', 'RECONCILE_JOURNAL_AND_POSTSTATE'],
      ['UNCERTAIN', 'RECONCILE_JOURNAL_AND_POSTSTATE'],
      ['OBSERVED_NOT_VERIFIED', 'INDEPENDENT_POSTSTATE_AND_RECEIPT_VERIFICATION'],
      ['COMPLETED_CLAIMED', 'INDEPENDENT_POSTSTATE_AND_RECEIPT_VERIFICATION'],
    ] as const;
    for (const [journalState, requiredNextStep] of cases) {
      const result = describeUntrustedMutationRecovery({ journalState });
      expect(result).toMatchObject({
        ok: true,
        disposition: {
          source: 'CALLER_REPORTED_UNTRUSTED',
          requiredNextStep,
          journalTrusted: false,
          semanticVerified: false,
          automaticRetryAllowed: false,
          fileMutationAllowed: false,
          completedEffectProven: false,
        },
      });
      if (!result.ok) continue;
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.isFrozen(result.disposition)).toBe(true);
      expect(() => {
        (result.disposition as { automaticRetryAllowed: boolean }).automaticRetryAllowed = true;
      }).toThrow();
    }
  });

  it('refuses fabricated positive evidence, unexpected keys and unsupported states', () => {
    for (const input of [
      {},
      [],
      null,
      undefined,
      'STARTED',
      { journalState: 'SAFE_TO_RETRY' },
      { journalState: 'COMPLETED_VERIFIED', postStateVerified: true },
      { journalState: 'ABSENT', noExecutionProven: true },
      { journalState: 'STARTED', allowReplay: true },
      { journalState: 'UNCERTAIN', grant: 'approved' },
    ]) {
      expect(describeUntrustedMutationRecovery(input)).toEqual({
        ok: false,
        code: 'FILE_RECOVERY_RECORD_REFUSED',
      });
    }
  });

  it('refuses getters, symbols, proxies, and exotic records without calling them', () => {
    let getterCalled = false;
    const getter: Record<string, unknown> = {};
    Object.defineProperty(getter, 'journalState', {
      enumerable: true,
      get() {
        getterCalled = true;
        return 'ABSENT';
      },
    });
    const symbolKey = { journalState: 'ABSENT', [Symbol('authority')]: true };
    const proxy = new Proxy({ journalState: 'ABSENT' }, {
      get() {
        throw new Error('untrusted proxy trap');
      },
    });
    for (const input of [getter, symbolKey, proxy, new Date(), new String('STARTED')]) {
      expect(describeUntrustedMutationRecovery(input)).toEqual({
        ok: false,
        code: 'FILE_RECOVERY_RECORD_REFUSED',
      });
    }
    expect(getterCalled).toBe(false);
  });

  it('produces repeatable advisory classifications without OS or journal claims', () => {
    const input = Object.create(null) as Record<string, unknown>;
    input.journalState = 'UNCERTAIN';
    const first = describeUntrustedMutationRecovery(input);
    expect(first).toEqual(describeUntrustedMutationRecovery(input));
    expect(first).toMatchObject({
      ok: true,
      disposition: {
        schema: 'shun.files.mutation-recovery-advisory.v02',
        requiredNextStep: 'RECONCILE_JOURNAL_AND_POSTSTATE',
        completedEffectProven: false,
      },
    });
  });
});
