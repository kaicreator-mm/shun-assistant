import { describe, expect, it } from 'vitest';
describe('R02-D2 mandatory nested CI discovery', () => {
  it('fails deliberately when the CI fault injection is requested', () => {
    expect(process.env.SHUN_R02_FAULT_INJECT_NESTED).not.toBe('1');
  });
});
