import { describe, expect, it } from 'vitest';
import { progressModel } from '../../../../apps/control-ui/public/v03/view-model.js';

describe('R04 exact Host guided progress', () => {
  it('shows trusted step position in both locales', () => {
    for (const locale of ['en', 'zh']) {
      const result = progressModel({position:1,total:3,paused:false},locale);
      expect(result).toMatchObject({ok:true,status:'RUNNING',position:{known:true}});
      expect(result.position.text).toContain('1');
      expect(result.position.text).toContain('3');
      expect(result.position.text).not.toContain('stepId');
    }
  });
  it('never shows Host-paused steps as running', () => {
    for (const locale of ['en', 'zh']) {
      const result = progressModel({position:1,total:1,paused:true},locale);
      expect(result).toMatchObject({ok:true,status:'PAUSED',position:{known:true}});
      expect(result.pausedReason.length).toBeGreaterThan(0);
    }
  });
  it('refuses to guess unknown progress or missing Host journey state', () => {
    for (const locale of ['en', 'zh']) {
      expect(progressModel({position:2,total:1,paused:false},locale).status).toBe('UNKNOWN');
      expect(progressModel(undefined,locale).status).toBe('UNKNOWN');
    }
  });
});
