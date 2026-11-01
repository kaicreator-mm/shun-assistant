import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const base = new URL('../../../../apps/control-ui/public/v03/', import.meta.url);
const source = (name: string): string => readFileSync(new URL(name, base), 'utf8');
const js = source('desktop.js');
const html = source('index.html');

describe('R04 shipped desktop bootstrap wiring', () => {
  it('every literal DOM lookup has exactly one matching HTML element', () => {
    const ids = [...html.matchAll(/\\bid="([^"]+)"/g)].map((match) => match[1]);
    expect(new Set(ids).size).toBe(ids.length);
    const lookups = [...js.matchAll(/\\$\\('([^']+)'\\)/g)].map((match) => match[1]);
    expect(lookups.length).toBeGreaterThan(30);
    for (const id of lookups) expect(ids).toContain(id);
  });

  it('the boot module imports only modules that actually ship with the UI', () => {
    const relative = [...js.matchAll(/from '\\.\\/([^']+)'/g)].map((match) => match[1]);
    expect(relative.length).toBeGreaterThan(3);
    for (const path of relative) {
      expect(path).not.toContain('..');
      expect(existsSync(new URL(path, base))).toBe(true);
    }
    expect(html).toContain('src="./desktop.js"');
  });

  it('all shipped labels and accessibility attributes exist in BOTH UI locales', () => {
    const en = js.slice(js.indexOf('\\n en: {'), js.indexOf('\\n },\\n zh: {'));
    const zh = js.slice(js.indexOf('\\n zh: {'), js.indexOf('\\n }\\n};\\nconst storage'));
    const keys = (value: string): Set<string> =>
      new Set([...value.matchAll(/(?:^|[,\\n{]\\s*)([a-zA-Z][a-zA-Z0-9]*):'/g)]
        .map((match) => match[1] as string));
    const english = keys(en);
    const chinese = keys(zh);
    expect(english.size).toBeGreaterThan(200);
    expect([...english].sort()).toEqual([...chinese].sort());
    for (const match of html.matchAll(/data-(?:i18n|placeholder|aria-label)="([^"]+)"/g)) {
      expect(english.has(match[1] as string)).toBe(true);
      expect(chinese.has(match[1] as string)).toBe(true);
    }
  });

  it('an unresolved decision blocks ALL later approvals, not just the same plan', () => {
    expect(js).toContain('if(approvalUnresolvedId)return;');
    expect(js).toContain('if(approvalUnresolvedId){');
    expect(js).toContain('approvalBusy||!!approvalUnresolvedId;');
    expect(js).not.toContain('approvalUnresolvedId===approvalSelected.id');
    expect(js).toContain("if(!persistUncertainApproval(selected.id))");
    expect(js).toContain("sessionStorage.setItem('shun-r04-approval-uncertain',id)");
  });
});
