import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const html = readFileSync(new URL('../public/v03/index.html', import.meta.url), 'utf8');
const ui = readFileSync(new URL('../public/v03/desktop.js', import.meta.url), 'utf8');

describe('R04 real desktop selected-root effect', () => {
  it('loads actual desktop.js, not unused app.js', () => {
    expect(html).toContain('src="./desktop.js"');
    expect(html).not.toContain('src="./app.js"');
  });

  it('connects metadata observation to explicit Host plan staging', () => {
    expect(ui).toContain("request('/api/v03/guided/folder-observation')");
    expect(ui).toContain("request('/api/v03/guided/plan-preview',{method:'POST'");
    expect(ui).toContain("staged?.status!=='STAGED'");
  });

  it('requires current exact Host proposal and explicit checked approval', () => {
    expect(ui).toContain("request('/api/v03/effect/proposal')");
    expect(ui).toContain('rootProposal?.identity===rootIdentity(currentModel)');
    // The confirmation checkbox is rendered per review step; the module-held
    // live reference keeps the explicit checked-approval gate without a
    // literal DOM lookup that the shipped HTML contract cannot satisfy.
    expect(ui).toContain('!rootConfirmBox?.checked');
    expect(ui).toContain('rootConfirmBox=checkbox');
    expect(ui).toContain("checkbox.addEventListener('change',syncRootReview)");
  });
  it('the APPROVE gate requires the approval continuation choice — never the blank or the back-semantics option', () => {
    // Final-audit P1: a `return-to-edit` selection plus the checked
    // confirmation used to still mint the APPROVE terminal (the backend
    // accepts any eligible option id). The desktop gate now refuses to
    // submit APPROVE unless the required continue CHOICE explicitly carries
    // the approval continuation, and the submit button stays disabled until
    // that intent is chosen.
    expect(ui).toContain('function rootApprovalIntentChosen(){');
    expect(ui).toContain("a.fieldId==='continue'&&a.value==='continue-to-independent-approval'");
    expect(ui).toContain('!rootApprovalIntentChosen()||!rootConfirmBox?.checked');
    expect(ui).toContain(
      '!rootReviewReady()||!rootApprovalIntentChosen()||!checkbox?.checked||busy',
    );
    expect(ui).toContain("select.addEventListener('change',syncRootReview)");
  });

  it('effect is a separate button, one attempt only, no fabricated completed outcome', () => {
    expect(html).toContain('id="root-effect-panel"');
    expect(ui).toContain("$('root-effect-run').addEventListener('click'");
    expect(ui).toContain('rootSent=true');
    expect(ui).toContain("status==='ADMITTED'?'admitted'");
    expect(ui).toContain("status==='REFUSED'?'refused'");
    expect(ui).toContain("rootWord(e?.receipt?.status==='REFUSED'?'refused':'unknown')");
  });

  it('U06 (#401): no manual reference copy anywhere — the panel has no reference inputs and the locale catalogs carry no reference labels', () => {
    expect(html).not.toContain('root-currentness-ref');
    expect(html).not.toContain('root-approval-ref');
    expect(html).not.toContain('root-currentness-label');
    expect(html).not.toContain('root-approval-label');
    // The shipped static copy must not direct the user to any console.
    expect(html).not.toMatch(/\breference\b/i);
    expect(ui).not.toContain('root-currentness-ref');
    expect(ui).not.toContain('root-approval-ref');
    expect(ui).not.toContain("currentness:'");
    expect(ui).not.toContain("approval:'");
    expect(ui).not.toMatch(/shun\.(currentness|approval)\.v1/);
    expect(ui).not.toContain('local service console');
    expect(ui).not.toContain('控制台');
  });

  it('effect HTTP carries the Case identity only — never references, plan/grant/permit or paths', () => {
    const i = ui.indexOf('async function sendRootEffect()');
    const j = ui.indexOf('const $ = id =>', i);
    expect(i).toBeGreaterThan(0);
    expect(j).toBeGreaterThan(i);
    const flow = ui.slice(i, j);
    expect(flow).toContain('caseId:rootApproved.caseId}');
    expect(flow).not.toContain('currentnessRef');
    expect(flow).not.toContain('approvalRef');
    expect(flow).not.toContain('grantRef');
    expect(flow).not.toContain('planHash');
    expect(flow).not.toContain('permit');
    expect(flow).not.toContain('absolutePath');
  });

  it('every literal DOM lookup matches a shipped HTML element (CI #664/#665 regression fence)', () => {
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
    expect(new Set(ids).size).toBe(ids.length);
    const lookups = [...ui.matchAll(/\$\('([^']+)'\)/g)].map((match) => match[1]);
    for (const id of lookups) expect(ids).toContain(id);
  });

  it('user-visible string values never contain the technical term Host (CI #664/#665 regression fence)', () => {
    expect(ui).not.toMatch(/:\s*'[^']*\bHost\b[^']*'/i);
  });
});
