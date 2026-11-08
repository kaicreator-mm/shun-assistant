import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
const html=readFileSync(new URL('../public/v03/index.html',import.meta.url),'utf8');
const ui=readFileSync(new URL('../public/v03/desktop.js',import.meta.url),'utf8');
describe('R04 real desktop selected-root effect',()=>{
 it('loads actual desktop.js, not unused app.js',()=>{
  expect(html).toContain('src="./desktop.js"');
  expect(html).not.toContain('src="./app.js"');
 });
 it('connects metadata observation to explicit Host plan staging',()=>{
  expect(ui).toContain("request('/api/v03/guided/folder-observation')");
  expect(ui).toContain("request('/api/v03/guided/plan-preview',{method:'POST'");
  expect(ui).toContain("staged?.status!=='STAGED'");
 });
 it('requires current exact Host proposal and explicit checked approval',()=>{
  expect(ui).toContain("request('/api/v03/effect/proposal')");
  expect(ui).toContain("rootProposal?.identity===rootIdentity(currentModel)");
  expect(ui).toContain("!$('root-confirm')?.checked");
  expect(ui).toContain("checkbox.addEventListener('change',syncRootReview)");
 });
 it('effect is a separate button, one attempt only, no fabricated completed outcome',()=>{
  expect(html).toContain('id="root-effect-panel"');
  expect(ui).toContain("$('root-effect-run').addEventListener('click'");
  expect(ui).toContain('rootSent=true');
  expect(ui).toContain("status==='ADMITTED'?'admitted'");
  expect(ui).toContain("status==='REFUSED'?'refused'");
  expect(ui).toContain("rootWord(e?.receipt?.status==='REFUSED'?'refused':'unknown')");
 });
 it('effect HTTP only receives Host-issued references, never plan/grant/permit',()=>{
  const i=ui.indexOf('async function sendRootEffect()');
  const j=ui.indexOf('function renderGuided()',i);
  expect(i).toBeGreaterThan(0);expect(j).toBeGreaterThan(i);
  const flow=ui.slice(i,j);
  expect(flow).toContain('caseId:rootApproved.caseId,currentnessRef,approvalRef');
  expect(flow).not.toContain('grantRef');expect(flow).not.toContain('planHash');
  expect(flow).not.toContain('permit');expect(flow).not.toContain('absolutePath');
 });
});