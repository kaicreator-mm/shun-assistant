import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const root = new URL('../../../../apps/control-ui/public/v03/', import.meta.url);
function source(file: string): string {
  return readFileSync(new URL(file, root), 'utf8');
}

describe('R04 source contract: the shipped desktop surface replaces technical operator panels', () => {
  it('uses the new Windows-familiar shell as the sole shipped entry', () => {
    const html = source('index.html');
    expect(html).toContain('src="./desktop.js"');
    expect(html).toContain('href="./desktop.css"');
    expect(html).toContain('id="dynamic-form"');
    expect(html).toContain('aria-label="Main navigation"');
    expect(html).not.toContain('src="./app.js"');
    expect(html).not.toContain('id="v03-j-grant"');
    expect(html).not.toContain('id="v03-j-approval"');
    expect(html).toContain('id="page-routine"');
    expect(html).toContain('id="page-assistant"');
    expect(html).toContain('id="page-approvals"');
    expect(html).toContain('id="simulation-banner"');
    expect(html).toContain('id="approval-confirm"');
    expect(html).toContain('id="host-task-list"');
    expect(html).toContain('id="host-task-detail"');
    expect(html).toContain('id="search-empty"');
    expect(html).toContain('id="search-clear"');
    expect(html).toContain('aria-keyshortcuts="Control+K"');
    expect(html).toContain('data-i18n="skipContent"');
    expect(html).toContain('id="folder-input"');
    expect(html).toContain('webkitdirectory');
    expect(html).toContain('data-aria-label="navigationLabel"');
    expect(html).toContain('data-aria-label="folderInputLabel"');
  });

  it('renders approved Host StepSpec fields without offering a raw effect/permit route', () => {
    const app = source('desktop.js');
    expect(app).toContain("import { currentStepModel, buildStepOutcome, userDecisionRelay, replayGuard }");
    expect(app).toContain("model.fields");
    expect(app).toContain("decision:'ANSWER'");
    expect(app).toContain("humanApproval:false");
    expect(app).toContain("model.kind!=='ASK'");
    expect(app).toContain("currentModel.fields.flatMap");
    expect(app).toContain("!f.required && (value==='' || value===false)");
    expect(app).toContain("addEventListener('click',()=>page('home'))");
    expect(app).toContain('/api/recipes/builtin/system-inventory');
    expect(app).toContain('/api/cloud/disclosure-preview');
    expect(app).toContain('projectRoutineExecution');
    expect(app).toContain('projectDisclosurePreview');
    expect(app).toContain('summarizeBrowserFolder');
    expect(app).toContain('guidedReceiptStatus');
    expect(app).toContain("function filterActions()");
    expect(app).toContain("'search-empty').hidden=visible!==0");
    expect(app).toContain("'search-clear').hidden=!q");
    expect(app).toContain("skipContent:'Skip to main content'");
    expect(app).toContain("skipContent:'跳转至主要内容'");
    expect(app).toContain('projectExactApproval');
    expect(app).toContain('projectApprovalDecision');
    expect(app).toContain('projectTaskSnapshots');
    expect(app).toContain('projectHostTaskDetail');
    expect(app).toContain('/api/tasks/');
    expect(app).toContain('hostTaskDetailRequest');
    expect(app).toContain("taskReconciled:'已核对'");
    expect(app).toContain("button.dataset.i18n='taskView'");
    expect(app).toContain("button.dataset.i18n='approvalSelect'");
    expect(app).toContain('if(approvalSelected)renderApprovalPreview(approvalSelected)');
    expect(app).toContain("healthStatus?.simulated===true");
    expect(app).toContain("realApprovalPosture(healthStatus)!=='REAL'");
    expect(app).toContain('const trustedTitle=stepText(model.titleKey)');
    expect(app).toContain('const trustedLabel=stepText(field.labelKey)');
    expect(app).toContain('unresolvedStepId===model.stepId');
    expect(app).not.toContain('/api/cloud/interpret');
    expect(app).not.toContain('/api/v03/gateway/submit');
    expect(app).not.toContain('/api/v03/effect/submit');
    expect(app).not.toContain('/api/v03/provider/first-use');
    expect(app).not.toContain('/api/v03/meta/feedback');
    expect(app).not.toContain('new AuthorizedAction');
  });

  it('exposes only real local read-only checks and obvious keyboard focus', () => {
    const app = source('desktop.js');
    const css = source('desktop.css');
    expect(app).toContain('/api/system/inventory');
    expect(app).toContain('/api/system/diagnosis');
    expect(app).toContain("event.key.toLowerCase()==='k'");
    expect(css).toContain(':focus-visible');
    expect(css).toContain('prefers-reduced-motion');
    expect(css).toContain('[hidden]');
  });

  it('keeps user-facing copy in both languages, not internal authorization identifiers', () => {
    const app = source('desktop.js');
    for (const label of ["heroTitle:", "actionInventory:", "actionDiagnosis:", "scopeTitle:", "notAnApproval:"]) {
      expect(app.split(label).length).toBeGreaterThan(2);
    }
    const html = source('index.html');
    expect(html).not.toMatch(/(planRef|grantRef|approvalRef|currentnessRef|effectPermit)/);
  });
});
