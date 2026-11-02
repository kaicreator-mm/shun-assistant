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
    expect(html).toContain('id="step-progress"');
    expect(html).toContain('aria-label="Main navigation"');
    expect(html).toContain('aria-controls="navigation"');
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
    const taskPage=html.slice(html.indexOf('id="page-tasks"'),html.indexOf('id="page-approvals"'));
    const historyPage=html.slice(html.indexOf('id="page-history"'),html.indexOf('id="page-settings"'));
    expect(taskPage).toContain('id="host-task-detail"');
    expect(taskPage.indexOf('id="host-task-detail"')).toBeLessThan(taskPage.indexOf('id="host-task-list"'));
    expect(taskPage).toContain('tabindex="-1"');
    expect(taskPage).toContain('id="host-task-refresh"');
    expect(taskPage).toContain('id="host-task-filter"');
    expect(taskPage).toContain('id="host-task-count"');
    expect(historyPage).not.toContain('id="host-task-detail"');
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
    expect(app).toContain('approvalDetailGeneration');
    expect(app).toContain('approvalInboxGeneration');
    expect(app).toContain('if(approvalUnresolvedId)return;');
    expect(app).toContain('if(approvalUnresolvedId){');
    expect(app).toContain('approvalBusy||!!approvalUnresolvedId;');
    expect(app).not.toContain('if(approvalUnresolvedId===approvalSelected.id)return;');
    expect(app).toContain('if(generation!==approvalDetailGeneration)return');
    expect(app).toContain("sessionStorage.setItem('shun-r04-approval-uncertain',id)");
    expect(app).toContain('if(!persistUncertainApproval(selected.id))');
    expect(app).toContain('mayHaveSent=true');
    expect(app).toContain("const technical=document.createElement('details')");
    expect(app).not.toContain("desc.textContent=item.riskClass+' · '+item.taskId");
    expect(app).toContain('projectApprovalDecision');
    expect(app).toContain('projectTaskSnapshots');
    expect(app).toContain('filterTaskSnapshots(hostTaskRows');
    expect(app).toContain("$('host-task-filter').addEventListener('change',()=>{");
    expect(app).toContain('projectHostTaskDetail');
    expect(app).toContain("timeline.className='task-progress-timeline'");
    expect(app).toContain("label.textContent=tr('taskProgressTitle')");
    expect(app).toContain("if(view.state==='AWAITING_AUTHORIZATION')");
    expect(app).toContain("link.addEventListener('click',()=>page('approvals'))");
    expect(app).toContain("taskOpenApprovals:'查看待审批事项'");
    expect(app).toContain('projectClarificationReceipt');
    expect(app).toContain('async function submitHostClarification(id,key,value)');
    expect(app).toContain('selected.revision,selected.updatedAt');
    expect(app).toContain('latest.revision,latest.updatedAt');
    expect(app).toContain('if(confirmed&&requestToken===hostTaskDetailRequest');
    expect(app).not.toContain('await loadHostTaskDetail(id);');
    expect(app).toContain("$('host-task-refresh').addEventListener");
    expect(app).toContain('if(!persistUncertainClarification(id))');
    expect(app).toContain("sessionStorage.setItem('shun-r04-clarification-uncertain',id)");
    expect(app).toContain("'/clarification'");
    expect(app).not.toContain("'/api/tasks/'+encodeURIComponent(id)+'/retry'");
    expect(app).toContain('projectGuidedHistory(lastState?.history)');
    expect(app).toContain('let guidedRefreshGeneration = 0;');
    expect(app).toContain('if(generation!==guidedRefreshGeneration)return');
    expect(app).toContain('progressModel(lastState?.journey,locale)');
    expect(app).toContain("model.kind!=='ASK'||!progressReady");
    expect(app).toContain('unresolvedStepId=submittedStepId');
    expect(app).toContain('let hostTaskListGeneration = 0;');
    expect(app).toContain("labeledRow(target,'taskStatus',tr('taskState'+view.state))");
    expect(app).toContain("taskStateSUCCEEDED:'Marked complete'");
    expect(app).toContain("taskStateSUCCEEDED:'已标记完成'");
    expect(app).toContain('if(generation!==hostTaskListGeneration)return');
    expect(app).toContain("function showError() { notify(tr('unknown')); }");
    expect(app).not.toContain('error instanceof Error ? error.message');
    expect(app).toContain('/api/tasks/');
    expect(app).toContain('hostTaskDetailRequest');
    expect(app).toContain('let hostTaskSelectedId = null;');
    expect(app).toContain("hostTaskDetail={status:'LOADING',id};");
    expect(app).toContain("if(focusDetail)$('host-task-detail').focus({preventScroll:false})");
    expect(app).toContain("button.setAttribute('aria-controls','host-task-detail')");
    expect(app).toContain("button.setAttribute('aria-expanded',String(selected))");
    expect(app).toContain("loadHostTaskDetail(item.id,true)");
    expect(app).toContain("hostTaskSelectedId=null;hostTaskDetail=null;renderHostTaskDetail();");
    expect(app).toContain("taskDetailLoading:'正在打开所选任务……'");
    expect(app).toContain('function guidedIdentity(model)');
    expect(app).toContain('const previousAnswers=previousModel?formAnswers():[]');
    expect(app).toContain('guidedIdentity(previousModel)===guidedIdentity(model)');
    expect(app).toContain("if(visible.length!==1)return");
    expect(app).toContain("if(event.key!=='Enter'||event.isComposing)return");
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
    expect(app).toContain("if(shell.classList.contains('menu-open'))");
    expect(app).toContain("$('menu-toggle').focus()");
    expect(css).toContain(':focus-visible');
    expect(css).toContain('prefers-reduced-motion');
    expect(css).toContain('.history-entry.host-task-selected');
    expect(css).toContain('[hidden]');
  });

  it('fences stale disclosures and local checks, with visible keyboard textarea focus', () => {
    const app = source('desktop.js');
    const css = source('desktop.css');
    expect(app).toContain('let aiPreviewGeneration = 0;');
    expect(app).toContain('let computerCheckGeneration = 0;');
    expect(app).toContain("if(generation!==aiPreviewGeneration||goal!==$('ai-goal').value)return");
    expect(app).toContain('if(token!==computerCheckGeneration)return');
    expect(app).toContain("++aiPreviewGeneration;$('ai-preview').disabled=false");
    expect(css).toContain('textarea:focus-visible');
  });

  it('keeps user-facing copy in both languages, not internal authorization identifiers', () => {
    const app = source('desktop.js');
    for (const label of ["heroTitle:", "actionInventory:", "actionDiagnosis:", "scopeTitle:", "notAnApproval:"]) {
      expect(app.split(label).length).toBeGreaterThan(2);
    }
    const html = source('index.html');
    expect(html).not.toMatch(/\b(?:planRef|grantRef|approvalRef|currentnessRef|effectPermit)\b/);
  });

  it('uses plain Windows-user language and states the real folder-preview boundary', () => {
    const app = source('desktop.js');
    const html = source('index.html');
    expect(app).toContain("actionFolder:'Preview a folder'");
    expect(app).toContain("actionFolder:'预览文件夹'");
    expect(app).toContain("taskStateEXECUTING:'In progress'");
    expect(app).toContain("taskStateEXECUTING:'进行中'");
    expect(app).toContain("safetyConfirm:'A verified, file-by-file change plan is not available yet.'");
    expect(app).toContain("safetyConfirm:'当前版本尚不支持经过核验的逐文件修改计划。'");
    expect(app).toContain("folderHint:'Local preview only: folder name, item count and total size.");
    expect(app).toContain("folderHint:'仅在本机预览文件夹名称、项目数量和总大小");
    expect(app).not.toMatch(/:\s*'[^']*\bHost\b[^']*'/i);
    expect(html).toContain('What is available in this version');
    expect(html).toContain('This preview does not read or change any files.');
    expect(html).not.toContain('review a plan and decide what happens');
  });

});
