/**
 * Shun R04 desktop surface. Pure same-origin client:
 * no grant, permit, approval, provider or raw command is created here.
 * Fields are rendered ONLY from the trusted, allowlisted StepSpec projection.
 */
import { t as approvedText } from './strings.js';
import { projectLocalObservation, projectRoutineState, projectRoutineExecution, projectDisclosurePreview } from './desktop-observations.js';
import { currentStepModel, buildStepOutcome, userDecisionRelay, replayGuard } from './view-model.js';

const words = {
 en: {
  brandSub:'Your Windows companion',navHome:'Home',navTasks:'My tasks',navAssistant:'AI request preview',navComputer:'My computer',navRoutine:'Saved routines',navHistory:'History',navSettings:'Settings',
  localOnly:'Runs on your computer',welcome:'WELCOME BACK',heroTitle:'What would you like to do?',heroDesc:'Choose a familiar task. Shun will guide you through the details.',searchLabel:'Find a task',searchPlaceholder:'Find an action…',quickTitle:'Quick actions',quickDesc:'Start safely; nothing changes without your approval.',
  actionAssistant:'Plan with AI',actionAssistantDesc:'Preview what might be shared before any model request.',actionInventory:'Computer overview',actionInventoryDesc:'See system information without changing anything.',actionDiagnosis:'Check my computer',actionDiagnosisDesc:'Run a safe, read-only health check.',actionRoutine:'Saved system check',actionRoutineDesc:'Reuse a verified read-only check without AI.',actionFolder:'Work with files',actionFolderDesc:'Choose a folder, review a plan and decide what happens.',openAction:'Open →',
  privacyTitle:'You stay in control',privacyDesc:'Local checks stay on this computer. Changes and cloud requests need separate approval.',recentTitle:'Continue a task',noCurrent:'No active task right now.',seeTasks:'View tasks →',
  guidedEyebrow:'GUIDED WORKFLOW',tasksTitle:'Your current task',tasksDesc:'One decision at a time. You can stop whenever you want.',stepTag:'NEXT STEP',noTaskTitle:'No task selected',noTaskDesc:'Choose an action from Home, or wait for a trusted task to be selected.',
  waiting:'Waiting',decline:'Back to home',continue:'Continue',scopeTitle:'Selected location',scopeUnknown:'No trusted folder selection yet.',safetyTitle:'Before anything changes',
  safetyPreview:'Review which files would change.',safetyConfirm:'Approve the exact plan separately.',safetyVerify:'Check the actual result afterward.',notAnApproval:'Answering a form does not authorize changes to your computer.',
  readOnly:'READ-ONLY',computerTitle:'My computer',computerDesc:'See real local information. No files are changed or sent to the cloud.',runOverview:'Show overview',runCheck:'Run health check',noReport:'Choose a check to see its results.',
  activity:'ACTIVITY',historyTitle:'Task history',historyDesc:'Only actual recorded outcomes appear here.',historyEmpty:'No completed steps yet.',preferences:'PREFERENCES',settingsTitle:'Settings',settingsDesc:'Choose how this app looks. Security decisions stay with Windows.',
  languageTitle:'Language',languageDesc:'Use Chinese or English in the interface.',appearanceTitle:'Appearance',appearanceDesc:'Follow your Windows theme or choose light/dark.',connectionTitle:'Connection',connectionDesc:'Shun listens on your computer only. Remote model calls require separate consent.',
  connected:'Connected locally',unavailable:'Local service unavailable',localMode:'Local checks',cloudMode:'Cloud opt-in',searchEmpty:'No matching actions. Try a different phrase.',
  ready:'Ready',needsAttention:'Needs attention',formUnavailable:'This step needs a trusted Host workflow. Nothing has been submitted.',previewMissing:'The actual action plan and independent authorization are not available in this view. No change can be made.',
  scopeReady:'A location has been selected by the trusted Host.',stepExpired:'This step is no longer current. Refresh before continuing.',recorded:'Your decision was recorded. No Windows permission was granted.',refused:'The request was refused.',unknown:'The result is unknown. Do not repeat the operation without checking its actual state.',
  offlineCheck:'This check is only available on a real Windows host.',loading:'Checking your computer…',completed:'Check completed',noData:'No safe summary is available.',technicalDetails:'Technical details',
  consentNext:'Continue to separate authorization',cancelDecision:'Decline this step',unsafeUnavailable:'This form is not an approval or an execution request.',reportMemory:'Memory',reportCpu:'Processor',reportDisk:'Storage',reportDevice:'Device',safeAction:'Read-only check',
  emptyNotice:'Choose a task on the home page to begin.',filterReset:'Clear search',assistantTag:'PRIVACY FIRST',assistantTitle:'Plan with AI',assistantDesc:'Describe a goal and inspect the exact data before consenting to anything.',assistantGoalLabel:'What would you like to do?',assistantPlaceholder:'Example: Explain why my computer feels slow…',assistantPreview:'Preview disclosure',assistantPrivacy:'Local preview only. No cloud send, consent or budget reservation occurs here.',assistantNoPreview:'No disclosure prepared yet.',assistantPreviewOk:'Exact proposed disclosure (not sent)',assistantPreviewFail:'Preview unavailable; nothing was sent.',assistantLoading:'Preparing local preview…',routineTag:'REUSABLE TASK',routineTitle:'Saved system check',routineIntro:'Save one verified, read-only system check and reuse it without AI requests. Shun checks local permissions every time.',routineName:'Computer overview',routineSafe:'Reads only aggregate CPU, memory and storage information. No files are modified.',routineSave:'Save routine',routineRun:'Run saved check',routineAuth:'Saving is not approval. The trusted Host checks permission on every run.',routineNoRun:'No verified run yet.',routineNotSaved:'Not saved',routineSaved:'Saved, not authorized',routineDenied:'Host refused the routine. Nothing was changed.',routineProgress:'Checking trusted Host…',routineSuccess:'Host-verified read-only result',routineError:'Unable to verify the routine status.',observedOnly:'Single observation; not a diagnosis or speed-up guarantee.',metricCpu:'CPU logical cores',metricMemory:'Available / total memory',metricStorage:'Free / total storage',metricProcesses:'Observed processes',metricStartup:'Startup entries',signalDisk:'Low storage space detected',signalMemory:'Low available memory detected',signalNone:'No low-memory or low-storage signal in this snapshot.'
 },
 zh: {
  brandSub:'你的 Windows 电脑助手',navHome:'首页',navTasks:'我的任务',navAssistant:'AI 请求预览',navComputer:'我的电脑',navRoutine:'保存的任务',navHistory:'历史记录',navSettings:'设置',
  localOnly:'仅在本机运行',welcome:'欢迎回来',heroTitle:'今天想让电脑做点什么？',heroDesc:'选择常用任务，顺助手会逐步引导你完成。',searchLabel:'查找任务',searchPlaceholder:'查找任务或操作…',quickTitle:'常用操作',quickDesc:'从安全的检查开始。任何改动都需要你的独立确认。',
  actionAssistant:'用 AI 规划',actionAssistantDesc:'先查看可能披露的信息，不会发送模型请求。',actionInventory:'查看电脑概况',actionInventoryDesc:'查看系统信息，不会修改任何内容。',actionDiagnosis:'检查电脑状态',actionDiagnosisDesc:'安全地检查电脑健康状况，只读操作。',actionRoutine:'保存的系统检查',actionRoutineDesc:'复用已验证的只读任务，不需要 AI。',actionFolder:'整理与管理文件',actionFolderDesc:'选择文件夹，检查计划并决定下一步。',openAction:'打开 →',
  privacyTitle:'电脑始终由你掌控',privacyDesc:'本地检查不会上传数据。修改电脑或连接云端前需单独授权。',recentTitle:'继续未完成的任务',noCurrent:'目前没有正在进行的任务。',seeTasks:'查看任务 →',
  guidedEyebrow:'分步引导',tasksTitle:'当前任务',tasksDesc:'每次只处理一步，随时可以停止。',stepTag:'下一步',noTaskTitle:'暂时没有任务',noTaskDesc:'从首页选择一个操作，或等待可信 Host 选中任务。',
  waiting:'等待中',decline:'返回首页',continue:'继续',scopeTitle:'已选择的位置',scopeUnknown:'尚未通过可信 Host 选择文件夹。',safetyTitle:'执行前的保护',
  safetyPreview:'确认将修改哪些文件。',safetyConfirm:'对具体计划单独授权。',safetyVerify:'执行后核对真实结果。',notAnApproval:'填写表单不代表授权修改电脑。',
  readOnly:'只读操作',computerTitle:'我的电脑',computerDesc:'查看真实的本机信息，不会改动文件或上传数据。',runOverview:'查看概况',runCheck:'检查健康状态',noReport:'选择一项检查来查看结果。',
  activity:'操作记录',historyTitle:'任务历史',historyDesc:'这里只显示真正已记录的结果。',historyEmpty:'还没有已完成的步骤。',preferences:'个性化',settingsTitle:'设置',settingsDesc:'调整显示方式。安全授权由 Windows 和可信 Host 处理。',
  languageTitle:'界面语言',languageDesc:'选择简体中文或英语。',appearanceTitle:'外观',appearanceDesc:'跟随系统主题或选择明暗外观。',connectionTitle:'连接状态',connectionDesc:'只在本机提供服务。调用云端模型必须另行确认。',
  connected:'已连接本机',unavailable:'本机服务不可用',localMode:'本地检查',cloudMode:'云端需授权',searchEmpty:'没有找到匹配的操作，请换个关键词。',
  ready:'可继续',needsAttention:'需要检查',formUnavailable:'此步骤尚需可信 Host 的业务支持，未提交任何内容。',previewMissing:'此处尚无法展示真实操作计划与独立授权信息，因此不会修改电脑。',
  scopeReady:'可信 Host 已选择一个位置。',stepExpired:'该步骤已过期，请刷新后再继续。',recorded:'已记录你的选择，没有签发 Windows 执行权限。',refused:'请求已拒绝。',unknown:'操作结果未知。核实真实状态前请勿重复操作。',
  offlineCheck:'此项检查仅在真实 Windows 主机上可用。',loading:'正在检查电脑…',completed:'检查完成',noData:'没有可安全展示的摘要。',technicalDetails:'技术细节',
  consentNext:'继续到独立授权',cancelDecision:'拒绝此步骤',unsafeUnavailable:'此表单不产生执行授权。',reportMemory:'内存',reportCpu:'处理器',reportDisk:'存储空间',reportDevice:'设备',safeAction:'只读检查',
  emptyNotice:'请先从首页选择一个任务。',filterReset:'清除搜索',assistantTag:'隐私优先',assistantTitle:'用 AI 规划',assistantDesc:'描述目标，在同意任何请求前先查看拟披露的精确内容。',assistantGoalLabel:'你想完成什么？',assistantPlaceholder:'例如：帮我解释电脑为什么变慢了……',assistantPreview:'查看披露内容',assistantPrivacy:'仅在本机生成预览，不会调用模型、签发同意或预留预算。',assistantNoPreview:'尚无披露预览。',assistantPreviewOk:'拟披露的原始内容（尚未发送）',assistantPreviewFail:'预览失败，未发送任何内容。',assistantLoading:'正在本机准备预览……',routineTag:'可复用的任务',routineTitle:'保存的系统检查',routineIntro:'保存一个已验证的只读系统检查，以后不用调用 AI 也能执行。每次都由本机核对权限。',routineName:'电脑概况',routineSafe:'只读取 CPU、内存和存储空间的汇总信息，不会修改文件。',routineSave:'保存任务',routineRun:'运行保存的检查',routineAuth:'保存任务不代表授权执行，每次运行都由可信 Host 检查权限。',routineNoRun:'还没有已验证的运行结果。',routineNotSaved:'尚未保存',routineSaved:'已保存，未授权执行',routineDenied:'可信 Host 拒绝运行，未修改任何内容。',routineProgress:'正在核对本机可信 Host…',routineSuccess:'本机已验证的只读结果',routineError:'无法核对任务状态。',observedOnly:'仅代表一次观察，不保证定位原因或提升速度。',metricCpu:'CPU 逻辑核心',metricMemory:'可用 / 总内存',metricStorage:'剩余 / 总存储空间',metricProcesses:'已观察的进程数',metricStartup:'启动项数量',signalDisk:'检测到剩余存储空间偏低',signalMemory:'检测到可用内存偏低',signalNone:'本次快照未检测到内存或存储空间不足的信号。'
 }
};
const storage = (() => {
 try { return {read:k=>sessionStorage.getItem(k),write:(k,v)=>sessionStorage.setItem(k,v)}; }
 catch { return {read:()=>null,write:()=>{}}; }
})();
let locale = storage.read('shun-ui-language') === 'en' ? 'en' :
 storage.read('shun-ui-language') === 'zh' ? 'zh' :
 (navigator.language || 'en').toLowerCase().startsWith('zh') ? 'zh' : 'en';
let current = null;
let lastState = null;
let connected = false;
let cloudOptIn = false;
let busy = false;
let routineBusy = false;
let verifiedRoutine = false;
const submitted = [];
const $ = id => document.getElementById(id);
const tr = key => (words[locale] && words[locale][key]) || words.en[key] || key;
function stepText(key) {
 const item = approvedText(locale, key);
 return item.ok ? item.text : null;
}
function set(id, value) { const node = $(id); if (node) node.textContent = value; }
function translate() {
 document.documentElement.lang = locale === 'zh' ? 'zh-CN' : 'en';
 for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = tr(node.dataset.i18n);
 for (const node of document.querySelectorAll('[data-placeholder]')) node.placeholder = tr(node.dataset.placeholder);
 $('language').value = locale;
 $('appearance').value = document.documentElement.dataset.theme || 'system';
 for (const label of document.querySelectorAll('[data-page]')) {
  if (label.classList.contains('nav-item') && label.classList.contains('active')) set('breadcrumb', label.textContent.trim());
 }
 set('connection', tr(connected ? 'connected' : 'unavailable'));
 set('settings-connection', tr(connected ? 'connected' : 'unavailable'));
 set('mode-label', tr(cloudOptIn ? 'cloudMode' : 'localMode'));
 renderGuided();
 renderHistory();
}
function page(name) {
 for (const p of document.querySelectorAll('main .page')) p.hidden = p.id !== 'page-' + name;
 for (const button of document.querySelectorAll('.nav-item')) {
  const isActive = button.dataset.page === name;
  button.classList.toggle('active', isActive);
  if (isActive) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current');
  if (isActive) set('breadcrumb', button.textContent.trim());
 }
 document.querySelector('.shell').classList.remove('menu-open');
 $('menu-toggle').setAttribute('aria-expanded','false');
 if (name === 'tasks') refresh().catch(showError);
 if (name === 'routine') refreshRoutine().catch(showError);
 $('main').focus({preventScroll:true});
}
function notify(message, kind='info') {
 const toast=$('toast'); toast.hidden=false; toast.textContent=message; toast.dataset.kind=kind;
}
function showError(error) { notify(tr('unknown') + ' ' + (error instanceof Error ? error.message : String(error))); }
async function request(url, options) {
 const reply=await fetch(url, {credentials:'same-origin',...options});
 const json=await reply.json().catch(()=>null);
 if (!reply.ok) {
  const code=typeof json?.code==='string'?json.code:typeof json?.error?.code==='string'?json.error.code:'HTTP_'+reply.status;
  const error=new Error(code); error.status=reply.status; throw error;
 }
 return json;
}
async function refresh() {
 try {
  const [health,state]=await Promise.all([
   request('/api/health').catch(()=>null),
   request('/api/v03/guided/state').catch(()=>null)
  ]);
  connected=health?.ok===true;
  cloudOptIn=connected && health.cloudMode==='REMOTE_OPT_IN';
  $('connection').previousElementSibling?.classList.toggle('online',connected);
  lastState=state;
  current=state?.currentStep || null;
  if (!connected) notify(tr('unavailable'));
  translate();
 } catch (error) { connected=false; current=null; lastState=null; showError(error);translate(); }
}
function renderGuided() {
 const form=$('dynamic-form'), fields=$('form-fields'), container=$('step-container'), alert=$('step-alert');
 form.hidden=true; fields.replaceChildren(); container.replaceChildren();alert.hidden=true;currentModel=null;
 if (!current) {
  set('step-title',tr('noTaskTitle'));set('step-description',tr('noTaskDesc'));
  set('step-status',tr('waiting'));set('scope-summary',tr('scopeUnknown'));
  set('home-task-summary',tr('noCurrent'));return;
 }
 const model=currentStepModel(current,Date.now());
 if (model.status!=='CURRENT') {
  set('step-title',tr('needsAttention'));set('step-description',tr('stepExpired'));
  set('step-status',model.status);alert.textContent=model.reason||tr('stepExpired');alert.hidden=false;return;
 }
 currentModel=model;
 set('home-task-summary',stepText(model.titleKey)||tr('ready'));
 set('step-title',stepText(model.titleKey)||tr('needsAttention'));
 set('step-description',model.requiresExplicitApproval?tr('previewMissing'):tr('notAnApproval'));
 set('step-status',tr('ready'));
 set('scope-summary',lastState?.scope?.status==='KNOWN'?tr('scopeReady'):tr('scopeUnknown'));
 for (const field of model.fields) {
  const block=document.createElement('div');block.className='field';
  const label=document.createElement('label');label.htmlFor='field-'+field.id;
  label.textContent=stepText(field.labelKey)||tr('needsAttention');
  const makeOption=o=>stepText(o.labelKey)||tr('needsAttention');
  if (field.type==='TEXT') {
   const input=document.createElement('input');input.type='text';input.id=label.htmlFor;input.name=field.id;
   input.required=field.required;input.maxLength=Math.min(field.maxLength||256,1024);input.autocomplete='off';
   block.append(label,input);
  } else if (field.type==='CHOICE') {
   const select=document.createElement('select');select.id=label.htmlFor;select.name=field.id;select.required=field.required;
   const blank=document.createElement('option');blank.value='';blank.textContent='—';select.append(blank);
   for (const option of field.options||[]) {const el=document.createElement('option');el.value=option.id;el.textContent=makeOption(option);select.append(el);}
   block.append(label,select);
  } else if (field.type==='CONFIRM') {
   const input=document.createElement('input');input.type='checkbox';input.id=label.htmlFor;input.name=field.id;
   input.required=field.required;const line=document.createElement('div');line.className='choice';line.append(input,label);block.append(line);
  } else {alert.textContent=tr('formUnavailable');alert.hidden=false;return;}
  fields.append(block);
 }
 form.hidden=false;
 const isReview=model.kind==='REVIEW_EFFECT';
 $('step-submit').disabled=model.kind!=='ASK';
 $('step-submit').textContent=tr('continue');
 $('step-refuse').disabled=false;
 set('approval-hint',isReview?tr('previewMissing'):tr('formUnavailable'));
 if (isReview) { alert.textContent=tr('previewMissing');alert.hidden=false; }
}
let currentModel=null;
function formAnswers() {
 if (!currentModel)return [];
 return currentModel.fields.flatMap(f=>{
  const input=$('field-'+f.id);
  if (!input) return [];
  const value=f.type==='CONFIRM'?!!input.checked:input.value;
  // Blank optional fields are absent, not invalid empty answers.
  if (!f.required && (value==='' || value===false)) return [];
  return [{fieldId:f.id,value}];
 });
}
async function submitDecision(decision) {
 if (busy || !current || !currentModel) return;
 if (decision==='ANSWER' && currentModel.kind!=='ASK') {notify(tr('formUnavailable'));return;}
 if (decision==='APPROVE') {notify(tr('previewMissing'));return;}
 const form=$('dynamic-form');
 if (decision==='ANSWER' && !form.reportValidity())return;
 const built=buildStepOutcome({step:current,answers:formAnswers(),sourceRef:'ui:shun-r04-desktop',occurredAtUnixMs:Date.now()});
 if (!built.ok) {notify(tr('refused')+' '+built.reason);return;}
 const relay=decision==='ANSWER' ? {ok:true,relay:{
  kind:'USER_DECISION_RELAY',humanApproval:false,authorityClaimed:false,
  decision:'ANSWER',relayedVia:'/api',stepId:current.stepId,
  stepDigest:current.templateRef.digest,caseRef:current.caseRef,outcome:built.outcome
 }} : userDecisionRelay({step:current,outcome:built.outcome,decision,confirmed:true,nowUnixMs:Date.now()});
 if (!relay.ok) {notify(tr('refused')+' '+relay.reason);return;}
 const replay=replayGuard(submitted,built.outcome);
 if (!replay.allowed) {notify(tr('refused'));return;}
 busy=true;$('step-submit').disabled=true;$('step-refuse').disabled=true;
 try{
  const receipt=await request('/api/v03/guided/decision',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(relay.relay)});
  if(receipt?.status!=='RECORDED'||receipt.humanGrantIssued!==false||receipt.effectSent!==false)throw Error('GUIDED_OUTCOME_UNKNOWN');
  submitted.push(replay.key);notify(tr('recorded'));await refresh();
 }catch(error){notify(tr('unknown')+' '+(error instanceof Error?error.message:''));}
 finally{busy=false;renderGuided();}
}
function renderHistory() {
 const box=$('history-list');box.replaceChildren();
 const history=Array.isArray(lastState?.history)?lastState.history:[];
 if (!history.length){const p=document.createElement('p');p.textContent=tr('historyEmpty');box.append(p);return;}
 for (const row of history.slice().reverse().slice(0,40)) {
  const item=document.createElement('div');item.className='history-entry';
  const title=document.createElement('strong');title.textContent=row.status==='ACCEPTED'?tr('recorded'):row.status==='REFUSED'?tr('refused'):tr('unknown');
  const when=document.createElement('time');when.textContent=typeof row.at==='string'?new Date(row.at).toLocaleString(locale==='zh'?'zh-CN':'en-US'):'';
  item.append(title,document.createElement('br'),when);box.append(item);
 }
}

function showLocalReport(target, projected) {
  target.replaceChildren();
  if (projected?.status !== 'OBSERVED') {
    const p=document.createElement('p');p.textContent=tr('noData');
    target.append(p);return false;
  }
  const h=document.createElement('h2');h.textContent=tr('completed');target.append(h);
  const dl=document.createElement('dl');
  const labels={cpu:'metricCpu',memory:'metricMemory',storage:'metricStorage',
    processes:'metricProcesses',startup:'metricStartup'};
  for(const item of [...projected.metrics,...projected.counts]){
    if(!Object.prototype.hasOwnProperty.call(labels,item.key))continue;
    const dt=document.createElement('dt'),dd=document.createElement('dd');
    dt.textContent=tr(labels[item.key]);dd.textContent=item.value;
    dl.append(dt,dd);
  }
  target.append(dl);
  const p=document.createElement('p');p.textContent=tr('observedOnly');target.append(p);
  if(projected.signals.length) {
    const list=document.createElement('ul');list.className='signal-list';
    for (const signal of projected.signals) {
      const li=document.createElement('li');
      li.textContent=tr(signal==='LOW_DISK_SPACE'?'signalDisk':'signalMemory');
      list.append(li);
    }
    target.append(list);
  }
  return true;
}
async function runCheck(kind) {
  page('computer');
  const result=$('computer-result');result.replaceChildren();
  const status=document.createElement('p');status.textContent=tr('loading');result.append(status);
  try {
    const data=await request(kind==='inventory'?'/api/system/inventory':'/api/system/diagnosis');
    const projected=projectLocalObservation(kind,data);
    if(!showLocalReport(result,projected)) throw Error(projected.code);
  }catch(error){
    result.replaceChildren();
    const p=document.createElement('p');
    p.textContent=tr('offlineCheck')+' '+(error instanceof Error?error.message:'');
    result.append(p);
  }
}
/** Only reads the Host-persisted, immutable built-in Recipe candidate status. */
async function refreshRoutine() {
  verifiedRoutine=false;$('routine-run').disabled=true;
  if(routineBusy)return;
  set('routine-status',tr('routineProgress'));
  try {
    const status=projectRoutineState(await request('/api/recipes/builtin/system-inventory'));
    if(status.status!=='OBSERVED')throw Error(status.code);
    verifiedRoutine=status.saved;
    $('routine-run').disabled=!status.saved;
    set('routine-status',tr(status.saved?'routineSaved':'routineNotSaved'));
  }catch(error){
    set('routine-status',tr('routineError'));
    $('routine-run').disabled=true;
  }
}
/** Explicit user click only; no arbitrary Recipe, hashes, file path or model input. */
async function saveRoutine() {
  if(routineBusy)return;
  routineBusy=true;$('routine-save').disabled=true;$('routine-run').disabled=true;
  set('routine-status',tr('routineProgress'));
  try {
    const saved=await request('/api/recipes/builtin/system-inventory/save',{
      method:'POST',headers:{'content-type':'application/json'},body:'{}'
    });
    if(saved?.ok!==true)throw Error('ROUTINE_SAVE_UNVERIFIED');
  }catch(error){set('routine-status',tr('routineDenied'));notify(tr('routineDenied'));}
  finally {routineBusy=false;$('routine-save').disabled=false;await refreshRoutine();}
}
/** A Host-authorized R0 read only; no front-end grant, no auto run/retry. */
async function runRoutine() {
  if(routineBusy || !verifiedRoutine)return;
  routineBusy=true;verifiedRoutine=false;$('routine-run').disabled=true;
  set('routine-status',tr('routineProgress'));
  const target=$('routine-result');target.replaceChildren();
  const p=document.createElement('p');p.textContent=tr('routineProgress');target.append(p);
  try {
    const outcome=await request('/api/recipes/builtin/system-inventory/run',{
      method:'POST',headers:{'content-type':'application/json'},body:'{}'
    });
    const projected=projectRoutineExecution(outcome);
    if(!showLocalReport(target,projected))throw Error(projected.code);
    set('routine-status',tr('routineSuccess'));
  }catch(error){
    target.replaceChildren();
    const message=document.createElement('p');message.textContent=tr('routineDenied');
    target.append(message);
    set('routine-status',tr('routineDenied'));
  }finally{routineBusy=false;await refreshRoutine();}
}
/** Exact privacy preview is a read-only local API call, never an LLM send. */
async function previewAiGoal() {
  const goal=$('ai-goal').value;
  if (!goal.trim()) return;
  const target=$('ai-preview-result');
  target.replaceChildren();
  const loading=document.createElement('p');loading.textContent=tr('assistantLoading');target.append(loading);
  $('ai-preview').disabled=true;
  try {
    const raw=await request('/api/cloud/disclosure-preview',{
      method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({goalText:goal})
    });
    const preview=projectDisclosurePreview(raw);
    if(preview.status!=='OBSERVED')throw Error(preview.code);
    target.replaceChildren();
    const title=document.createElement('h3');title.textContent=tr('assistantPreviewOk');
    const exact=document.createElement('pre');exact.className='disclosure';
    exact.textContent=preview.projectionJson; // never innerHTML, never reconstruct the bytes
    const info=document.createElement('p');info.textContent=tr('assistantPrivacy');
    target.append(title,exact,info);
  }catch{
    target.replaceChildren();
    const notice=document.createElement('p');notice.textContent=tr('assistantPreviewFail');
    target.append(notice);
  }finally{$('ai-preview').disabled=false;}
}
document.querySelectorAll('[data-page]').forEach(button=>button.addEventListener('click',()=>page(button.dataset.page)));
document.querySelectorAll('[data-action]').forEach(button=>button.addEventListener('click',()=>{
 const kind=button.dataset.action;
 if(kind==='assistant')page('assistant');
 else if(kind==='guided')page('tasks');
 else if(kind==='routine')page('routine');
 else runCheck(kind).catch(showError);
}));
$('run-inventory').addEventListener('click',()=>runCheck('inventory').catch(showError));
$('run-diagnosis').addEventListener('click',()=>runCheck('diagnosis').catch(showError));
$('routine-save').addEventListener('click',()=>saveRoutine().catch(showError));
$('routine-run').addEventListener('click',()=>runRoutine().catch(showError));
$('ai-preview-form').addEventListener('submit',event=>{event.preventDefault();previewAiGoal().catch(showError);});
$('ai-goal').addEventListener('input',()=>{const box=$('ai-preview-result');box.replaceChildren();const p=document.createElement('p');p.textContent=tr('assistantNoPreview');box.append(p);});
$('refresh').addEventListener('click',()=>refresh().catch(showError));
$('language').addEventListener('change',event=>{locale=event.target.value==='zh'?'zh':'en';storage.write('shun-ui-language',locale);translate();});
$('appearance').addEventListener('change',event=>{const v=['light','dark'].includes(event.target.value)?event.target.value:'system';document.documentElement.dataset.theme=v;storage.write('shun-ui-theme',v);});
document.documentElement.dataset.theme=storage.read('shun-ui-theme')||'system';
$('menu-toggle').addEventListener('click',()=>{
 const shell=document.querySelector('.shell');shell.classList.toggle('menu-open');
 $('menu-toggle').setAttribute('aria-expanded',String(shell.classList.contains('menu-open')));
});
$('dynamic-form').addEventListener('submit',event=>{event.preventDefault();submitDecision('ANSWER').catch(showError);});
// Back is local navigation; it neither refuses a Host case nor grants execution.
$('step-refuse').addEventListener('click',()=>page('home'));
$('task-search').addEventListener('input',event=>{
 const q=event.target.value.trim().toLocaleLowerCase(locale==='zh'?'zh-CN':'en');
 for(const card of document.querySelectorAll('[data-action]'))card.hidden=!!q&&!card.textContent.toLocaleLowerCase().includes(q);
});
document.addEventListener('keydown',event=>{
 if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();page('home');$('task-search').focus();}
 if(event.key==='Escape'){$('task-search').blur();document.querySelector('.shell').classList.remove('menu-open');}
});
translate();refresh().catch(showError);
