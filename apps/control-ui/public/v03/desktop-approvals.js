/**
 * R04: strict read-only UI projection over the actual Host approval API.
 * No grant, consent, Permit, policy or approval object is created here.
 */
const SHA = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RISKS = ['R2', 'R3'];
// Exact Host contract TaskState whitelist, display-only, not an authority.
const STATES = ['RECEIVED','INTERPRETING','CLARIFICATION','RESOLVING','PLANNED','AWAITING_AUTHORIZATION','EXECUTING','VERIFYING','LIFECYCLE_RECONCILIATION','SUCCEEDED','FAILED','CANCELLED','NEEDS_INTERVENTION'];
const TEXT_MAX = 4096;

/** @param {unknown} value @returns {value is Record<string, any>} */
function object(value) { return !!value && typeof value === 'object' && !Array.isArray(value); }
/** @param {unknown} value @param {number} max */
function shortText(value, max=TEXT_MAX) { return typeof value==='string' && value.length>0 && value.length<=max; }
/** @param {string} code */
function refused(code){return {status:'REFUSED',code};}
/** @param {unknown} x @param {number} now */
function future(x,now){const n=typeof x==='string'?Date.parse(x):NaN;return Number.isFinite(n)&&n>now&&n<=now+24*60*60*1000;}
/** @param {unknown} a @param {number} now */
function pending(a,now){
 return object(a)&&ID.test(a.approvalId)&&ID.test(a.taskId)&&SHA.test(a.planHash)&&
 a.status==='PENDING'&&RISKS.includes(a.riskClass)&&a.requiresExplicitApproval===true&&
 shortText(a.summary)&&future(a.expiresAt,now);
}
/** @param {unknown} health */
export function realApprovalPosture(health){
 if(!object(health)||health.ok!==true||health.loopbackOnly!==true)return 'UNKNOWN';
 if(health.simulated===true)return 'DEMO';
 if(health.simulated!==false||!object(health.policy)||health.policy.kind!=='ACTIVE'||
   !shortText(health.policy.revision,128))return 'BLOCKED';
 return 'REAL';
}
/** @param {unknown} health @param {unknown} value @param {number} now */
export function projectPendingApprovals(health,value,now){
 const posture=realApprovalPosture(health);
 if(posture!=='REAL')return {status:posture,items:[]};
 if(!Number.isSafeInteger(now)||!object(value)||!Array.isArray(value.approvals)||
    value.approvals.length>64)return refused('APPROVAL_INBOX_UNVERIFIED');
 if(value.approvals.some(a=>!pending(a,now)))return refused('APPROVAL_INBOX_UNVERIFIED');
 const items=value.approvals.map(a=>({
   id:a.approvalId,taskId:a.taskId,summary:a.summary,
   planHash:a.planHash,riskClass:a.riskClass,expiresAt:a.expiresAt
 }));
 return {status:'READY',items};
}
/**
 * Full immutable approval preview. Both Host approval and PlanPreview must
 * reference exactly the same task, SHA-256 plan, risk, expiry and policy.
 * @param {unknown} health
 * @param {unknown} value
 * @param {string} expectedId
 * @param {number} now
 */
export function projectExactApproval(health,value,expectedId,now){
 if(realApprovalPosture(health)!=='REAL'||!object(health)||!object(health.policy))
   return refused('AUTHORITY_UNAVAILABLE');
 if(!ID.test(expectedId)||!object(value)||!object(value.approval)||!object(value.preview))return refused('PREVIEW_UNVERIFIED');
 const a=value.approval,p=value.preview;
 if(!pending(a,now)||a.approvalId!==expectedId||p.taskId!==a.taskId||
    p.planHash!==a.planHash||p.riskClass!==a.riskClass||
    p.requiresExplicitApproval!==true||!shortText(p.riskStatement)||
    !shortText(p.policySnapshotRevision,128)||
    p.policySnapshotRevision!==health.policy.revision||
    !object(p.recovery)||!shortText(p.recovery.summary)||
    !object(p.verification)||!shortText(p.verification.summary)||
    !Array.isArray(p.verification.checks)||p.verification.checks.length>64||
    p.verification.checks.some(x=>!shortText(x,256))||
    p.expiresAt!==a.expiresAt||
    !Array.isArray(p.actions)||p.actions.length===0||p.actions.length>64){
   return refused('PLAN_IDENTITY_UNVERIFIED');
 }
 const actions=[];
 for(const item of p.actions){
  if(!object(item)||!shortText(item.description)||!shortText(item.op,128)||
     !shortText(item.actionId,128)||!['NONE','USER','ELEVATED'].includes(item.requiredPrivilege)||
     !object(item.network)||typeof item.network.allowed!=='boolean')return refused('ACTION_PREVIEW_UNVERIFIED');
  if(item.filesystem!==undefined && (
       !object(item.filesystem)||!Array.isArray(item.filesystem.read)||
       !Array.isArray(item.filesystem.write)||item.filesystem.read.length>128||
       item.filesystem.write.length>128||
       [...item.filesystem.read,...item.filesystem.write].some(x=>!shortText(x,1024))
  ))return refused('SCOPE_PREVIEW_UNVERIFIED');
  const domains=item.network.domains;
  if(domains!==undefined&&(!Array.isArray(domains)||domains.length>64||
      domains.some(x=>!shortText(x,256))))return refused('NETWORK_PREVIEW_UNVERIFIED');
  actions.push({
   title:item.op,description:item.description,requiredPrivilege:item.requiredPrivilege,
   read:item.filesystem?.read||[],write:item.filesystem?.write||[],
   networkAllowed:item.network.allowed,networkDomains:domains||[]
  });
 }
 return {status:'READY',id:a.approvalId,taskId:a.taskId,summary:a.summary,
  planHash:a.planHash,risk:a.riskClass,riskStatement:p.riskStatement,
  actions,verification:p.verification.summary,recovery:p.recovery.summary,
  expiresAt:a.expiresAt};
}
/** Verify exact echoed Host decision; approval is never effect completion.
 * @param {unknown} value @param {any} approvedView @param {boolean} userChoice
 */
export function projectApprovalDecision(value,approvedView,userChoice){
 if(!object(value)||!object(value.decision)||!approvedView||approvedView.status!=='READY')
   return refused('DECISION_UNVERIFIED');
 const d=value.decision;
 if(d.approvalId!==approvedView.id||d.taskId!==approvedView.taskId||
  d.planHash!==approvedView.planHash||d.approved!==userChoice||
  d.approvedBy!=='USER_APPROVAL')return refused('DECISION_MISMATCH');
 return {status:'RECORDED',approved:userChoice};
}
/** @param {unknown} value */
export function projectTaskSnapshots(value){
 if(!object(value)||!Array.isArray(value.tasks)||value.tasks.length>256)
   return refused('TASK_HISTORY_UNVERIFIED');
 const items=[];
 for(const task of value.tasks){
  if(!object(task)||!shortText(task.taskId,128)||!shortText(task.title,2048)||
   !STATES.includes(task.state)||!shortText(task.updatedAt,64)||
   !Number.isFinite(Date.parse(task.updatedAt)))return refused('TASK_HISTORY_UNVERIFIED');
  items.push({id:task.taskId,title:task.title,state:task.state,
   updatedAt:task.updatedAt});
 }
 return {status:'READY',items:items.slice(-100).reverse()};
}

/**
 * Read-only bounded projection of GET /api/tasks/:id. A Host task state is
 * reported as recorded metadata, never translated into an effect grant.
 * @param {unknown} value
 * @param {string} expectedId
 */
export function projectHostTaskDetail(value,expectedId){
 if(!ID.test(expectedId)||!object(value)||value.taskId!==expectedId||
    !shortText(value.title,2048)||!STATES.includes(value.state)||
    !shortText(value.updatedAt,64)||!Number.isFinite(Date.parse(value.updatedAt)))
   return refused('TASK_DETAIL_UNVERIFIED');
 let plan=null,verification=null,recovery=null;
 if(value.planSummary!==undefined){
  const p=value.planSummary;
  if(!object(p)||!SHA.test(p.planHash)||!['R0','R1','R2','R3'].includes(p.riskClass)||
     !shortText(p.riskStatement)||!Number.isSafeInteger(p.actionCount)||p.actionCount<0)
    return refused('TASK_PLAN_UNVERIFIED');
  plan={risk:p.riskClass,riskStatement:p.riskStatement,actionCount:p.actionCount,planHash:p.planHash};
 }
 if(value.verification!==undefined){
  const v=value.verification;
  if(!object(v)||!shortText(v.status,96)||!Array.isArray(v.checks)||v.checks.length>128||
     v.checks.some(x=>!object(x)||!shortText(x.checkId,128)||!shortText(x.status,96)))
    return refused('TASK_VERIFICATION_UNVERIFIED');
  verification={status:v.status,checks:v.checks.map(x=>({id:x.checkId,status:x.status}))};
 }
 if(value.recovery!==undefined){
  const r=value.recovery;
  if(!object(r)||!shortText(r.classification,128)||!shortText(r.detail)||typeof r.reconciled!=='boolean')
    return refused('TASK_RECOVERY_UNVERIFIED');
  recovery={classification:r.classification,detail:r.detail,reconciled:r.reconciled};
 }
 return {status:'READY',id:expectedId,title:value.title,state:value.state,
  updatedAt:value.updatedAt,plan,verification,recovery};
}
