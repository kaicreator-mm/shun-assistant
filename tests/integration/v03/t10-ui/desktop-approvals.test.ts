import {describe,it,expect} from 'vitest';
import {
 realApprovalPosture,projectPendingApprovals,projectExactApproval,
 projectApprovalDecision,projectTaskSnapshots,projectHostTaskDetail
} from '../../../../apps/control-ui/public/v03/desktop-approvals.js';

const now=Date.parse('2026-11-01T12:00:00Z');
const future='2026-11-01T12:10:00Z';
const health={ok:true,loopbackOnly:true,simulated:false,
 policy:{kind:'ACTIVE',revision:'policy-current'}};
const pending={approvalId:'ui-123',taskId:'task-abc',planHash:'a'.repeat(64),
 status:'PENDING',riskClass:'R2',requiresExplicitApproval:true,
 summary:'Review bounded cleanup',expiresAt:future};
const preview={taskId:pending.taskId,planHash:pending.planHash,riskClass:'R2',
 requiresExplicitApproval:true,riskStatement:'Destructive change needs approval.',
 policySnapshotRevision:'policy-current',expiresAt:future,
 actions:[{actionId:'step-1',op:'file.move',requiredPrivilege:'USER',
 description:'Move bounded files inside the approved folder.',
 filesystem:{read:['C:\\safe'],write:['C:\\safe']},network:{allowed:false}}],
 recovery:{summary:'Reconcile with durable Journal before retry.'},
 verification:{summary:'Compare actual post-state.',checks:['step-verified']}};

describe('R04 real ActionController approval UI',()=>{
 it('keeps demo/untrusted/non-active policy out of the approval action path',()=>{
  expect(realApprovalPosture({...health,simulated:true})).toBe('DEMO');
  expect(realApprovalPosture({...health,policy:{kind:'UNKNOWN'}})).toBe('BLOCKED');
  expect(realApprovalPosture({...health,loopbackOnly:false})).toBe('UNKNOWN');
  expect(projectPendingApprovals({...health,simulated:true},{approvals:[pending]},now))
    .toEqual({status:'DEMO',items:[]});
 });
 it('requires exact pending and live expiry',()=>{
  expect(projectPendingApprovals(health,{approvals:[pending]},now)).toMatchObject({
   status:'READY',items:[{id:'ui-123',riskClass:'R2'}]
  });
  expect(projectPendingApprovals(health,{approvals:[{...pending,status:'APPROVED'}]},now).status).toBe('REFUSED');
  expect(projectPendingApprovals(health,{approvals:[pending]},now+720000).status).toBe('REFUSED');
 });
 it('requires identical task/plan/risk/policy/expiry and bounded human preview',()=>{
  const good=projectExactApproval(health,{approval:pending,preview},pending.approvalId,now);
  expect(good).toMatchObject({status:'READY',risk:'R2',planHash:'a'.repeat(64)});
  expect(projectExactApproval(health,{approval:pending,preview:{...preview,planHash:'b'.repeat(64)}},pending.approvalId,now).status).toBe('REFUSED');
  expect(projectExactApproval(health,{approval:pending,preview:{...preview,policySnapshotRevision:'old'}},pending.approvalId,now).status).toBe('REFUSED');
  expect(projectExactApproval(health,{approval:pending,preview:{...preview,actions:[]}},pending.approvalId,now).status).toBe('REFUSED');
  expect(projectExactApproval(health,{approval:pending,preview:{...preview,expiresAt:undefined}},pending.approvalId,now).status).toBe('REFUSED');
  expect(projectExactApproval(health,{approval:pending,preview:{...preview,expiresAt:'2026-11-01T12:11:00Z'}},pending.approvalId,now).status).toBe('REFUSED');
  expect(projectExactApproval(health,{approval:pending,preview:{...preview,actions:[{...preview.actions[0],network:{allowed:true,domains:['untrusted.example']}}]}},pending.approvalId,now).status).toBe('READY');
 });
 it('considers Host decision recorded only on exact echoed identity, never success of an effect',()=>{
  const selected=projectExactApproval(health,{approval:pending,preview},pending.approvalId,now);
  const decision={decision:{approvalId:pending.approvalId,taskId:pending.taskId,
   planHash:pending.planHash,approved:true,approvedBy:'USER_APPROVAL'}};
  expect(projectApprovalDecision(decision,selected,true)).toEqual({status:'RECORDED',approved:true});
  expect(projectApprovalDecision({...decision,decision:{...decision.decision,planHash:'b'.repeat(64)}},selected,true).status).toBe('REFUSED');
  expect(projectApprovalDecision(decision,selected,false).status).toBe('REFUSED');
 });
 it('opens a task detail only for the exact Host task identity and supported evidence',()=>{
  const recorded={taskId:'task-a',title:'Local check',state:'COMPLETED',
   updatedAt:'2026-11-01T12:00:00Z',
   planSummary:{planHash:'a'.repeat(64),riskClass:'R0',riskStatement:'Read-only check.',
    actionCount:1},verification:{status:'PASSED',
    checks:[{checkId:'disk-observed',status:'PASSED'}]},
   recovery:{classification:'NOT_REQUIRED',detail:'No recovery was needed.',reconciled:true}};
  expect(projectHostTaskDetail(recorded,'task-a')).toMatchObject({status:'READY',
   verification:{status:'PASSED'},plan:{risk:'R0'},recovery:{reconciled:true}});
  expect(projectHostTaskDetail(recorded,'task-b').status).toBe('REFUSED');
  expect(projectHostTaskDetail({...recorded,updatedAt:'unknown'},'task-a').status).toBe('REFUSED');
  expect(projectHostTaskDetail({...recorded,verification:{status:'PASSED',checks:[{status:'PASSED'}]}},'task-a').status).toBe('REFUSED');
  expect(projectHostTaskDetail({...recorded,planSummary:{...recorded.planSummary,planHash:'forged'}},'task-a').status).toBe('REFUSED');
 });
 it('renders only bounded verified task metadata from the Host list',()=>{
  expect(projectTaskSnapshots({tasks:[{taskId:'task-a',title:'PC health check',
    state:'COMPLETED',updatedAt:'2026-11-01T12:00:00Z'}]}).status).toBe('READY');
  expect(projectTaskSnapshots({tasks:[{taskId:'task-a',title:'',state:'COMPLETED',
    updatedAt:'2026-11-01T12:00:00Z'}]}).status).toBe('REFUSED');
  expect(projectTaskSnapshots({tasks:[{taskId:'task-a',title:'Local check',
    state:'COMPLETED',updatedAt:'invalid-timestamp'}]}).status).toBe('REFUSED');
 });
});
