import { describe, it, expect } from 'vitest';
import {
  formatGib, projectLocalObservation, projectRoutineState, projectRoutineExecution,
} from '../../../../apps/control-ui/public/v03/desktop-observations.js';

const base = {
  schema: 'shun.system-inventory.v02',
  platform: 'win32',
  provenance: 'node:os+node:fs:statfs',
  localOnly: true,
  externalDisclosures: [],
  cpuLogicalCount: 8,
  memoryTotalBytes: 17179869184,
  memoryFreeBytes: 8589934592,
  diskTotalBytes: 107374182400,
  diskFreeBytes: 53687091200,
};
const inventory = {
  ok: true, source: 'LIVE_WINDOWS_LOCAL_READONLY',
  localOnly: true, externalDisclosures: [], snapshot: base,
};
const diagnosis = {
  ok: true, source: 'LIVE_WINDOWS_LOCAL_READONLY', recipeExecuted: false, cloudCalls: 0,
  report: {
    schema: 'shun.windows-diagnostic-report.v02', status: 'OBSERVED_ONLY',
    localOnly: true, externalDisclosures: [],
    limitation:'SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM',
    evidence: {
      ...base, inventoryProvenance: base.provenance,
      runtimeProvenance: 'fixed-readonly-powershell',
      processCount: 83, startupEntryCount: 9,
    },
    signals: ['LOW_FREE_MEMORY'], advice: [{action:'REVIEW_APPLICATIONS',effect:'NONE'}],
  },
};
describe('R04 real local-only observation projection', () => {
  it('formats an exact trusted local inventory for people, not as raw DTO data', () => {
    expect(formatGib(base.memoryTotalBytes)).toBe('16.0 GiB');
    expect(projectLocalObservation('inventory', inventory)).toEqual({
      status:'OBSERVED', metrics: [
        {key:'cpu',value:'8'}, {key:'memory',value:'8.0 GiB / 16.0 GiB'},
        {key:'storage',value:'50.0 GiB / 100.0 GiB'}
      ], counts:[], signals:[],
    });
  });
  it('refuses a fabricated source, incorrect schema, unsafe bytes or added disclosures', () => {
    expect(projectLocalObservation('inventory',{...inventory,source:'DEMO'}).status).toBe('REFUSED');
    expect(projectLocalObservation('inventory',{...inventory,snapshot:{...base,memoryFreeBytes:-1}}).status).toBe('REFUSED');
    expect(projectLocalObservation('inventory',{...inventory,externalDisclosures:['cloud']}).status).toBe('REFUSED');
    expect(projectLocalObservation('inventory',{...inventory,snapshot:{...base,platform:'linux'}}).status).toBe('REFUSED');
    expect(projectLocalObservation('foo',inventory).status).toBe('REFUSED');
  });
  it('projects approved diagnostic signals only, with no input-derived scripts or paths', () => {
    const result = projectLocalObservation('diagnosis', diagnosis);
    expect(result.status).toBe('OBSERVED');
    if (result.status === 'OBSERVED') {
      expect(result.signals).toEqual(['LOW_FREE_MEMORY']);
      expect(result.counts).toEqual([
        {key:'processes',value:'83'}, {key:'startup',value:'9'}
      ]);
      expect(JSON.stringify(result)).not.toContain('REVIEW_APPLICATIONS');
    }
    expect(projectLocalObservation('diagnosis',{
      ...diagnosis,report:{...diagnosis.report,signals:['DELETE_FILES']}
    }).status).toBe('REFUSED');
    expect(projectLocalObservation('diagnosis',{...diagnosis,cloudCalls:1}).status).toBe('REFUSED');
  });
  it('only shows a genuine Host-authorized, immutable R0 Recipe observation',()=>{
    const valid={ok:true,status:'VERIFIED_READONLY_OBSERVATION',recipeExecuted:true,
      modelCalls:0,externalDisclosures:[],recipeId:'shun.builtin.system-inventory.readonly.v02',
      revisionSha256:'a'.repeat(64),planHash:'b'.repeat(64),snapshot:base};
    expect(projectRoutineExecution(valid).status).toBe('OBSERVED');
    expect(projectRoutineExecution({...valid,recipeExecuted:false}).status).toBe('REFUSED');
    expect(projectRoutineExecution({...valid,externalDisclosures:['somewhere']}).status).toBe('REFUSED');
    expect(projectRoutineExecution({...valid,snapshot:{...base,platform:'linux'}}).status).toBe('REFUSED');
  });
  it('requires verifiable immutable built-in recipe metadata before offering to run',()=>{
    const good={ok:true,saved:true,state:'PERSISTED_CANDIDATE_ONLY',
      recipeId:'shun.builtin.system-inventory.readonly.v02',
      revisionSha256:'a'.repeat(64),executionAuthorized:false,modelCalls:0};
    expect(projectRoutineState(good)).toEqual({status:'OBSERVED',saved:true});
    expect(projectRoutineState({...good,executionAuthorized:true}).status).toBe('REFUSED');
    expect(projectRoutineState({...good,revisionSha256:'invalid'}).status).toBe('REFUSED');
    expect(projectRoutineState({...good,recipeId:'user-generated'}).status).toBe('REFUSED');
    expect(projectRoutineState({...good,saved:false,state:'NOT_SAVED',revisionSha256:null}))
      .toEqual({status:'OBSERVED',saved:false});
  });
});
