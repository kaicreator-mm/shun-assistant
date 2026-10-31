import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { composeTrustedRuntimeBuild } from '../../../../packages/domain-app/src/activation/trusted-build.ts';
import { activatePublicShunDomainApp } from '../../../../packages/domain-app/src/activation/public-sdk.ts';
import type { V10ModuleInput } from '../../../../packages/domain-app/src/build/composition.ts';
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');

const roles=['kernel-primary','standard-primary','business','capability'];
function modules() {
  return roles.map((role,i)=>{
    const src='export const MODULE_ID="package:'+i+'";\\n'.repeat(4);
    return {module: {
      packageId:'package:'+i, role, abiVersion:'v08-'+role+'-abi/1',
      moduleSource:src, moduleSha256:sha(src), endpoint:'./index.js',
    } satisfies V10ModuleInput, approvedSha256:sha(src)};
  });
}
function input() {
  return {
    appId:'app:test', audience:'aud:test', buildId:'r02', targetProfile:'node24-esm/1',
    modules:modules(),
    routes:[{intentId:'goal-interpret',operationId:'interpretGoal',
      capabilityId:'cap:llm',handlerId:'interpretGoal'}],
    hardBudget:{maxStepsPerTurn:4,maxWorkUnitsPerTurn:8},
  };
}
describe('R02-A public SDK production source gates',()=>{
  it('Shun B owns one K-governed non-idempotent external LLM effect', async()=>{
    const business = await import(
      '../../../../packages/domain-app/src/activation/modules/business-goal.mjs'
    );
    const policy = business.getPolicy();
    expect(policy.packageId).toBe(business.MODULE_ID);
    expect(policy.intentBindings['goal-interpret'].roles).toEqual(['requester']);
    const effect = policy.effectBindings['effect:goal-interpret'];
    expect(effect.semantics).toBe('non-idempotent');
    expect(effect.external.await).toBe('terminal');
    expect(effect.resource).toEqual({key:'llm',operation:'interpretGoal'});
    expect(typeof effect.handler).toBe('function');
  });

  it('rejects placeholder K, missing real source and wrong source digest',()=>{
    const original=input();
    const badSource={...original,modules:original.modules.map((m,i)=>i===0?
      {...m,module:{...m.module,moduleSource:'throw new Error("K_EFFECT_BINDING_REQUIRED_AT_ACTIVATION");',
      moduleSha256:sha('throw new Error("K_EFFECT_BINDING_REQUIRED_AT_ACTIVATION");')},
      approvedSha256:sha('throw new Error("K_EFFECT_BINDING_REQUIRED_AT_ACTIVATION");')}:m)};
    expect(composeTrustedRuntimeBuild(badSource).status).toBe('REFUSED');
    expect(composeTrustedRuntimeBuild({...original,modules:original.modules.slice(1)}).status).toBe('REFUSED');
    expect(composeTrustedRuntimeBuild({...original,modules:original.modules.map((m,i)=>i===2?
      {...m,approvedSha256:'0'.repeat(64)}:m)}).status).toBe('REFUSED');
    expect(composeTrustedRuntimeBuild({...original,targetProfile:'node22-esm/1'}).status).toBe('REFUSED');
  });

  it('refuses a fake SDK facade even if BUILD has a digest', async()=>{
    const prepared=composeTrustedRuntimeBuild(input());
    expect(prepared.status).toBe('READY_FOR_PUBLIC_SDK_BUILD');
    if(prepared.status!=='READY_FOR_PUBLIC_SDK_BUILD')return;
    await expect(activatePublicShunDomainApp({
      sdk:{
        buildV10App:(opts)=>({subjectDigest:'f'.repeat(64),modules:opts.modules}),
        activateV10App:async()=>({facade:{ send:undefined },dispose(){}}),
      },
      buildOptions:prepared.options,
      host:{
        store:{},tenantId:'tenant:test',now:Date.now,
        deploymentIdentity:{deployedAppId:'deploy:test',tenantId:'tenant:test',appId:'app:test'},
        queryAuthority:{}, deploymentRoot:'C:/Shun',
      },
    })).rejects.toThrow('V03_PUBLIC_SDK_ACTIVATION_REFUSED');
  });
});
