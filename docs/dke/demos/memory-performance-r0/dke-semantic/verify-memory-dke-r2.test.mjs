import test from 'node:test';
import assert from 'node:assert/strict';
import {validateArtifacts,readArtifacts} from './verify-memory-dke-r2.mjs';
import {evaluateFixture,impactSource} from './memory-dke-evaluator-r2.mjs';

const fresh=()=>Object.fromEntries(Object.entries(readArtifacts()).map(([k,v])=>[k,v]));
const parse=content=>Object.fromEntries(Object.entries(content).map(([k,v])=>[k,JSON.parse(v)]));
const edit=(raw,key,cb)=>{const j=JSON.parse(raw[key]);cb(j);raw[key]=JSON.stringify(j,null,2)+'\n';};
const rejects=(raw,reason)=>{
 const r=validateArtifacts(raw);
 assert.equal(r.ok,false,'must reject tamper');
 assert.ok(r.errors.some(e=>e.startsWith(reason)),JSON.stringify(r.errors));
};

test('R2 source-pinned DKE fixture, evolution and handoff validators close mechanically',()=>{
 const r=validateArtifacts(fresh());
 assert.equal(r.ok,true,JSON.stringify(r.errors));
 assert.deepEqual([r.metrics.totalScopedCqs,r.metrics.semanticFixtures,r.metrics.evolutionScenarios],[16,48,7]);
 assert.equal(r.metrics.eligibleForSap,false);
 assert.equal(r.metrics.eligibleForDisHandoff,false);
});

test('semantic challenger exercises all 48 positive, negative and UNKNOWN cases',()=>{
 const j=parse(fresh());
 let n=0;
 for(const item of j.oracles.semanticCases){
  assert.deepEqual(item.cases.map(x=>x.polarity),['POSITIVE','NEGATIVE','UNKNOWN']);
  for(const row of item.cases){
   assert.equal(evaluateFixture(item.kind,row.input),row.expected,item.id+':'+row.polarity);
   n++;
  }
 }
 assert.equal(n,48);
});

test('counterexample injection cannot silently preserve semantic fixture success',()=>{
 const j=parse(fresh());
 const x=j.oracles.semanticCases.find(x=>x.kind==='metric-separation');
 const neg=x.cases.find(x=>x.polarity==='NEGATIVE');
 neg.expected='SUPPORTED';
 assert.equal(evaluateFixture(x.kind,neg.input),'REFUTED');
});

test('paired candidate + source edits fail exact data-lock even with self-described version',()=>{
 const j=fresh();
 edit(j,'delta',x=>x.claims[0].statement='WorkingSet64 always equals Private Bytes');
 rejects(j,'PIN_MISMATCH:delta');
});

test('changing oracle expected verdict is detected by independent file hash',()=>{
 const j=fresh();
 edit(j,'oracles',x=>x.semanticCases[0].cases[1].expected='SUPPORTED');
 rejects(j,'PIN_MISMATCH:oracles');
});

test('DIS Gate A or B cannot be advanced from candidate fixtures',()=>{
 const j=fresh();
 edit(j,'handoff',x=>{x.gates.gateA.status='PASS';x.status='QUALIFIED';});
 rejects(j,'PIN_MISMATCH:handoff');
});

test('declaring R2 AOT production consumption is rejected',()=>{
 const j=fresh();
 edit(j,'handoff',x=>{x.aot.r2NewKnowledgeLoadedByCurrentRuntime=true;});
 rejects(j,'PIN_MISMATCH:handoff');
});

test('source mutation activates only justified reverse impact; unrelated stays bounded',()=>{
 const j=parse(fresh());
 const ex2=impactSource('EXT-MEM-PROCESS-COUNTERS-EX2',j.knowledge,j.extension,j.delta,j.aot,j.handoff);
 assert.ok(ex2.claims.includes('CA-CLM-025'));
 assert.ok(ex2.sapObligations.includes('SAP-CA-MEMORY-PERFORMANCE-09'));
 assert.ok(!ex2.aotRules.includes('MEM-AOT-001'));
 assert.ok(!ex2.functions.includes('computer.memory.plan'));
 const unrelated=impactSource('SRC-UNRELATED-THIRD-PARTY',j.knowledge,j.extension,j.delta,j.aot,j.handoff);
 assert.equal(unrelated.sourceState,'UNREGISTERED_SOURCE');
 assert.equal(unrelated.sapObligations.length,0);
});

test('unexpected negative fact cannot be blessed as normal cache optimization',()=>{
 const outcome=evaluateFixture('cache-standby',{cacheType:'STANDBY',action:'CLEAR_BY_DEFAULT'});
 assert.equal(outcome,'REFUTED');
});

test('untrusted process timestamps or candidate proof never upgrade memory leak',()=>{
 assert.equal(evaluateFixture('leak-hypothesis',{stableProcessInstance:false,privateCommitSeries:1,sameWorkload:false,idleRecoveryObserved:false,conclusion:'CONFIRMED_LEAK'}),'REFUTED');
 assert.equal(evaluateFixture('sample-timestamp',{analyzedAtKnown:true,hostSampledAtVerified:false,sampledAt:'2099-01-01',claim:'HOST_SAMPLED_AT_VERIFIED'}),'REFUTED');
});
