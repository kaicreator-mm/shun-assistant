import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateResearchRulePredicates,consumePinnedResearchAot} from './memory-aot-research-consumer-r9.mjs';
const rules=Array.from({length:6},(_,i)=>({id:'MEM-DEC-'+String(i+1).padStart(3,'0')}));
function report(status='LOW_FREE_MEMORY_LEGACY_HEURISTIC'){return {
 schema:'shun.demo.memory-performance-report.v0',outcome:'OBSERVED_ONLY',
 privacy:{localOnly:true,externalDisclosures:[]},
 source:{processMetric:'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT',aotRuleIds:[],aotRuleConsumption:'NOT_APPLIED_BY_THIS_DEMO'},
 diagnosis:{status,rootCause:'UNKNOWN',missingMetrics:['SYSTEM_COMMIT_BYTES']},
 evidence:{topResidentProcesses:[{rank:1,localAlias:'PROCESS_01',residentWorkingSetBytes:1024}]},
 optimizationPlan:{status:'ADVISORY_ONLY',effectsAuthorized:false,executed:false},
 verification:{speedupClaim:'NONE',improvementComparison:'UNKNOWN_UNTIL_TRUSTED_COMPARABLE_WORKLOAD_AND_USER_OUTCOME_METRIC'}};}
test('low signal executes matching research predicates, never claims production AOT',()=>{
 const r=evaluateResearchRulePredicates(rules,report());
 assert.equal(r.outcome,'ADVISORY_ONLY');
 assert.deepEqual(r.matchedDecisionRuleIds,['MEM-DEC-001','MEM-DEC-003','MEM-DEC-004','MEM-DEC-006']);
 assert.equal(r.decisionRulesEvaluated.length,6);assert.deepEqual(r.sourceRulesApplied,[]);
 assert.equal(r.productionAotExecuted,false);assert.equal(r.effectsAuthorized,false);});
test('no low signal is distinct, never healthy/speedup inference',()=>{
 const r=evaluateResearchRulePredicates(rules,report('NO_LEGACY_LOW_FREE_MEMORY_SIGNAL'));
 assert.equal(r.matchedDecisionRuleIds.includes('MEM-DEC-002'),true);
 assert.equal(r.matchedDecisionRuleIds.includes('MEM-DEC-001'),false);assert.equal(r.measuredSpeedup,'UNKNOWN');});
test('request-to-optimize rule only matches explicit intent; still no effects',()=>{
 assert.equal(evaluateResearchRulePredicates(rules,report()).matchedDecisionRuleIds.includes('MEM-DEC-005'),false);
 const r=evaluateResearchRulePredicates(rules,report(),{userGoal:'OPTIMIZE_MEMORY'});
 assert.equal(r.matchedDecisionRuleIds.includes('MEM-DEC-005'),true);assert.equal(r.effectsAuthorized,false);});
test('forged outcome, Host, permission, privacy, or speedup fails closed',()=>{
 for(const patch of [{outcome:'UNKNOWN'},
 {privacy:{localOnly:false,externalDisclosures:['https://example.invalid']}},
 {optimizationPlan:{status:'APPLIED',effectsAuthorized:true,executed:true}},
 {diagnosis:{status:'OPTIMIZED',rootCause:'BROWSER',missingMetrics:[]}},
 {source:{processMetric:'PRIVATE_BYTES',aotRuleConsumption:'APPLIED',aotRuleIds:['MEM-AOT-001']}},
 {verification:{speedupClaim:'20%',improvementComparison:'TRUSTED'}}]){
  const r=evaluateResearchRulePredicates(rules,{...report(),...patch});
  assert.equal(r.outcome,'UNKNOWN');assert.equal(r.effectsAuthorized,false);assert.deepEqual(r.matchedDecisionRuleIds,[]);
 }});
test('unknown, duplicate, or missing decision ids fail closed',()=>{
 for(const bad of [rules.slice(0,5),[...rules.slice(0,5),rules[4]],[{id:'MALICIOUS'},...rules.slice(1)]])
  assert.equal(evaluateResearchRulePredicates(bad,report()).outcome,'UNKNOWN');});
test('unverified AOT raw data can never issue an execution receipt',()=>{
 const r=consumePinnedResearchAot('{',report());assert.equal(r.outcome,'UNKNOWN');
 assert.equal(r.productionAotExecuted,false);assert.equal(r.disFunctionInvoked,false);
 assert.deepEqual(r.decisionRulesEvaluated,[]);});
test('report label refuses rule execution on unknown or unpinned predicates',async()=>{
 const {researchAotConsumptionLabel}=await import('./memory-aot-research-consumer-r9.mjs');
 assert.equal(researchAotConsumptionLabel({outcome:'UNKNOWN'}),'NO_RESEARCH_RULES_EVALUATED_UNKNOWN');
 assert.equal(researchAotConsumptionLabel({outcome:'ADVISORY_ONLY'}),'NO_RESEARCH_RULES_EVALUATED_UNKNOWN');
 assert.equal(researchAotConsumptionLabel({outcome:'ADVISORY_ONLY',researchDecisionRuleConsumption:'EXECUTED_IN_RESEARCH_RUNTIME_ONLY'}),
  'RESEARCH_DECISION_RULES_EVALUATED_NOT_PRODUCTION_AOT');
});
