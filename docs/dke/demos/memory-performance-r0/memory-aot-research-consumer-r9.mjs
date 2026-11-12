import {validateMemoryAotCandidate} from './memory-aot-integrity.mjs';

const RULE_IDS=Object.freeze(Array.from({length:6},(_,i)=>'MEM-DEC-'+String(i+1).padStart(3,'0')));
function unknown(code){return {schema:'shun.demo.memory-aot-research-consumption.r9',outcome:'UNKNOWN',code,
 decisionRulesEvaluated:[],matchedDecisionRuleIds:[],sourceRulesApplied:[],effectsAuthorized:false,
 productionAotExecuted:false,disFunctionInvoked:false,hostProvenance:'NOT_ESTABLISHED_BY_RESEARCH_CONSUMER',
 sapQualification:'NOT_QUALIFIED',externalDisclosures:[]};}
function safe(report){return report?.schema==='shun.demo.memory-performance-report.v0' &&
 report.outcome==='OBSERVED_ONLY' && report.privacy?.localOnly===true &&
 Array.isArray(report.privacy.externalDisclosures)&&report.privacy.externalDisclosures.length===0&&
 report.source?.processMetric==='RESIDENT_MEMORY_BYTES_AT_SNAPSHOT'&&
 report.source?.aotRuleConsumption==='NOT_APPLIED_BY_THIS_DEMO'&&
 Array.isArray(report.source.aotRuleIds)&&report.source.aotRuleIds.length===0&&
 ['LOW_FREE_MEMORY_LEGACY_HEURISTIC','NO_LEGACY_LOW_FREE_MEMORY_SIGNAL'].includes(report.diagnosis?.status)&&
 report.diagnosis.rootCause==='UNKNOWN'&&Array.isArray(report.evidence?.topResidentProcesses)&&
 Array.isArray(report.diagnosis?.missingMetrics)&&report.optimizationPlan?.status==='ADVISORY_ONLY'&&
 report.optimizationPlan.effectsAuthorized===false&&report.optimizationPlan.executed===false&&
 report.verification?.speedupClaim==='NONE'&&report.verification.improvementComparison===
 'UNKNOWN_UNTIL_TRUSTED_COMPARABLE_WORKLOAD_AND_USER_OUTCOME_METRIC';}
// Predicate engine has no effects and grants no authority, even for forged inputs.
// This export allows isolated tests; ONLY the pinned wrapper authenticates the AOT source bytes.
export function evaluateResearchRulePredicates(decisionRules,report,options={}){
 if(!Array.isArray(decisionRules)||decisionRules.length!==6||
 decisionRules.some((r,i)=>r?.id!==RULE_IDS[i])||!safe(report))return unknown('UNQUALIFIED_OR_INVALID_RESEARCH_INPUT');
 const low=report.diagnosis.status==='LOW_FREE_MEMORY_LEGACY_HEURISTIC';
 const checks=[low,!low,report.evidence.topResidentProcesses.length>0,
 report.diagnosis.missingMetrics.length>0,options.userGoal==='OPTIMIZE_MEMORY',true];
 const evaluated=decisionRules.map((r,i)=>({id:r.id,matched:checks[i],status:'AUTHOR_CANDIDATE_POLICY_ONLY'}));
 return {schema:'shun.demo.memory-aot-research-consumption.r9',outcome:'ADVISORY_ONLY',
 source:'UNVERIFIED_PREDICATE_TEST_UNTIL_PINNED_WRAPPER',decisionRulesEvaluated:evaluated,
 matchedDecisionRuleIds:evaluated.filter(x=>x.matched).map(x=>x.id),sourceRulesApplied:[],
 effectsAuthorized:false,productionAotExecuted:false,disFunctionInvoked:false,
 hostProvenance:'NOT_ESTABLISHED_BY_RESEARCH_CONSUMER',sapQualification:'NOT_QUALIFIED',
 externalDisclosures:[],measuredSpeedup:'UNKNOWN'};}
export function consumePinnedResearchAot(rawCandidate,report,options={}){
 const proof=validateMemoryAotCandidate(rawCandidate);if(!proof.ok)return unknown(proof.code);
 let candidate;try{candidate=JSON.parse(rawCandidate);}catch{return unknown('AOT_INVALID_JSON');}
 const r=evaluateResearchRulePredicates(candidate.decisionRules,report,options);
 if(r.outcome!=='ADVISORY_ONLY')return r;
 return {...r,source:'EXACT_PINNED_AOT_CANDIDATE_DECISION_RULES',sourceGitBlob:proof.gitBlob,
 researchDecisionRuleConsumption:'EXECUTED_IN_RESEARCH_RUNTIME_ONLY'};}

// UNKNOWN reports (or unpinned predicate-only tests) cannot claim that rules ran.
export function researchAotConsumptionLabel(evaluation) {
 return evaluation?.outcome==='ADVISORY_ONLY' &&
   evaluation.researchDecisionRuleConsumption==='EXECUTED_IN_RESEARCH_RUNTIME_ONLY'
   ? 'RESEARCH_DECISION_RULES_EVALUATED_NOT_PRODUCTION_AOT'
   : 'NO_RESEARCH_RULES_EVALUATED_UNKNOWN';
}
