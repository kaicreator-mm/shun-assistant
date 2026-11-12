// DKE-only semantic challenge fixture evaluator.
// A deterministic counterexample detector, not a source-of-truth semantic oracle.
const DECISIONS = Object.freeze(["SUPPORTED","REFUTED","UNKNOWN"]);
function result(x){if(!DECISIONS.includes(x))throw Error("invalid evaluator decision");return x;}
export function evaluateFixture(kind,x){
 if(!x||typeof x!=="object")return "UNKNOWN";
 switch(kind){
 case "metric-separation":
   if(x.metric==="WorkingSet64"&&x.interpretation==="PRIVATE_BYTES")return "REFUTED";
   return x.metric==="WorkingSet64"&&x.interpretation==="RESIDENT_WORKING_SET"&&x.source==="SOURCE_PINNED"?"SUPPORTED":"UNKNOWN";
 case "memory-pressure":
   if(x.conclusion==="CONFIRMED_ROOT_CAUSE"&&(x.observations<2||!x.commit||!x.paging||!x.workload))return "REFUTED";
   return x.observations>=3&&x.available&&x.commit&&x.paging&&x.workload&&x.conclusion==="POTENTIAL_PRESSURE"?"SUPPORTED":"UNKNOWN";
 case "process-ranking":
   if(x.action==="KILL"||x.attribution==="SAFE_TO_KILL"||x.attribution==="ROOT_CAUSE")return "REFUTED";
   return x.metric==="WORKING_SET"&&x.ranking===true&&x.attribution==="RANKING_ONLY"&&x.action==="NONE"?"SUPPORTED":"UNKNOWN";
 case "leak-hypothesis":
   if(x.conclusion==="CONFIRMED_LEAK"&&(!x.stableProcessInstance||x.privateCommitSeries<3||!x.sameWorkload))return "REFUTED";
   return x.stableProcessInstance===true&&x.privateCommitSeries>=3&&x.sameWorkload===true&&x.idleRecoveryObserved===true&&x.conclusion==="SUSPECTED_ONLY"?"SUPPORTED":"UNKNOWN";
 case "cache-standby":
   if(x.action==="CLEAR_BY_DEFAULT"||x.action==="TRIM_ALL")return "REFUTED";
   return x.cacheType==="STANDBY"&&x.action==="EXPLAIN_NO_EFFECT"?"SUPPORTED":"UNKNOWN";
 case "effect-authorization":
   if(x.productAdmission!==true&&x.effect!=="NONE")return "REFUTED";
   return x.productAdmission===false&&x.effect==="NONE"&&x.planRisks===true&&x.planEvidence===true?"SUPPORTED":"UNKNOWN";
 case "performance-comparison":
   if(x.conclusion==="SPEEDUP_PROVED"&&(!x.independentComparator||!x.userOutcome))return "REFUTED";
   return x.conclusion==="NO_SPEEDUP_CLAIM"&&x.independentComparator===false&&x.userOutcome===false?"SUPPORTED":"UNKNOWN";
 case "hardware-upgrade":
   if(x.conclusion==="UPGRADE_COMPATIBLE"&&(!x.exactModel||!x.oemCompatibility||!x.sustainedDemand))return "REFUTED";
   return x.conclusion==="ADVICE_CANDIDATE"&&x.exactModel&&x.oemCompatibility&&x.sustainedDemand?"SUPPORTED":"UNKNOWN";
 case "privacy-minimization":
   if(x.rawCommandLine===true||x.localOnly===false||x.noAutomaticEgress===false)return "REFUTED";
   return x.localOnly===true&&x.redaction===true&&x.noAutomaticEgress===true&&x.rawCommandLine===false?"SUPPORTED":"UNKNOWN";
 case "api-unknown":
   if(x.reportedAs==="PrivateUsage"&&(!x.osApplicabilityVerified||!x.apiAvailable||x.metric==="WorkingSet64"))return "REFUTED";
   return x.osApplicabilityVerified===true&&x.apiAvailable===true&&x.metric==="PrivateUsage"&&x.reportedAs==="PRIVATE_COMMIT"?"SUPPORTED":"UNKNOWN";
 case "aot-boundary":
   if(x.liveFacts===true||x.permissions===true)return "REFUTED";
   return x.sourcePinned===true&&x.stableSemantics===true&&x.liveFacts===false&&x.permissions===false?"SUPPORTED":"UNKNOWN";
 case "ex2-availability":
   if(x.reportedAs==="PRIVATE_RESIDENT"&&(!x.osBuildVerified||!x.ex2Supported||x.field!=="PrivateWorkingSetSize"))return "REFUTED";
   return x.osBuildVerified===true&&x.ex2Supported===true&&x.field==="PrivateWorkingSetSize"&&x.reportedAs==="PRIVATE_RESIDENT"?"SUPPORTED":"UNKNOWN";
 case "counter-cadence":
   if(x.conclusion==="CONFIRMED_LEAK_BY_NAME"||typeof x.sampleIntervalMs==="number"&&x.sampleIntervalMs<1000&&x.conclusion!=="UNKNOWN")return "REFUTED";
   return typeof x.sampleIntervalMs==="number"&&x.sampleIntervalMs>=1000&&x.stableInstanceKey===true&&x.conclusion==="DIAGNOSTIC_TREND_CANDIDATE"?"SUPPORTED":"UNKNOWN";
 case "fault-counter":
   if(x.counter==="PageFaultCount"&&x.claim==="HARD_FAULTS_PER_SECOND")return "REFUTED";
   return x.counter==="PageFaultCount"&&x.unit==="CUMULATIVE"&&x.claim==="CUMULATIVE_ONLY"?"SUPPORTED":"UNKNOWN";
 case "reference-set":
   if(x.claim==="SAFE_PASSIVE_INSTANT_READING"||x.claim==="SCENARIO_REFERENCE_SET_CANDIDATE"&&(!x.scenarioBound||!x.explicitConsent||!x.overheadDisclosed))return "REFUTED";
   return x.scenarioBound===true&&x.explicitConsent===true&&x.overheadDisclosed===true&&x.claim==="SCENARIO_REFERENCE_SET_CANDIDATE"?"SUPPORTED":"UNKNOWN";
 case "sample-timestamp":
   if(x.claim==="HOST_SAMPLED_AT_VERIFIED"&&x.hostSampledAtVerified!==true)return "REFUTED";
   return x.analyzedAtKnown===true&&x.hostSampledAtVerified===false&&x.sampledAt==="UNKNOWN"&&x.claim==="PROCESSING_TIMESTAMP_ONLY"?"SUPPORTED":"UNKNOWN";
 default:throw Error("UNREGISTERED_ORACLE_KIND:"+String(kind));
 }
}
function refArray(row,field){return Array.isArray(row?.[field])?row[field]:[];}
function intersections(a,b){return a.some(x=>b.has(x));}
const sort=x=>[...x].sort();
export function impactSource(sourceId,base,extension,delta,aot,handoff) {
 const allClaims=[...extension.claims,...delta.claims];
 const allCqs=[...extension.competencyQuestions,...delta.competencyQuestions];
 const allRelations=extension.relations;
 const allInvariants=extension.invariants;
 const allSap=[...extension.semanticAssuranceProfiles.flatMap(p=>p.obligations),...delta.sapObligations];
 const known=new Set([...base.sourceInventory,...base.externalSources,...extension.externalSources,...delta.sources].map(s=>s.id));
 if(!known.has(sourceId))return {sourceId,sourceState:"UNREGISTERED_SOURCE",claims:[],cqs:[],relations:[],invariants:[],sapObligations:[],aotRules:[],elements:[],functions:[],qualification:"HOLD_SOURCE_OWNER_DECISION"};
 const claims=new Set(allClaims.filter(x=>refArray(x,"sourceRefs").concat(refArray(x,"sources")).includes(sourceId)).map(x=>x.id));
 const cqs=new Set(allCqs.filter(x=>refArray(x,"sourceRefs").includes(sourceId)).map(x=>x.id));
 const relations=new Set(allRelations.filter(x=>refArray(x,"sourceRefs").includes(sourceId)).map(x=>x.id));
 const invariants=new Set(allInvariants.filter(x=>refArray(x,"sourceRefs").includes(sourceId)).map(x=>x.id));
 const sapObligations=new Set(allSap.filter(x=>{
  const c=refArray(x,"sourceRefs");const direct=c.includes(sourceId);
  return direct||intersections(refArray(x,"claimRefs"),claims)||intersections(refArray(x,"cqRefs"),cqs)||
   intersections(refArray(x,"relationRefs"),relations)||intersections(refArray(x,"invariantRefs").concat(refArray(x,"globalInvariantRefs")),invariants);
 }).map(x=>x.id));
 const aotRules=new Set(aot.sourceRules.filter(x=>x.sourceRefs.includes(sourceId)).map(x=>x.id));
 const elements=new Set();
 for(const c of allClaims)if(claims.has(c.id)&&c.semanticOwner||claims.has(c.id)&&c.owner)elements.add(c.semanticOwner||c.owner);
 for(const q of allCqs)if(cqs.has(q.id))elements.add(q.element);
 for(const p of extension.semanticAssuranceProfiles)if(p.obligations.some(x=>sapObligations.has(x.id)))elements.add(p.element);
 for(const o of delta.sapObligations)if(sapObligations.has(o.id))elements.add(o.owner);
 const functions=new Set(handoff.functionDependencies.filter(x=>intersections(x.dependencyObligations,sapObligations)).map(x=>x.id));
 return {sourceId,sourceState:"REGISTERED_SOURCE",claims:sort(claims),cqs:sort(cqs),relations:sort(relations),invariants:sort(invariants),sapObligations:sort(sapObligations),aotRules:sort(aotRules),elements:sort(elements),functions:sort(functions),qualification:"REVIEW_REQUIRED_NO_AUTOMATIC_PASS"};
}
export function validateOraclePack(pack,extension,delta){
 const errors=[];
 const cqSet=new Set([...extension.competencyQuestions,...delta.competencyQuestions].map(x=>x.id));
 const expectedCqIds=[...cqSet].filter(id=>/^CQ-CA-0(2[1-9]|3[0-6])$/.test(id));
 const seen=new Set();
 for(const oracle of pack.semanticCases){
  if(seen.has(oracle.cqId)||!cqSet.has(oracle.cqId))errors.push("DUPLICATE_OR_UNKNOWN_CQ:"+oracle.cqId);
  seen.add(oracle.cqId);
  if(oracle.cases.length!==3||new Set(oracle.cases.map(x=>x.polarity)).size!==3)errors.push("POLARITY_COVERAGE:"+oracle.cqId);
  for(const entry of oracle.cases){
   let actual;try{actual=evaluateFixture(oracle.kind,entry.input);}catch{actual="EVALUATOR_EXCEPTION";}
   if(entry.expected!==actual)errors.push("SEMANTIC_COUNTEREXAMPLE:"+oracle.cqId+":"+entry.polarity+":expected="+entry.expected+":actual="+actual);
  }
 }
 for(const id of expectedCqIds)if(!seen.has(id))errors.push("CQ_ORACLE_MISSING:"+id);
 if(pack.semanticCases.length!==16)errors.push("ORACLE_COUNT_MISMATCH");
 return {ok:!errors.length,errors,metrics:{cqs:seen.size,fixtures:pack.semanticCases.reduce((n,x)=>n+x.cases.length,0)}};
}
export function validateImpactBench(impactPack,base,extension,delta,aot,handoff) {
 const errors=[];
 for(const s of impactPack.reviewFixtures){
  const actual=impactSource(s.sourceId,base,extension,delta,aot,handoff);
  for(const [key,values] of Object.entries(s.mustInclude)){
   for(const v of values)if(!actual[key]?.includes(v))errors.push("MISSING_REVERSE_IMPACT:"+s.id+":"+key+":"+v);
  }
  for(const [key,values] of Object.entries(s.mustExclude)){
   for(const v of values)if(actual[key]?.includes(v))errors.push("UNBOUNDED_REVERSE_IMPACT:"+s.id+":"+key+":"+v);
  }
  if(s.kind==="UNRELATED_SOURCE_CHANGE"&&actual.sourceState!=="UNREGISTERED_SOURCE")errors.push("UNREGISTERED_SOURCE_FALSIFIED:"+s.id);
 }
 return {ok:!errors.length,errors,metrics:{sourceChangeFixtures:impactPack.reviewFixtures.length}};
}
