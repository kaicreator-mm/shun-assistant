// Source-first DKE R2 evidence checker.  Checks mechanically demonstrable
// contracts/fixtures only; does NOT certify semantic truth or SAP qualification.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {validateOraclePack,validateImpactBench,evaluateFixture,impactSource} from './memory-dke-evaluator-r2.mjs';

const root=dirname(fileURLToPath(import.meta.url));
const memoryRoot=resolve(root,'../..');
export const PINS=Object.freeze({
 knowledge:'c877ec23dc59b0ae17681c7d8f7505b1521c8011',
 demand:'74c10245e88608d12ae716bd2bae1623a2f55dc5',
 extension:'8d0c1c0e732cb7e9183ca830a0384798946b43a6',
 aot:'e5bf93668066be5c76148c1a4cbdd930dcf55c29',
 delta:'fddd2d9cbe9a342683eefdcabe2277dac012568c',
 oracles:'7097a1891589b6970ecd99bf00d71ec3b36bcf1c',
 evolution:'5ce9972f81e77f61a405ca8edc5f9270a180f9cd',
 handoff:'ac6e9965a4060885367dcc7b0ec16767d89c46c6'
});
function blob(text) {
 const b=Buffer.from(text,'utf8');
 return createHash('sha1').update(Buffer.from('blob '+b.length+'\0')).update(b).digest('hex');
}
const expectedPaths={
 knowledge:resolve(memoryRoot,'implementation/COMPUTER_ASSISTANT_KNOWLEDGE_R0.json'),
 demand:resolve(memoryRoot,'implementation/DEMAND_TO_FUNCTION_CLOSURE_R0.json'),
 extension:resolve(memoryRoot,'implementation/PERFORMANCE_MEMORY_EXTENSION_R0.json'),
 aot:resolve(root,'../AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json'),
 delta:resolve(root,'SOURCE_FIRST_KNOWLEDGE_DELTA_R2.json'),
 oracles:resolve(root,'SEMANTIC_ORACLES_R2.json'),
 evolution:resolve(root,'EVOLUTION_IMPACT_R2.json'),
 handoff:resolve(root,'DKE_TO_DIS_HANDOFF_R2.json')
};
function unknownRefs(refs,set) {return refs.filter(x=>!set.has(x));}
function refs(x,key){return Array.isArray(x?.[key])?x[key]:[];}
export function validateArtifacts(contents){
 const errors=[];
 const add=(ok,name)=>{if(!ok)errors.push(name);};
 for(const [name,pin] of Object.entries(PINS)){
  add(typeof contents[name]==='string'&&blob(contents[name])===pin,'PIN_MISMATCH:'+name);
 }
 // Parse only after SHA/shape checks; parse failure also fails closed.
 let j;
 try {j=Object.fromEntries(Object.entries(contents).map(([k,v])=>[k,JSON.parse(v)]));}
 catch {return {ok:false,errors:[...errors,'INVALID_JSON'],metrics:{}};}
 const {knowledge,extension,aot,delta,oracles,evolution,handoff}=j;
 const sourceIds=new Set([...knowledge.sourceInventory,...knowledge.externalSources,...extension.externalSources,...delta.sources].map(x=>x.id));
 const elementIds=new Set([...knowledge.elements,...extension.elements].map(x=>x.id));
 const cqIds=new Set([...extension.competencyQuestions,...delta.competencyQuestions].map(x=>x.id));
 const claimIds=new Set([...extension.claims,...delta.claims].map(x=>x.id));
 const sapIds=new Set([...extension.semanticAssuranceProfiles.flatMap(p=>p.obligations),...delta.sapObligations].map(x=>x.id));
 const sapProfileIds=new Set([...knowledge.semanticAssuranceProfile.elements,...extension.semanticAssuranceProfiles].map(x=>x.profileId));
 add(delta.status==='SOURCE_LINKED_AUTHOR_CANDIDATE','FALSE_DKE_QUALIFICATION');
 add(delta.claims.length===5&&delta.competencyQuestions.length===5&&delta.sapObligations.length===5,'DELTA_COVERAGE');
 add(oracles.semanticCases.length===16,'CQ_COVERAGE');
 add(delta.sources.every(x=>x.status==='OFFICIAL_URL_LOCATOR_NOT_IMMUTABLE_GIT_BLOB'&&x.url.startsWith('https://learn.microsoft.com/')),'UNVERIFIED_SOURCE_AUTHORITY');
 for(const c of delta.claims){
  add(elementIds.has(c.owner)&&unknownRefs(c.sources,sourceIds).length===0,'CLAIM_OWNER_OR_SOURCE:'+c.id);
  add(c.epistemic!=='QUALIFIED'&&c.id.startsWith('CA-CLM-'),'CLAIM_FALSE_PROMOTION:'+c.id);
 }
 for(const cq of delta.competencyQuestions){
  add(elementIds.has(cq.element)&&unknownRefs(cq.sourceRefs,sourceIds).length===0,'CQ_OWNER_OR_SOURCE:'+cq.id);
  add(cq.validationState==='NOT_RUN','CQ_FALSE_PROMOTION:'+cq.id);
 }
 for(const o of delta.sapObligations){
  add(sapProfileIds.has(o.profileId)&&elementIds.has(o.owner),'SAP_OWNER:'+o.id);
  add(unknownRefs(o.claimRefs,claimIds).length===0&&unknownRefs(o.cqRefs,cqIds).length===0&&unknownRefs(o.sourceRefs,sourceIds).length===0,'SAP_REFS:'+o.id);
  add(o.qualification==='NOT_QUALIFIED'&&o.validationState==='NOT_RUN'&&o.positive&&o.negative&&o.unknown,'SAP_FALSE_PROMOTION:'+o.id);
 }
 add(handoff.status==='BLOCKED_PENDING_INDEPENDENT_SEMANTIC_QUALIFICATION','HANDOFF_STATUS');
 add(handoff.gates.gateA.status==='BLOCKED'&&handoff.gates.gateB.status==='BLOCKED','UNAUTHORIZED_GATE_ADVANCEMENT');
 add(handoff.qualifications.dkeElements===0&&handoff.qualifications.sapObligationsQualified===0&&handoff.qualifications.productImplementationAuthorized===false,'QUALIFICATION_COUNT');
 add(handoff.aot.r2NewKnowledgeLoadedByCurrentRuntime===false,'R2_AOT_FALSE_CONSUMPTION');
 add(aot.productionConsumable===false&&aot.status==='DEMO_ONLY_CANDIDATE_NOT_QUALIFIED','AOT_PRODUCTION_FALSE_PROMOTION');
 for(const f of handoff.functionDependencies){
  add(refs(f,'dependencyObligations').length>0&&unknownRefs(f.dependencyObligations,sapIds).length===0,'DIS_DEPENDENCY_CLOSURE:'+f.id);
 }
 const oracleResult=validateOraclePack(oracles,extension,delta);
 const impactResult=validateImpactBench(evolution,knowledge,extension,delta,aot,handoff);
 errors.push(...oracleResult.errors,...impactResult.errors);
 return {ok:errors.length===0,errors,metrics:{
  newClaims:delta.claims.length,newCqs:delta.competencyQuestions.length,newSapObligations:delta.sapObligations.length,
  totalScopedCqs:oracleResult.metrics.cqs,semanticFixtures:oracleResult.metrics.fixtures,
  evolutionScenarios:impactResult.metrics.sourceChangeFixtures,
  disCandidates:handoff.functionDependencies.length,
  eligibleForSap:false,eligibleForDisHandoff:false,eligibleForProductionAot:false
 }};
}
export function readArtifacts(){
 return Object.fromEntries(Object.entries(expectedPaths).map(([k,v])=>[k,readFileSync(v,'utf8')]));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
 const result=validateArtifacts(readArtifacts());
 process.stdout.write(JSON.stringify({outputLabel:'SHUN_DKE_MEMORY_SEMANTIC_R2_VERIFICATION',...result},null,2)+'\n');
 if(!result.ok)process.exitCode=1;
 }catch{process.stdout.write(JSON.stringify({ok:false,status:'VALIDATOR_INPUT_OR_IO_ERROR'})+'\n');process.exitCode=1;}
}
