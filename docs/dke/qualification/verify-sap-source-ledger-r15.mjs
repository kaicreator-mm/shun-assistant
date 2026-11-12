/**
 * R15 source-first mechanical qualification intake gate.
 * This is NOT a qualified independent semantic Oracle, Product admission,
 * SAP/K5, ECP, AOT or native Windows evidence.
 */
import { createHash } from 'node:crypto';

export const SOURCE_BLOB_PINS = Object.freeze({
  knowledge: 'da8425d82f3725c10bce92d206bbb8adfd6e7169',
  memory: '8d0c1c0e732cb7e9183ca830a0384798946b43a6',
  r2: 'fddd2d9cbe9a342683eefdcabe2277dac012568c',
  packet: 'dc7a851e9b542809b5876940cb56fc7a79bbbed9',
  delegated: 'a6a1cb178b01fe3ee7fa0ec04d8250fd26b071eb',
});
export const EXPECTED_SAP = Object.freeze({base:58, memoryR0:12, memoryR2:5, total:75});
const NETWORK_POLICY_REFS = ['SRC-PRODUCT-FREEZE','SRC-PRODUCT-PRD','SRC-PRODUCT-L1'];

export function gitBlobId(bytes) {
  const raw=Buffer.isBuffer(bytes)?bytes:Buffer.from(bytes);
  return createHash('sha1').update(Buffer.from('blob '+raw.length+'\0')).update(raw).digest('hex');
}

const same = (a,b) => JSON.stringify(a)===JSON.stringify(b);
const refs = (x) => Array.isArray(x?.sourceRefs)?x.sourceRefs:null;
const hasTriplet = (x) => ['positive','negative','unknown'].every(k =>
  typeof x?.[k]?.expectedCase==='string' && x[k].expectedCase.trim().length>0 &&
  x[k].state==='NOT_EXECUTED');
function indexStrict(items,getId,label,fail) {
  const result=new Map();
  if(!Array.isArray(items)){fail(label+'_MISSING');return result;}
  for(const item of items) {
    const id=getId(item);
    if(typeof id!=='string'||!id||result.has(id)){fail(label+'_DUPLICATE_OR_EMPTY');continue;}
    result.set(id,item);
  }
  return result;
}

/** Validates a bounded source-scoped author handoff; never returns semantic PASS. */
export function validateSapSourceLedgerR15(input) {
  const errors=[];
  const fail=(code)=>{if(!errors.includes(code))errors.push(code);};
  const {knowledge,memory,r2,packet,delegated,rawKnowledge,rawMemory,rawR2,rawPacket,rawDelegated}=input||{};
  if(!knowledge||!memory||!r2||!packet||!delegated){fail('SOURCE_PACK_MISSING');return {ok:false,errors,qualifiedSap:0};}
  // Source handoff ledgers are also input evidence: original-byte-pinned, not
  // caller-generated lists that can silently rewrite rights, provenance or Oracles.
  const originalBytes={knowledge:rawKnowledge,memory:rawMemory,r2:rawR2,
    packet:rawPacket,delegated:rawDelegated};
  for(const [kind,expected] of Object.entries(SOURCE_BLOB_PINS)) {
    if(!originalBytes[kind]||gitBlobId(originalBytes[kind])!==expected)fail('SOURCE_BLOB_MISMATCH_'+kind.toUpperCase());
  }
  // Caller-provided parsed objects cannot drift from the exact pinned raw bytes.
  for(const [kind,object] of [['knowledge',knowledge],['memory',memory],['r2',r2],['packet',packet],['delegated',delegated]]) {
    try {
      if(!same(JSON.parse(originalBytes[kind].toString('utf8')),object))
        fail('SOURCE_OBJECT_BYTES_MISMATCH_'+kind.toUpperCase());
    } catch {
      fail('SOURCE_ORIGINAL_BYTES_UNPARSEABLE_'+kind.toUpperCase());
    }
  }
  const modelSources=[
    ...((knowledge.semanticAssuranceProfile?.elements)||[]).flatMap(x=>x.obligations||[]),
    ...((memory.semanticAssuranceProfiles)||[]).flatMap(x=>x.obligations||[]),
    ...(r2.sapObligations||[]),
  ];
  const count=[(knowledge.semanticAssuranceProfile?.elements||[]).reduce((n,p)=>n+(p.obligations||[]).length,0),
    (memory.semanticAssuranceProfiles||[]).reduce((n,p)=>n+(p.obligations||[]).length,0),
    (r2.sapObligations||[]).length];
  if(!same(count,[58,12,5]))fail('SOURCE_SAP_COUNT_DRIFT');
  const source=indexStrict(modelSources,x=>x?.id,'SOURCE_SAP',fail);
  const byPacket=indexStrict(packet.sapObligations,x=>x?.id,'PACKET_SAP',fail);
  const byOwner=indexStrict(delegated.rows,x=>x?.sapId,'DELEGATED_SAP',fail);
  if([source.size,byPacket.size,byOwner.size].some(n=>n!==EXPECTED_SAP.total))
    fail('SAP_COVERAGE_DRIFT');
  const external=indexStrict(delegated.externalPublisherSources,x=>x?.id,'EXTERNAL_PUBLISHER',fail);
  const knownSourceIds=indexStrict(packet.sourceCatalog,x=>x?.id,'SOURCE_CATALOG',fail);
  if(external.size!==24||knownSourceIds.size!==94)fail('SOURCE_CATALOG_COUNT_DRIFT');
  const gSource=[...(knowledge.globalInvariants||[]),...(memory.invariants||[])];
  const globals=indexStrict(gSource,x=>x?.id,'SOURCE_GLOBAL',fail);
  const pg=indexStrict(packet.globalInvariants,x=>x?.id,'PACKET_GLOBAL',fail);
  const dg=indexStrict(delegated.globalInvariants,x=>x?.globalId,'DELEGATED_GLOBAL',fail);
  if([globals.size,pg.size,dg.size].some(n=>n!==19))fail('GLOBAL_COVERAGE_DRIFT');
  for(const [id,original] of source) {
    const packetRow=byPacket.get(id),owner=byOwner.get(id),sourceList=refs(original);
    if(!packetRow||!owner){fail('SAP_MISSING_'+id);continue;}
    if(!sourceList || !same(sourceList,refs(packetRow)) || !same(sourceList,refs(owner)) ||
      new Set(sourceList).size!==sourceList.length)
      fail('SAP_SOURCE_REFERENCE_MISMATCH_'+id);
    if((sourceList||[]).some(s=>!knownSourceIds.has(s)))fail('UNKNOWN_SOURCE_REF_'+id);
    const actualExternal=(sourceList||[]).filter(s=>external.has(s));
    const listedExternal=(owner.externalPublisherRefs||[]).map(x=>x?.id);
    if(!same(actualExternal,listedExternal))fail('SAP_EXTERNAL_PUBLISHER_MISMATCH_'+id);
    const expectedCases = ['positiveCase','negativeCase','unknownCase'].map(
      (field) => original[field] ?? original[field.replace('Case','')]);
    if(!same(expectedCases,[
      packetRow.positive?.expectedCase,
      packetRow.negative?.expectedCase,
      packetRow.unknown?.expectedCase,
    ]) || !same(expectedCases,[
      owner.positive?.case, owner.negative?.case, owner.unknown?.case,
    ])) fail('SAP_CASE_SOURCE_MUTATION_'+id);
    if(packetRow.sapQualification!=='NOT_QUALIFIED' ||
      packetRow.ownerDecision!=='PENDING_NOT_ATTESTED' ||
      packetRow.independentOracle!=='NOT_RUN' || !hasTriplet(packetRow) ||
      owner.formalSapQualified!==false ||
      owner.sourceOwnerSourceSemanticQualification!=='NOT_ATTESTED' ||
      owner.independentDomainOracle!=='NOT_RUN' ||
      owner.projectOwnerDelegatedDecision!=='NARROW')
      fail('FALSE_SAP_OR_OWNER_QUALIFICATION_'+id);
  }
  for(const [id,original] of globals){
    const p=pg.get(id),d=dg.get(id);
    if(!p||!d || !same(refs(original),refs(p)) || !same(refs(original),refs(d)))
      fail('GLOBAL_SOURCE_MISMATCH_'+id);
    if(p?.qualification!=='NOT_QUALIFIED'||d?.formalGlobalQualified!==false||
      d?.sourceOwnerAttested!==false||d?.independentDomainOracle!=='NOT_RUN')
      fail('FALSE_GLOBAL_QUALIFICATION_'+id);
  }
  const network=['SAP-CA-NETWORK-01','SAP-CA-NETWORK-02','SAP-CA-NETWORK-03'];
  for(const id of network) {
    const s=source.get(id),p=byPacket.get(id),d=byOwner.get(id);
    if(!same(refs(s),NETWORK_POLICY_REFS)||!same(refs(p),NETWORK_POLICY_REFS)||
       !same(refs(d),NETWORK_POLICY_REFS)||
       d?.externalPublisherRefs?.length!==0||
       s?.qualification!=='NOT_QUALIFIED')
       fail('NETWORK_FALSE_DOMAIN_SOURCE_'+id);
  }
  const networkProfile=(knowledge.semanticAssuranceProfile?.elements||[])
    .find(x=>x.profileId==='SAP-CA-NETWORK');
  const networkElement=(knowledge.elements||[]).find(x=>x.id==='CA-NETWORK');
  if(networkProfile?.claimRefs?.length!==0||networkElement?.sourceClaims?.length!==0||
     (knowledge.competencyQuestions||[]).find(x=>x.id==='CQ-CA-010')?.sourceRefs?.length!==0)
     fail('NETWORK_CLAIM_UNSOURCED_GATE');
  for(const ext of external.values()){
    if(ext.independentPublisherSourceOwnerAttestation!==false||
       ext.qualification!=='BLOCKED_PUBLISHER_BYTES_RIGHTS_OS_APPLICABILITY'||
       ext.pageOriginalBytesSha256!==null)
       fail('EXTERNAL_SOURCE_FALSE_QUALIFICATION_'+ext.id);
  }
  if(packet.summary?.totalSap!==75||packet.summary.qualifiedSap!==0||
     packet.summary.globalInvariantQualified!==0||
     packet.summary.formalK5!==0||
     packet.summary.productionDisFunction!==0||
     packet.summary.productionAotConsumption!==0||
     packet.summary.completeUserFunctionClosure!==0||
     delegated.sourceDecisionCount?.formalSapPass!==0||
     delegated.sourceDecisionCount?.originalPublisherSourceSemanticsQualified!==0)
     fail('UNAUTHORIZED_FORMAL_GATE_PROMOTION');
  // Status is structural evidence only: Caller may not use 'ok' as a SAP PASS.
  return {ok:errors.length===0,errors,
    verifiedSap:source.size,verifiedGlobals:globals.size,
    externalPublisherSources:external.size,qualifiedSap:0,
    qualification:'STRUCTURAL_SOURCE_INTEGRITY_ONLY_NOT_SEMANTIC_ORACLE'};
}
