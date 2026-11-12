import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateSapSourceLedgerR15, SOURCE_BLOB_PINS, gitBlobId }
  from '../../docs/dke/qualification/verify-sap-source-ledger-r15.mjs';

const root = new URL('../../', import.meta.url);
const files = Object.freeze({
  rawKnowledge: 'docs/dke/implementation/COMPUTER_ASSISTANT_KNOWLEDGE_R0.json',
  rawMemory: 'docs/dke/implementation/PERFORMANCE_MEMORY_EXTENSION_R0.json',
  rawR2: 'docs/dke/demos/memory-performance-r0/dke-semantic/SOURCE_FIRST_KNOWLEDGE_DELTA_R2.json',
  packet: 'docs/dke/qualification/OWNER_ORACLE_75_SAP_ADJUDICATION_R13.json',
  delegated: 'docs/dke/qualification/PROJECT_OWNER_DELEGATED_SCOPE_DECISIONS_R14.json',
});
function load() {
  const r = Object.fromEntries(Object.entries(files).map(([name,relative]) =>
    [name,readFileSync(new URL(relative,root))]));
  return {
    ...r,
    knowledge:JSON.parse(r.rawKnowledge.toString('utf8')),
    memory:JSON.parse(r.rawMemory.toString('utf8')),
    r2:JSON.parse(r.rawR2.toString('utf8')),
    packet:JSON.parse(r.packet.toString('utf8')),
    delegated:JSON.parse(r.delegated.toString('utf8')),
  };
}
function error(input,label) {
  const result=validateSapSourceLedgerR15(input);
  assert.equal(result.ok,false,'Must refuse invalid source evidence');
  assert.ok(result.errors.some(x=>x.includes(label)),JSON.stringify(result.errors));
}

test('current 75 SAP/19 Global/24 publisher packet is exact-source aligned but still not qualified',()=>{
  const data=load();
  assert.equal(gitBlobId(data.rawKnowledge),SOURCE_BLOB_PINS.knowledge);
  assert.equal(gitBlobId(data.rawMemory),SOURCE_BLOB_PINS.memory);
  assert.equal(gitBlobId(data.rawR2),SOURCE_BLOB_PINS.r2);
  const r=validateSapSourceLedgerR15(data);
  assert.equal(r.ok,true,JSON.stringify(r.errors));
  assert.equal(r.verifiedSap,75);
  assert.equal(r.verifiedGlobals,19);
  assert.equal(r.externalPublisherSources,24);
  assert.equal(r.qualifiedSap,0);
  assert.equal(r.qualification,'STRUCTURAL_SOURCE_INTEGRITY_ONLY_NOT_SEMANTIC_ORACLE');
});
test('fabricating unrelated disk publisher in both packet and delegated network row fails against original source',()=>{
  const x=load(),a=x.packet.sapObligations.find(x=>x.id==='SAP-CA-NETWORK-01'),
    b=x.delegated.rows.find(x=>x.sapId==='SAP-CA-NETWORK-01');
  a.sourceRefs.push('EXT-PHYSICAL-DISK');b.sourceRefs.push('EXT-PHYSICAL-DISK');
  b.externalPublisherRefs.push({id:'EXT-PHYSICAL-DISK'});
  error(x,'SAP_SOURCE_REFERENCE_MISMATCH_SAP-CA-NETWORK-01');
});
test('forged SAP positive/negative/UNKNOWN case (including delegated echo) fails against original source claim',()=>{
  const x=load(),id='SAP-CA-MEMORY-PERFORMANCE-09';
  x.packet.sapObligations.find(x=>x.id===id).positive.expectedCase='Always speedup';
  x.delegated.rows.find(x=>x.sapId===id).positive.case='Always speedup';
  error(x,'SAP_CASE_SOURCE_MUTATION_'+id);
});
test('changing actual model objects while keeping pinned original bytes fails',()=>{
  const x=load();
  x.knowledge.semanticAssuranceProfile.elements.find(x=>x.profileId==='SAP-CA-NETWORK')
    .obligations[0].sourceRefs.push('EXT-DISK-MGMT');
  error(x,'SOURCE_OBJECT_BYTES_MISMATCH_KNOWLEDGE');
});
test('changing both source bytes and model facts cannot bypass independently locked Git Blob',()=>{
  const x=load();
  x.rawKnowledge=Buffer.from(x.rawKnowledge.toString('utf8').replace(
    'PRODUCT_SCOPE_ONLY_NETWORK_TECHNICAL_EVIDENCE_MISSING','FAKE_QUALIFIED_SCOPE'));
  error(x,'SOURCE_BLOB_MISMATCH_KNOWLEDGE');
});
test('global owner drift or false global qualification fails closed',()=>{
  const x=load();
  x.delegated.globalInvariants[0].sourceRefs=['EXT-PHYSICAL-DISK'];
  error(x,'GLOBAL_SOURCE_MISMATCH_CA-INV-001');
  const y=load();
  y.delegated.globalInvariants[0].formalGlobalQualified=true;
  error(y,'FALSE_GLOBAL_QUALIFICATION_CA-INV-001');
});
test('no publisher authority or SAP/K5 promotion from mutable URL, owner delegation or green CI',()=>{
  const x=load();
  x.delegated.externalPublisherSources[0].qualification='QUALIFIED';
  error(x,'EXTERNAL_SOURCE_FALSE_QUALIFICATION_');
  const y=load();
  y.packet.sapObligations[0].sapQualification='QUALIFIED';
  error(y,'FALSE_SAP_OR_OWNER_QUALIFICATION_');
  const z=load();
  z.packet.summary.productionAotConsumption=1;
  error(z,'UNAUTHORIZED_FORMAL_GATE_PROMOTION');
});
test('missing or duplicate SAP IDs fail closed, no count-only success',()=>{
  const x=load();
  x.packet.sapObligations[0].id=x.packet.sapObligations[1].id;
  error(x,'PACKET_SAP_DUPLICATE_OR_EMPTY');
  const y=load();y.delegated.rows.pop();
  error(y,'SAP_COVERAGE_DRIFT');
});
