import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate, gitBlobSha } from './verify-demand-function-closure-r0.mjs';

const root=path.dirname(fileURLToPath(import.meta.url));
const sourceBytes=fs.readFileSync(path.join(root,'COMPUTER_ASSISTANT_KNOWLEDGE_R0.json'));
const source=JSON.parse(sourceBytes.toString('utf8'));
const matrix=JSON.parse(fs.readFileSync(path.join(root,'DEMAND_TO_FUNCTION_CLOSURE_R0.json'),'utf8'));
// The fixture is plain JSON; avoid an unnecessary structuredClone runtime dependency.
const clone=()=>JSON.parse(JSON.stringify(matrix));
const expectReject=(edit,expected)=>{
 const x=clone(); edit(x); const result=validate(x,source,{knowledgeBlob:gitBlobSha(sourceBytes)});
 assert.equal(result.ok,false,'tampered matrix must be rejected');
 assert.ok(result.errors.some(e=>e.startsWith(expected)),JSON.stringify(result.errors));
};

test('source-pinned matrix validates without claiming semantic qualification',()=>{
 const result=validate(matrix,source,{knowledgeBlob:gitBlobSha(sourceBytes)});
 assert.equal(result.ok,true,JSON.stringify(result.errors));
 assert.equal(result.metrics.jobs,15);
 assert.equal(result.metrics.frozenProductJobs,10);
 assert.equal(result.metrics.futureCandidateJobs,5);
});
test('duplicate user job is rejected',()=>expectReject(x=>x.jobs[1].id=x.jobs[0].id,'DUPLICATE_OR_EMPTY_JOB_ID'));
test('unknown Claim cannot enter a job',()=>expectReject(x=>x.jobs[0].claimIds=['CA-CLM-FORGED'],'BROKEN_CLAIM_REFERENCES'));
test('unknown CQ cannot silently pass',()=>expectReject(x=>x.jobs[0].cqIds=['CQ-FAKE'],'BROKEN_CQ_REFERENCES'));
test('unknown source reference is rejected',()=>expectReject(x=>x.jobs[0].sourceRefs.push('SRC-LLM-GUESSED'),'BROKEN_SOURCE_REFERENCES'));
test('global semantic owner cannot vanish',()=>expectReject(x=>x.jobs[0].elementIds=x.jobs[0].elementIds.filter(id=>id!=='CA-GLOBAL-VERIFICATION'),'GLOBAL_SEMANTIC_OWNER_LOST'));
test('future software manager cannot become admitted',()=>expectReject(x=>x.jobs[10].productAdmission='ADMITTED','FUTURE_PRODUCT_ADMISSION_FORGED'));
test('native receipt cannot be manufactured from source',()=>expectReject(x=>x.jobs[2].feasibility.actualNativeEvidence='PASS','FEASIBILITY_OVERCLAIM'));
test('Function schema cannot be forged by DKE',()=>expectReject(x=>x.jobs[2].functionCandidate.inputSchema='real.write/1','UNAUTHORIZED_DIS_FUNCTION_CLAIM'));
test('missing independent postcondition fails closure',()=>expectReject(x=>x.jobs[2].independentPostcondition='','FUNCTION_CLOSURE_GAP'));
test('missing UNKNOWN/recovery fails closure',()=>expectReject(x=>x.jobs[2].unknownOrRecoveryCase='','FUNCTION_CLOSURE_GAP'));
test('knowledge cannot become qualified by author check',()=>expectReject(x=>x.jobs[0].sapQualification='QUALIFIED','FORGED_QUALIFICATION_OR_CLOSURE'));
test('demand cannot masquerade as quantified market need',()=>expectReject(x=>x.jobs[0].demandEvidence.businessValue=100,'FALSE_DEMAND_EVIDENCE'));
test('source change invalidates exact pinned dossier',()=>expectReject(x=>x.evidenceBase.candidateHead='deadbeef','AUTHORITY_SOURCE_REPIN_NOT_REVIEWED'));
test('dossier bytes mismatch blocks validity',()=>{
 const result=validate(matrix,source,{knowledgeBlob:'0000000000000000000000000000000000000000'});
 assert.ok(result.errors.some(e=>e.startsWith('KNOWLEDGE_DOSSIER_BLOB_MISMATCH')));
});
test('current Product checkpoint cannot grant implementation',()=>expectReject(x=>x.governance.implementationAuthorized=true,'ILLEGAL_PROMOTION_OR_AUTHORITY'));

test('paired knowledge-plus-matrix repin cannot counterfeit reviewed Git Blob',()=>{
 const tampered=JSON.parse(JSON.stringify(source));
 tampered.claims[0].statement += ' counterfeit';
 const forged=gitBlobSha(Buffer.from(JSON.stringify(tampered),'utf8'));
 const x=clone(); x.evidenceBase.candidateBlob=forged;
 const result=validate(x,tampered,{knowledgeBlob:forged});
 assert.equal(result.ok,false);
 assert.ok(result.errors.some(e=>e.startsWith('AUTHORITY_SOURCE_REPIN_NOT_REVIEWED')),JSON.stringify(result.errors));
 assert.ok(result.errors.some(e=>e.startsWith('KNOWLEDGE_DOSSIER_BLOB_MISMATCH')),JSON.stringify(result.errors));
});
test('duplicate Product item cannot hide omitted frozen journey',()=>expectReject(x=>{
 x.jobs[1].demandEvidence.locator=x.jobs[0].demandEvidence.locator;
},'PRODUCT_JOURNEY_COVERAGE_DRIFT'));
test('network source gap cannot masquerade as domain Claim closure',()=>expectReject(x=>{
 x.jobs[14].semanticTrace.status='BOUNDED_SOURCE_CANDIDATE_NOT_FUNCTIONAL_CLOSURE';
},'FALSE_SEMANTIC_TRACE_CLOSURE'));
test('primary domain Claim witness is not any arbitrary registered Claim',()=>expectReject(x=>{
 x.jobs[2].semanticTrace.primaryElementClaimWitnessIds=['CA-CLM-002'];
},'PRIMARY_DOMAIN_CLAIM_TRACE_MISMATCH'));
test('a source-only cloud/Host trace cannot be promoted to physical E2E closure',()=>expectReject(x=>{
 x.jobs[4].semanticTrace.verifiedFunctionReceipt='PASS';
},'FALSE_SEMANTIC_TRACE_CLOSURE'));
test('a missing reviewed source-blob argument refuses rather than inferring currentness',()=>{
 const result=validate(matrix,source);
 assert.equal(result.ok,false);
 assert.ok(result.errors.some(e=>e.startsWith('KNOWLEDGE_DOSSIER_BLOB_MISMATCH')),JSON.stringify(result.errors));
});
