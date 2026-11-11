import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const EXPECTED_KNOWLEDGE_BLOB = 'c877ec23dc59b0ae17681c7d8f7505b1521c8011';
const EXPECTED_DEMAND_BLOB = '74c10245e88608d12ae716bd2bae1623a2f55dc5';

/**
 * Source locks deliberately live in reviewer-readable validator source, NOT
 * only in candidate JSON. Paired mutation of a dossier and its self-described
 * candidateBlob must fail closed.
 */

function gitBlobSha(text) {
  const bytes = Buffer.from(text, 'utf8');
  return createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
}
function unique(values) { return new Set(values).size === values.length; }
function hasAll(set, values) { return values.every((x) => set.has(x)); }

export function validateArtifacts(base, ext, demand, demo, contract, aot, baseText, demandText) {
  const errors = [];
  const baseSourceIds = new Set([...base.sourceInventory, ...base.externalSources].map((x) => x.id));
  const externalIds = new Set(ext.externalSources.map((x) => x.id));
  const sourceIds = new Set([...baseSourceIds, ...externalIds]);
  const elementIds = new Set([...base.elements.map((x) => x.id), ...ext.elements.map((x) => x.id)]);
  const claimIds = new Set([...base.claims.map((x) => x.id), ...ext.claims.map((x) => x.id)]);
  const relationIds = new Set([...base.relations.map((x) => x.id), ...ext.relations.map((x) => x.id)]);
  const invariantIds = new Set([...base.globalInvariants.map((x) => x.id), ...ext.invariants.map((x) => x.id)]);
  const cqIds = new Set([...base.competencyQuestions.map((x) => x.id), ...ext.competencyQuestions.map((x) => x.id)]);
  const sapProfiles = new Set(base.semanticAssuranceProfile.elements.map((x) => x.profileId));
  const add = (condition, code) => { if (!condition) errors.push(code); };

  add(ext.stackedOn.knowledgeBlob === EXPECTED_KNOWLEDGE_BLOB && gitBlobSha(baseText) === EXPECTED_KNOWLEDGE_BLOB, 'BASE_KNOWLEDGE_BLOB_MISMATCH');
  add(ext.stackedOn.demandBlob === EXPECTED_DEMAND_BLOB && gitBlobSha(demandText) === EXPECTED_DEMAND_BLOB, 'BASE_DEMAND_BLOB_MISMATCH');
  add(base.project === 'kaicreator-mm/shun-assistant', 'BASE_PROJECT_IDENTITY');
  add(unique(ext.claims.map((x) => x.id)) && ext.claims.every((x) => !base.claims.some((y) => y.id === x.id)), 'DUPLICATE_EXTENSION_CLAIM');
  add(unique(ext.elements.map((x) => x.id)) && ext.elements.every((x) => !base.elements.some((y) => y.id === x.id)), 'DUPLICATE_EXTENSION_ELEMENT');
  add(unique(ext.relations.map((x) => x.id)) && ext.relations.every((x) => !base.relations.some((y) => y.id === x.id)), 'DUPLICATE_EXTENSION_RELATION');
  add(unique(ext.invariants.map((x) => x.id)) && ext.invariants.every((x) => !base.globalInvariants.some((y) => y.id === x.id)), 'DUPLICATE_EXTENSION_INVARIANT');
  add(unique(ext.competencyQuestions.map((x) => x.id)) && ext.competencyQuestions.every((x) => !base.competencyQuestions.some((y) => y.id === x.id)), 'DUPLICATE_EXTENSION_CQ');
  add(unique(ext.externalSources.map((x) => x.id)) && ext.externalSources.every((x) => !baseSourceIds.has(x.id)), 'DUPLICATE_EXTENSION_SOURCE');
  for (const pin of ext.sourceEvidencePins) {
    const original = base.sourceInventory.find((x) => x.id === pin.id);
    add(Boolean(original) && original.blob === pin.blob && original.path === pin.path && original.commit === pin.commit && original.branch === pin.branch, `SOURCE_PIN_MISMATCH:${pin.id}`);
  }
  for (const source of ext.externalSources) {
    add(source.authority === 'MICROSOFT_LEARN' && source.url.startsWith('https://learn.microsoft.com/'), `EXTERNAL_SOURCE_AUTHORITY:${source.id}`);
  }
  for (const claim of ext.claims) add(hasAll(sourceIds, claim.sourceRefs), `CLAIM_SOURCE_REF:${claim.id}`);
  for (const e of ext.elements) {
    add(elementIds.has(e.parent), `ELEMENT_PARENT:${e.id}`);
    add(hasAll(claimIds, e.sourceClaims), `ELEMENT_CLAIMS:${e.id}`);
    add(hasAll(relationIds, e.relationRefs), `ELEMENT_RELATIONS:${e.id}`);
    add(hasAll(invariantIds, e.globalInvariantRefs), `ELEMENT_INVARIANTS:${e.id}`);
    add(hasAll(cqIds, e.cqRefs), `ELEMENT_CQS:${e.id}`);
    add(e.scopeContract?.owner === e.id && e.scopeContract?.qualification === 'NOT_QUALIFIED', `ELEMENT_SCOPE_CONTRACT:${e.id}`);
  }
  for (const r of ext.relations) {
    add(elementIds.has(r.from) && elementIds.has(r.to) && elementIds.has(r.semanticOwner), `RELATION_ENDPOINT:${r.id}`);
    add(hasAll(sourceIds, r.sourceRefs) && hasAll(cqIds, r.cqRefs) && hasAll(invariantIds, r.invariantRefs), `RELATION_EVIDENCE:${r.id}`);
  }
  for (const inv of ext.invariants) {
    add(elementIds.has(inv.owner) && hasAll(elementIds, inv.appliesTo), `INVARIANT_OWNER_SCOPE:${inv.id}`);
    add(hasAll(sourceIds, inv.sourceRefs) && hasAll(cqIds, inv.cqRefs), `INVARIANT_EVIDENCE:${inv.id}`);
  }
  for (const q of ext.competencyQuestions) {
    add(elementIds.has(q.element) && hasAll(sourceIds, q.sourceRefs), `CQ_OWNER_SOURCE:${q.id}`);
  }
  for (const p of ext.semanticAssuranceProfiles) {
    add(elementIds.has(p.element) && p.elementScopeRef === p.element, `SAP_ELEMENT:${p.profileId}`);
    add(hasAll(claimIds,p.claimRefs) && hasAll(sourceIds,p.sourceRefs) && hasAll(relationIds,p.relationRefs) && hasAll(invariantIds,p.invariantRefs) && hasAll(cqIds,p.cqRefs), `SAP_PROFILE_REFS:${p.profileId}`);
    add(p.status === 'OPEN' && p.qualification === 'NOT_QUALIFIED', `SAP_NOT_CANDIDATE:${p.profileId}`);
    for (const o of p.obligations) {
      add(hasAll(sourceIds,o.sourceRefs) && hasAll(relationIds,o.relationRefs) && hasAll(invariantIds,o.invariantRefs) && hasAll(cqIds,o.cqRefs), `SAP_OBLIGATION_REFS:${o.id}`);
      add(Boolean(o.positiveCase && o.negativeCase && o.unknownCase && o.oracle) && o.validationState === 'NOT_RUN' && o.qualification === 'NOT_QUALIFIED', `SAP_OBLIGATION_ORACLE:${o.id}`);
    }
  }
  add(hasAll(elementIds,ext.rootExtension.appendChildren) && hasAll(claimIds,ext.rootExtension.appendClaimRefs) && hasAll(relationIds,ext.rootExtension.appendRelationRefs) && hasAll(invariantIds,ext.rootExtension.appendInvariantRefs) && hasAll(cqIds,ext.rootExtension.appendCqRefs), 'ROOT_EXTENSION_REFS');
  add(ext.coverageMapAppend.length === ext.elements.length && ext.coverageMapAppend.every((x) => elementIds.has(x.element) && hasAll(cqIds,x.cqRefs) && hasAll(invariantIds,x.globalInvariantRefs)), 'NEW_ELEMENT_COVERAGE_MAP');
  add(ext.coverageMapExtensions.every((x) => elementIds.has(x.element)), 'EXISTING_COVERAGE_MAP_EXTENSIONS');
  add(ext.semanticAssuranceProfileExtensions.every((x) => sapProfiles.has(x.profileId)), 'EXISTING_SAP_PROFILE_EXTENSIONS');
  add(ext.decomposition.hierarchyEdgesAppend.every((x) => elementIds.has(x.from) && elementIds.has(x.to) && elementIds.has(x.owner)), 'HIERARCHY_EDGE_REFS');
  add(ext.qualification.independentReview === 'NOT_RUN' && ext.qualification.sapQualifiedElements === 0 && ext.qualification.productAdmission === 'NOT_ADMITTED', 'QUALIFICATION_OVERCLAIM');

  add(demand.jobs.length === 1 && demand.jobs[0].id === 'CA-JOB-16', 'DEMAND_JOB_ID');
  const job = demand.jobs[0];
  add(job.productAdmission === 'FUTURE_CANDIDATE_NOT_ADMITTED' && job.feasibility.productImplementationAuthorization === 'NOT_AUTHORIZED_BY_FROZEN_PRODUCT_CHECKPOINT', 'DEMAND_PRODUCT_ADMISSION');
  add(hasAll(elementIds,job.elementIds) && hasAll(claimIds,job.claimIds) && hasAll(cqIds,job.cqIds) && hasAll(sourceIds,job.sourceRefs), 'DEMAND_TRACE_REFS');
  add(job.closure === 'NOT_RUN' && job.sapQualification === 'NOT_QUALIFIED', 'DEMAND_CLOSURE_STATUS');

  add(contract.status === 'DIS_CONTRACT_CANDIDATE_NOT_QUALIFIED' && contract.productAdmission === 'NOT_ADMITTED', 'DIS_QUALIFICATION');
  add(unique(contract.functions.map((x) => x.functionId)) && contract.functions.length === 4, 'DIS_FUNCTION_IDS');
  add(contract.functions.every((x) => x.effect === 'NONE'), 'DIS_EFFECT_BOUNDARY');
  add(contract.pipeline.steps.join(',') === 'computer.memory.observe,computer.memory.assess,computer.memory.plan', 'DIS_PIPELINE_ORDER');
  add(contract.ecpCandidate.status === 'NOT_QUALIFIED', 'DIS_ECP_STATUS');

  add(aot.status === 'DEMO_ONLY_CANDIDATE_NOT_QUALIFIED' && aot.productionConsumable === false && aot.activation === 'RESEARCH_DEMO_HARNESS_ONLY', 'AOT_NOT_PRODUCTION');
  add(aot.sourceRules.length >= 8 && aot.decisionRules.length >= 6, 'AOT_RULE_COVERAGE');
  add(aot.neverCompile.some((x) => x.includes('process lists')) && aot.neverCompile.some((x) => x.includes('approvals')), 'AOT_NEVER_COMPILE');
  add(demo.runtimeScope.readOnly === true && demo.runtimeScope.localOnly === true && demo.runtimeScope.effectsAuthorized === false && demo.runtimeScope.automaticEgress === false, 'RUNTIME_NO_EFFECT_EGRESS');
  add(demo.productAuthority.implementationAuthorized === false && demo.productAuthority.productAdmission === 'NOT_ADMITTED', 'DEMO_PRODUCT_BOUNDARY');
  add(demo.stages.length === 4 && demo.stages.map((x) => x.stage).join(',') === 'DKE,DIS,AOT,Runtime', 'DEMO_STAGE_ORDER');
  add(demo.stages.find((x) => x.stage === 'Runtime').nativeReceipt === 'NOT_RUN', 'DEMO_NATIVE_RECEIPT');
  return { ok: errors.length === 0, errors, metrics: { claims:ext.claims.length,elements:ext.elements.length,relations:ext.relations.length,invariants:ext.invariants.length,cqs:ext.competencyQuestions.length,sapProfiles:ext.semanticAssuranceProfiles.length,sapObligations:ext.semanticAssuranceProfiles.reduce((n,p)=>n+p.obligations.length,0),externalSources:ext.externalSources.length,internalSourcePins:ext.sourceEvidencePins.length,functions:contract.functions.length,aotRules:aot.sourceRules.length } };
}

async function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
  const read = async (p) => readFile(resolve(root,p),'utf8');
  const [baseText,demandText,extText,demandExtText,demoText,contractText,aotText] = await Promise.all([
    read('docs/dke/implementation/COMPUTER_ASSISTANT_KNOWLEDGE_R0.json'),
    read('docs/dke/implementation/DEMAND_TO_FUNCTION_CLOSURE_R0.json'),
    read('docs/dke/implementation/PERFORMANCE_MEMORY_EXTENSION_R0.json'),
    read('docs/dke/implementation/PERFORMANCE_MEMORY_DEMAND_EXTENSION_R0.json'),
    read('docs/dke/demos/memory-performance-r0/DKE_DIS_AOT_RUNTIME_DEMO_R0.json'),
    read('docs/dke/demos/memory-performance-r0/DIS_FUNCTION_CONTRACT_R0.json'),
    read('docs/dke/demos/memory-performance-r0/AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json'),
  ]);
  const result = validateArtifacts(JSON.parse(baseText),JSON.parse(extText),JSON.parse(demandExtText),JSON.parse(demoText),JSON.parse(contractText),JSON.parse(aotText),baseText,demandText);
  process.stdout.write(JSON.stringify({validator:'SHUN_PERFORMANCE_MEMORY_EXTENSION_R0',...result},null,2)+'\n');
  if (!result.ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => { process.stderr.write('VALIDATOR_INPUT_OR_IO_ERROR\n'); process.exitCode = 1; });
}
