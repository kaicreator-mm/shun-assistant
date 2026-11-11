/**
 * DKE-D0 candidate structural and authority-boundary checker.
 * This validates a proposed demand→knowledge→function matrix against its
 * exact source dossier, not semantic truth or native execution.
 *
 * Usage (Node.js runtime providing the imported built-ins and syntax):
 * No blanket minimum Node version is imposed by this standalone DKE checker.
 * If a specific feature requires a minimum version, document and test that
 * feature's actual compatibility rather than inheriting the monorepo engine.
 *   node docs/dke/implementation/verify-demand-function-closure-r0.mjs
 *   node --test docs/dke/implementation/verify-demand-function-closure-r0.test.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

// This standalone checker is pinned to the *independently inspected source bytes*,
// not to a mutable D0-provided candidateBlob claim. Changing both JSON files is
// insufficient to manufacture a valid source pin; updating this lock requires
// an explicit new exact-source review.
const REVIEWED_KNOWLEDGE_HEAD = '22a929ce1fbb5cdb5b2819cd3e98e71bbf21085a';
const REVIEWED_KNOWLEDGE_BLOB = 'c877ec23dc59b0ae17681c7d8f7505b1521c8011';

export function gitBlobSha(data) {
  const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return crypto.createHash('sha1')
    .update(Buffer.from('blob ' + bytes.length + '\0', 'utf8'))
    .update(bytes)
    .digest('hex');
}

export function validate(matrix, knowledge, options = {}) {
  const errors = [];
  const add = (code, detail) => errors.push(code + (detail ? ': ' + detail : ''));
  const nonEmpty = value => typeof value === 'string' && value.trim().length > 0;
  if (!matrix || matrix.schema !== 'shun.dke.demand-functional-closure-r0') {
    add('BAD_SCHEMA');
    return { ok: false, errors };
  }
  if (matrix.status !== 'AUTHOR_CANDIDATE_NOT_INDEPENDENTLY_REVIEWED') add('ILLEGAL_QUALIFICATION_STATUS');
  if (matrix.governance?.implementationAuthorized !== false ||
      matrix.governance?.sourceScaffoldAuthorized !== false ||
      matrix.governance?.noImplicitAdmission !== true ||
      matrix.governance?.independentStage0 !== 'NOT_CLAIMED' ||
      matrix.governance?.k5 !== 'NOT_QUALIFIED' ||
      matrix.governance?.disHandoff !== 'BLOCKED' ||
      matrix.governance?.aotPackage !== 'NOT_CREATED' ||
      matrix.governance?.nativeWindowsDkeTests !== 'NOT_RUN') {
    add('ILLEGAL_PROMOTION_OR_AUTHORITY');
  }
  if (matrix.evidenceBase?.candidateHead !== REVIEWED_KNOWLEDGE_HEAD ||
      matrix.evidenceBase?.candidateBlob !== REVIEWED_KNOWLEDGE_BLOB ||
      matrix.evidenceBase?.productOriginal?.prdBlob !== 'f062b7f2c3dc3bf4aeeb7594ab5c2bc75b34d0ab' ||
      matrix.evidenceBase?.productOriginal?.l1Blob !== '4c703c3f0c283f4d3918babef8f87f56869698e5' ||
      matrix.evidenceBase?.productFreeze?.blob !== '0f8a67c2f06364d58a842502d3dee11bfeeedba4' ||
      matrix.evidenceBase?.sourceCodeSnapshot !== '1224fea4097799467e2c0c454885e680f1f28248') {
    add('AUTHORITY_SOURCE_REPIN_NOT_REVIEWED');
  }
  if (options.knowledgeBlob !== REVIEWED_KNOWLEDGE_BLOB ||
      options.knowledgeBlob !== matrix.evidenceBase?.candidateBlob) {
    add('KNOWLEDGE_DOSSIER_BLOB_MISMATCH');
  }
  const index = (array, field, label) => {
    if (!Array.isArray(array)) {
      add('MISSING_' + label + '_REGISTRY');
      return new Set();
    }
    const items = array.map(v => v?.[field]);
    if (items.some(v => !nonEmpty(v)) || new Set(items).size !== items.length) add('BAD_' + label + '_IDENTIFIERS');
    return new Set(items);
  };
  const elements = index(knowledge?.elements, 'id', 'ELEMENT');
  const claims = index(knowledge?.claims, 'id', 'CLAIM');
  const questions = index(knowledge?.competencyQuestions, 'id', 'CQ');
  const sources = index(knowledge?.sourceInventory, 'id', 'SOURCE');
  if (!Array.isArray(matrix.jobs)) {
    add('MISSING_JOBS');
    return { ok: false, errors };
  }
  const jobs = matrix.jobs;
  const ids = new Set();
  let d0 = 0;
  let candidate = 0;
  const seenProductItems = new Set();
  for (const row of jobs) {
    const id = row?.id;
    if (!nonEmpty(id) || ids.has(id)) add('DUPLICATE_OR_EMPTY_JOB_ID', String(id));
    ids.add(id);
    if (!nonEmpty(row?.title) || !nonEmpty(row?.goal)) add('MISSING_GOAL', String(id));
    if (!row?.demandEvidence || row.demandEvidence.frequencyEvidence !== 'UNKNOWN_NOT_MEASURED' ||
        row.demandEvidence.businessValue !== 'NOT_QUANTIFIED' ||
        !nonEmpty(row.demandEvidence.locator)) add('FALSE_DEMAND_EVIDENCE', id);
    if (row?.demandClass === 'D0') {
      d0++;
      const productItem = /^PRD-v0\.3-domain-harness-R0\.md §2 item (10|[1-9]); Product Freeze checkpoint$/.exec(row.demandEvidence?.locator ?? '');
      if (!productItem || seenProductItems.has(Number(productItem[1]))) add('PRODUCT_JOURNEY_COVERAGE_DRIFT', String(id));
      if (productItem) seenProductItems.add(Number(productItem[1]));
      if (row.productAdmission !== 'FROZEN_PRODUCT_REQUIREMENT_ONLY' ||
          row.demandEvidence?.kind !== 'FROZEN_PRODUCT_JOURNEY' ||
          !/PRD-v0\.3-domain-harness-R0\.md §2 item [1-9]|PRD-v0\.3-domain-harness-R0\.md §2 item 10/.test(row.demandEvidence.locator)) {
        add('PRODUCT_SCOPE_MISMATCH', id);
      }
    } else if (row?.demandClass === 'D1' || row?.demandClass === 'D2') {
      candidate++;
      if (row.productAdmission !== 'FUTURE_CANDIDATE_NOT_ADMITTED' ||
          row.demandEvidence?.kind !== 'OWNER_REQUESTED_KNOWLEDGE_RESEARCH_ONLY' ||
          row.functionCandidate?.status !== 'NOT_ADMITTED') add('FUTURE_PRODUCT_ADMISSION_FORGED', id);
    } else add('UNKNOWN_DEMAND_CLASS', id);
    const refs = [
      ['elementIds', elements, 'ELEMENT'], ['claimIds', claims, 'CLAIM'],
      ['cqIds', questions, 'CQ'], ['sourceRefs', sources, 'SOURCE'],
    ];
    for (const [key, registry, label] of refs) {
      if (!Array.isArray(row?.[key]) || row[key].length === 0 ||
          row[key].some(ref => !registry.has(ref))) add('BROKEN_' + label + '_REFERENCES', id);
      else if (new Set(row[key]).size !== row[key].length) add('DUPLICATE_' + label + '_REFERENCES', id);
    }
    // Validate the primary domain Claim-to-Element edge, rather than accepting
    // arbitrary IDs from the global registry. Explicit gaps cannot be PASS.
    const primary = knowledge?.elements?.find(e => e.id === row.elementIds?.[0]);
    const witnessedClaims = (primary?.scopeContract?.sourceClaimRefs ?? [])
      .filter(x => row.claimIds?.includes(x));
    const declaredWitnesses = row.semanticTrace?.primaryElementClaimWitnessIds;
    if (!primary || row.semanticTrace?.primaryElementId !== primary.id ||
        !Array.isArray(declaredWitnesses) ||
        JSON.stringify(declaredWitnesses) !== JSON.stringify(witnessedClaims)) {
      add('PRIMARY_DOMAIN_CLAIM_TRACE_MISMATCH', String(id));
    }
    if (witnessedClaims.length === 0 && row.semanticTrace?.status !== 'NETWORK_DOMAIN_SEMANTICS_UNSOURCED') {
      add('UNSOURCED_DOMAIN_WITNESS_NOT_DECLARED', String(id));
    }
    const requiredStatus = {
      'CA-JOB-05':'HOST_EFFECT_WITNESS_NOT_PINNED',
      'CA-JOB-07':'KERNEL_JOURNAL_HOST_E2E_NOT_PINNED',
      'CA-JOB-08':'PRODUCT_REQUIREMENT_ONLY_NO_UI_WITNESS',
      'CA-JOB-15':'NETWORK_DOMAIN_SEMANTICS_UNSOURCED',
    }[id] ?? 'BOUNDED_SOURCE_CANDIDATE_NOT_FUNCTIONAL_CLOSURE';
    if (row.semanticTrace?.status !== requiredStatus ||
        !nonEmpty(row.semanticTrace?.evidenceGap) ||
        row.semanticTrace?.verifiedFunctionReceipt !== 'NOT_RUN' ||
        row.semanticTrace?.postconditionOracleExecution !== 'NOT_RUN' ||
        row.semanticTrace?.qualifiedSourceFirstDecision !== 'PENDING') {
      add('FALSE_SEMANTIC_TRACE_CLOSURE', String(id));
    }
    for (const idRequired of ['CA-GLOBAL-PROVENANCE','CA-GLOBAL-AUTHORITY',
       'CA-GLOBAL-VERIFICATION','CA-GLOBAL-CURRENTNESS']) {
      if (!row.elementIds?.includes(idRequired)) add('GLOBAL_SEMANTIC_OWNER_LOST', id + ' ' + idRequired);
    }
    for (const idRequired of ['SRC-PRODUCT-PRD','SRC-PRODUCT-L1','SRC-PRODUCT-FREEZE']) {
      if (!row.sourceRefs?.includes(idRequired)) add('PRODUCT_SOURCE_LINEAGE_LOST', id + ' ' + idRequired);
    }
    if (!Array.isArray(row?.knowledgeRequirements) || !row.knowledgeRequirements.length ||
        !Array.isArray(row?.aotEligible) || !row.aotEligible.length ||
        !Array.isArray(row?.runtimeOnly) || !row.runtimeOnly.length) add('KNOWLEDGE_AOT_RUNTIME_SPLIT_MISSING', id);
    if (!['I0','I1','I2','I3','I4'].includes(row.feasibility?.targetClass) ||
        !nonEmpty(row.feasibility?.currentSourceObservation) ||
        row.feasibility?.actualNativeEvidence !== 'NOT_RUN_IN_THIS_DKE_WORKSTREAM' ||
        row.feasibility?.integrationEvidence !== 'NOT_ESTABLISHED' ||
        row.feasibility?.productImplementationAuthorization !== 'NOT_AUTHORIZED_BY_FROZEN_PRODUCT_CHECKPOINT' ||
        row.feasibility?.implementationEstimate !== 'UNKNOWN' ||
        row.feasibility?.maintenanceEstimate !== 'UNKNOWN') add('FEASIBILITY_OVERCLAIM', id);
    if (!nonEmpty(row?.functionCandidate?.name) ||
        row.functionCandidate?.inputSchema !== 'NOT_DEFINED_DIS_OWNER' ||
        row.functionCandidate?.typedOutput !== 'NOT_DEFINED_DIS_OWNER' ||
        row.functionCandidate?.pipeline !== 'NOT_DEFINED_DIS_OWNER' ||
        !['NOT_ADMITTED','DIS_NOT_PROPOSED_OR_QUALIFIED'].includes(row.functionCandidate?.status)) {
      add('UNAUTHORIZED_DIS_FUNCTION_CLAIM', id);
    }
    if (!Array.isArray(row?.preconditions) || row.preconditions.length === 0 ||
        !nonEmpty(row?.independentPostcondition) ||
        !nonEmpty(row?.negativeOrRefusalCase) ||
        !nonEmpty(row?.unknownOrRecoveryCase)) add('FUNCTION_CLOSURE_GAP', id);
    if (!nonEmpty(row?.risk) || !Array.isArray(row?.unresolvedDecisions) ||
        row.unresolvedDecisions.length < 2) add('RISK_OR_OWNER_GATE_GAP', id);
    if (row?.verificationEvidence !== 'TEST_DEFINITIONS_ONLY_NOT_RUNTIME_RECEIPT' ||
        row?.sapQualification !== 'NOT_QUALIFIED' || row?.closure !== 'NOT_RUN') add('FORGED_QUALIFICATION_OR_CLOSURE', id);
  }
  if (seenProductItems.size !== 10 ||
      [...Array(10)].some((_, i) => !seenProductItems.has(i + 1))) {
    add('PRODUCT_JOURNEY_COVERAGE_DRIFT');
  }
  if (jobs.length !== 15 || matrix.jobCount !== 15 ||
      matrix.productCriticalCount !== 10 || matrix.futureCandidateCount !== 5 ||
      d0 !== 10 || candidate !== 5) add('JOB_COVERAGE_COUNT_MISMATCH');
  const metrics = { jobs: jobs.length, frozenProductJobs: d0, futureCandidateJobs: candidate,
    uniqueElementRefs: new Set(jobs.flatMap(x => x.elementIds||[])).size,
    uniqueClaimRefs: new Set(jobs.flatMap(x => x.claimIds||[])).size,
    uniqueCqRefs: new Set(jobs.flatMap(x => x.cqIds||[])).size,
    uniqueSourceRefs: new Set(jobs.flatMap(x => x.sourceRefs||[])).size };
  return {ok:errors.length===0, errors, metrics};
}

const self = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (self) {
  const base = path.dirname(fileURLToPath(import.meta.url));
  const rawKnowledge = fs.readFileSync(path.join(base,'COMPUTER_ASSISTANT_KNOWLEDGE_R0.json'));
  const knowledge = JSON.parse(rawKnowledge.toString('utf8'));
  const matrix = JSON.parse(fs.readFileSync(path.join(base,'DEMAND_TO_FUNCTION_CLOSURE_R0.json'),'utf8'));
  const result=validate(matrix, knowledge, {knowledgeBlob:gitBlobSha(rawKnowledge)});
  process.stdout.write(JSON.stringify({validator:'DKE_D0_MATRIX_R0',...result},null,2)+'\n');
  if(!result.ok) process.exitCode=1;
}
