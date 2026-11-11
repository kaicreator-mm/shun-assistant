import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { validateArtifacts } from './verify-performance-memory-extension-r0.mjs';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');
async function fixtures() {
  const [baseText,demandText,extText,demandExtText,demoText,contractText,aotText] = await Promise.all([
    read('./COMPUTER_ASSISTANT_KNOWLEDGE_R0.json'),
    read('./DEMAND_TO_FUNCTION_CLOSURE_R0.json'),
    read('./PERFORMANCE_MEMORY_EXTENSION_R0.json'),
    read('./PERFORMANCE_MEMORY_DEMAND_EXTENSION_R0.json'),
    read('../demos/memory-performance-r0/DKE_DIS_AOT_RUNTIME_DEMO_R0.json'),
    read('../demos/memory-performance-r0/DIS_FUNCTION_CONTRACT_R0.json'),
    read('../demos/memory-performance-r0/AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json'),
  ]);
  return {
    base:JSON.parse(baseText),demand:JSON.parse(demandText),ext:JSON.parse(extText),
    demandExt:JSON.parse(demandExtText),demo:JSON.parse(demoText),
    contract:JSON.parse(contractText),aot:JSON.parse(aotText),baseText,demandText,
  };
}
function validate(f) {
  return validateArtifacts(f.base,f.ext,f.demandExt,f.demo,f.contract,f.aot,f.baseText,f.demandText);
}

test('performance-memory extension and four-layer demo references are mechanically closed', async () => {
  const f = await fixtures();
  const r = validate(f);
  assert.equal(r.ok,true,JSON.stringify(r.errors));
  assert.equal(r.metrics.elements,2);
  assert.equal(r.metrics.sapObligations,12);
});

test('duplicate Element identity fails closed', async () => {
  const f = await fixtures();
  f.ext.elements[1].id = f.ext.elements[0].id;
  const r = validate(f);
  assert.ok(r.errors.includes('DUPLICATE_EXTENSION_ELEMENT'));
});

test('a candidate job cannot silently become Product admitted', async () => {
  const f = await fixtures();
  f.demandExt.jobs[0].productAdmission = 'FROZEN_PRODUCT_REQUIREMENT_ONLY';
  const r = validate(f);
  assert.ok(r.errors.includes('DEMAND_PRODUCT_ADMISSION'));
});

test('an AOT candidate cannot be silently promoted to production consumption', async () => {
  const f = await fixtures();
  f.aot.productionConsumable = true;
  const r = validate(f);
  assert.ok(r.errors.includes('AOT_NOT_PRODUCTION'));
});

test('effectful DIS Function is rejected from this read-only demo', async () => {
  const f = await fixtures();
  f.contract.functions[0].effect = 'MUTATION';
  const r = validate(f);
  assert.ok(r.errors.includes('DIS_EFFECT_BOUNDARY'));
});

test('paired source dossier plus self-reported Git blob tamper cannot bypass independent lock', async () => {
  const f = await fixtures();
  f.baseText += '\n';
  const bytes = Buffer.from(f.baseText, 'utf8');
  f.ext.stackedOn.knowledgeBlob = createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
  const result = validate(f);
  assert.ok(result.errors.includes('BASE_KNOWLEDGE_BLOB_MISMATCH'));
});

test('paired demand-matrix plus self-reported Git blob tamper cannot bypass independent lock', async () => {
  const f = await fixtures();
  f.demandText += '\n';
  const bytes = Buffer.from(f.demandText, 'utf8');
  f.ext.stackedOn.demandBlob = createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
  const result = validate(f);
  assert.ok(result.errors.includes('BASE_DEMAND_BLOB_MISMATCH'));
});
