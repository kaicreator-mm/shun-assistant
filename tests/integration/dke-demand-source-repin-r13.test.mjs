import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  validate, gitBlobSha,
} from '../../docs/dke/implementation/verify-demand-function-closure-r0.mjs';

const base = new URL('../../docs/dke/implementation/', import.meta.url);
const raw = readFileSync(new URL('COMPUTER_ASSISTANT_KNOWLEDGE_R0.json', base));
const knowledge = JSON.parse(raw.toString('utf8'));
const matrix = JSON.parse(readFileSync(
  new URL('DEMAND_TO_FUNCTION_CLOSURE_R0.json', base), 'utf8',
));
const exactBlob = 'da8425d82f3725c10bce92d206bbb8adfd6e7169';
const upstreamHead = 'd6df57422b8a329e8fcfbad1146c86740978db70';

test('exact new knowledge Blob matches independently locked D0 source and source HEAD', () => {
  assert.equal(gitBlobSha(raw), exactBlob);
  assert.equal(matrix.evidenceBase.candidateBlob, exactBlob);
  assert.equal(matrix.evidenceBase.candidateHead, upstreamHead);
  const result = validate(matrix, knowledge, { knowledgeBlob: gitBlobSha(raw) });
  assert.equal(result.ok, true, result.errors.join('\n'));
  assert.equal(result.metrics.jobs, 15);
});

test('updating matrix self-reported candidate pin without the verifier lock fails closed', () => {
  const forged = structuredClone(matrix);
  forged.evidenceBase.candidateBlob = 'f'.repeat(40);
  forged.evidenceBase.candidateHead = 'e'.repeat(40);
  const result = validate(forged, knowledge, { knowledgeBlob: 'f'.repeat(40) });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes('AUTHORITY_SOURCE_REPIN_NOT_REVIEWED')));
});

test('injecting unrelated disk source into CA-NETWORK must fail downstream validation', () => {
  const forged = structuredClone(knowledge);
  const net = forged.semanticAssuranceProfile.elements.find(x => x.profileId === 'SAP-CA-NETWORK');
  net.obligations[0].sourceRefs.push('EXT-PHYSICAL-DISK');
  const result = validate(matrix, forged, { knowledgeBlob: exactBlob });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes('NETWORK_FALSE_SOURCE_PROVENANCE')));
});

test('missing Network source Claim is a declared gap, never a qualified Function', () => {
  const net = knowledge.semanticAssuranceProfile.elements.find(x => x.profileId === 'SAP-CA-NETWORK');
  assert.deepEqual(net.claimRefs, []);
  assert.ok(net.obligations.every(x => x.qualification === 'NOT_QUALIFIED'));
  assert.equal(matrix.jobs.find(x => x.id === 'CA-JOB-15').semanticTrace.status,
    'NETWORK_DOMAIN_SEMANTICS_UNSOURCED');
  assert.equal(matrix.governance.disHandoff, 'BLOCKED');
});
