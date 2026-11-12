import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const knowledge = JSON.parse(readFileSync(
  new URL('../../docs/dke/implementation/COMPUTER_ASSISTANT_KNOWLEDGE_R0.json', import.meta.url),
  'utf8',
));
const network = knowledge.semanticAssuranceProfile.elements.find(
  (entry) => entry.profileId === 'SAP-CA-NETWORK',
);
const element = knowledge.elements.find((entry) => entry.id === 'CA-NETWORK');
const cq = knowledge.competencyQuestions.find((entry) => entry.id === 'CQ-CA-010');
const policySources = ['SRC-PRODUCT-FREEZE', 'SRC-PRODUCT-PRD', 'SRC-PRODUCT-L1'];

function isBoundedNetworkSourceClaim(profile) {
  return profile?.claimRefs?.length === 0 &&
    profile.obligations?.length === 3 &&
    profile.sourceRefs?.every((id) => policySources.includes(id)) &&
    profile.obligations.every((obligation) =>
      obligation.sourceRefs?.every((id) => policySources.includes(id)) &&
      obligation.sourceQualification === 'PRODUCT_SCOPE_ONLY_NETWORK_TECHNICAL_EVIDENCE_MISSING' &&
      obligation.validationState === 'NOT_RUN' &&
      obligation.qualification === 'NOT_QUALIFIED' &&
      ['positiveCase', 'negativeCase', 'unknownCase'].every(
        (key) => typeof obligation[key] === 'string' && obligation[key].length > 0,
      ),
    );
}

test('unqualified CA-NETWORK cannot cite disk, WinGet, PnP or storage as network-specific SAP evidence', () => {
  assert.ok(isBoundedNetworkSourceClaim(network));
  assert.deepEqual(network.sourceRefs, policySources);
  assert.deepEqual(network.obligations.map((x) => x.id), [
    'SAP-CA-NETWORK-01', 'SAP-CA-NETWORK-02', 'SAP-CA-NETWORK-03',
  ]);
  assert.deepEqual(element.sourceClaims, []);
  assert.deepEqual(cq.sourceRefs, []);
  assert.equal(cq.validationState, 'NOT_RUN');
});

test('changing unrelated disk/driver publisher cannot directly invalidate any network SAP', () => {
  const unrelated = [
    'EXT-PHYSICAL-DISK', 'EXT-WINGET-OVERVIEW', 'EXT-PNP-GET', 'EXT-DISK-MGMT',
    'EXT-DISK-INITIALIZE', 'EXT-PNPUTIL', 'SRC-STORAGE-EXECUTE',
    'SRC-JIT-ORCHESTRATOR',
  ];
  for (const sourceId of unrelated) {
    assert.equal(network.sourceRefs.includes(sourceId), false);
    assert.ok(network.obligations.every((row) => !row.sourceRefs.includes(sourceId)));
  }
  assert.ok(knowledge.semanticAssuranceProfile.elements.some((profile) =>
    profile.element !== 'CA-NETWORK' &&
    profile.obligations.some((row) => row.sourceRefs.includes('EXT-PHYSICAL-DISK')),
  ), 'disk source is still used where it is relevant');
});

test('injecting a false cross-domain source into network profile or a single obligation must fail', () => {
  const forgedProfile = { ...network, sourceRefs: [...network.sourceRefs, 'EXT-PHYSICAL-DISK'] };
  assert.equal(isBoundedNetworkSourceClaim(forgedProfile), false);
  const forgedRow = { ...network.obligations[0],
    sourceRefs: [...network.obligations[0].sourceRefs, 'EXT-PNPUTIL'] };
  assert.equal(isBoundedNetworkSourceClaim({
    ...network, obligations: [forgedRow, ...network.obligations.slice(1)],
  }), false);
});

test('network requires actual domain Source Claim, future Oracle and approval before promotion', () => {
  assert.equal(network.evidenceGap, 'NO_QUALIFIED_NETWORK_DOMAIN_SOURCE_CLAIM_OR_EXTERNAL_ORACLE');
  assert.equal(element.scopeContract.knowledgeSourceGap,
    'UNSOURCED_NETWORK_DOMAIN_CLAIM_AND_CQ_UNQUALIFIED');
  assert.ok(network.obligations.every((x) => x.oracle.includes('MISSING')));
  assert.ok(network.obligations.every((x) => x.qualification === 'NOT_QUALIFIED'));
  assert.ok(network.obligations.every((x) => x.evidenceRefs.length === 0));
});
