import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const root = new URL('../../', import.meta.url);
const content = (relative) => readFileSync(new URL(relative, root));
const json = (relative) => JSON.parse(content(relative).toString('utf8'));
const knowledgePath = 'docs/dke/implementation/COMPUTER_ASSISTANT_KNOWLEDGE_R0.json';
const packetPath = 'docs/dke/qualification/OWNER_ORACLE_75_SAP_ADJUDICATION_R13.json';
const ledgerPath = 'docs/dke/qualification/PROJECT_OWNER_DELEGATED_SCOPE_DECISIONS_R14.json';
const model = json(knowledgePath);
const memory = json('docs/dke/implementation/PERFORMANCE_MEMORY_EXTENSION_R0.json');
const r2 = json('docs/dke/demos/memory-performance-r0/dke-semantic/SOURCE_FIRST_KNOWLEDGE_DELTA_R2.json');
const packet = json(packetPath);
const delegated = json(ledgerPath);
const sourceBlob = (relative) => {
  const raw = content(relative);
  return createHash('sha1').update(Buffer.from(`blob ${raw.length}\0`)).update(raw).digest('hex');
};
const sourceRows = [
  ...model.semanticAssuranceProfile.elements.flatMap(p => p.obligations),
  ...memory.semanticAssuranceProfiles.flatMap(p => p.obligations),
  ...r2.sapObligations,
];
const sourceById = new Map(sourceRows.map(x => [x.id, x]));
const packetById = new Map(packet.sapObligations.map(x => [x.id, x]));
const ledgerById = new Map(delegated.rows.map(x => [x.sapId, x]));
const sourceRefs = (row) => row.sourceRefs;

test('R13 75 SAP packet is pinned to exact changed knowledge Git Blob, not historical R8 bytes', () => {
  assert.equal(sourceBlob(knowledgePath), 'da8425d82f3725c10bce92d206bbb8adfd6e7169');
  assert.equal(packet.sourceDocuments.find(x => x.path === knowledgePath).gitBlob,
    sourceBlob(knowledgePath));
  assert.equal(packet.previousSourcePacket.gitBlob, '943333f699124f4c66679e01fa764cd4429ed593');
  assert.equal(packet.sourceDocuments.length, 3);
  assert.equal(packet.summary.qualifiedSap, 0);
});

test('all 75 authoritative SAP rows match current source and delegated source-scope ledger', () => {
  assert.equal(sourceRows.length, 75);
  assert.equal(sourceById.size, 75);
  assert.equal(packetById.size, 75);
  assert.equal(ledgerById.size, 75);
  for (const [id, original] of sourceById) {
    const expected = sourceRefs(original);
    assert.deepEqual(packetById.get(id)?.sourceRefs, expected, id + ' packet');
    assert.deepEqual(ledgerById.get(id)?.sourceRefs, expected, id + ' delegated scope');
    assert.equal(packetById.get(id)?.sapQualification, 'NOT_QUALIFIED', id);
    assert.equal(packetById.get(id)?.ownerDecision, 'PENDING_NOT_ATTESTED', id);
    assert.equal(ledgerById.get(id)?.projectOwnerDelegatedDecision, 'NARROW', id);
  }
});

test('Network future candidate has no false external evidence and remains unqualified', () => {
  const required = ['SRC-PRODUCT-FREEZE', 'SRC-PRODUCT-PRD', 'SRC-PRODUCT-L1'];
  for (const id of ['SAP-CA-NETWORK-01','SAP-CA-NETWORK-02','SAP-CA-NETWORK-03']) {
    assert.deepEqual(packetById.get(id).sourceRefs, required);
    assert.deepEqual(ledgerById.get(id).sourceRefs, required);
    assert.deepEqual(ledgerById.get(id).externalPublisherRefs, []);
    assert.equal(packetById.get(id).independentOracle, 'NOT_RUN');
  }
  assert.equal(packet.sapObligations.filter(x=>x.sourceRefs.includes('EXT-PHYSICAL-DISK')).length,55);
  assert.equal(delegated.sourceScopeRepairR14.qualifiedNetworkSapCount,0);
});

test('mutating only R13 packet or a delegated source fails semantic source alignment', () => {
  const original = sourceById.get('SAP-CA-NETWORK-01');
  const fake = structuredClone(packetById.get('SAP-CA-NETWORK-01'));
  fake.sourceRefs.push('EXT-PHYSICAL-DISK');
  assert.notDeepEqual(fake.sourceRefs, sourceRefs(original));
  const fakeDelegation = structuredClone(ledgerById.get('SAP-CA-NETWORK-02'));
  fakeDelegation.externalPublisherRefs.push({id:'EXT-PHYSICAL-DISK'});
  assert.notDeepEqual(fakeDelegation.externalPublisherRefs, ledgerById.get('SAP-CA-NETWORK-02').externalPublisherRefs);
});
