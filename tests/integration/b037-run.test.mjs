import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveSharpForB037, OUTPUT_RELATIVE, REPORT_CASE } from './b037-run.mjs';

function facts(overrides = {}) {
  return {
    environmentId: 'source-test-local-windows',
    backendKind: 'LOCAL_WINDOWS',
    os: 'WINDOWS',
    arch: 'X64',
    observationRevision: 'source-test-1',
    runtimeCapabilities: ['sharp-libvips'],
    privilegeMode: 'STANDARD_USER',
    guiSession: true,
    filesystemCapabilities: ['read', 'write'],
    networkPolicy: 'OFFLINE',
    resources: { cpuCores: 4, memoryMb: 4096, freeDiskMb: 1024 },
    ...overrides,
  };
}

test('shared resolver selects the real sharp binding under no-network gates', async () => {
  const record = await resolveSharpForB037(facts());
  assert.equal(record.resolvedCapabilityId, 'image.batch_process');
  assert.equal(record.selectedBindingId, 'binding-image-sharp-i0-local');
  assert.equal(record.privacyDisclosurePlan.externalDisclosure, 'FORBIDDEN');
  assert.ok(record.hardGateDispositions.length >= 4);
  assert.ok(record.hardGateDispositions.every((row) => row.outcome === 'PASS'));
  assert.ok(record.selectionReasons.some((reason) => reason.includes('single trusted binding')));
});

test('resolver fails closed when the observed backend is not local Windows', async () => {
  await assert.rejects(
    () => resolveSharpForB037(facts({ backendKind: 'LOCAL_POSIX', os: 'LINUX' })),
    /B037_SHARED_RESOLUTION_FAILED/,
  );
});

test('integration constants remain tied to the frozen T09 case', () => {
  assert.equal(REPORT_CASE, 'B-037');
  assert.equal(OUTPUT_RELATIVE, 'candidate/B-037');
});
