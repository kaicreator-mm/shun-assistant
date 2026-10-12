import assert from 'node:assert/strict';
import { test } from 'node:test';
import { combineHostAndFixture, FIXTURE_SOURCE, REPORT_RELATIVE } from './b040-run.mjs';

const secret = 'SHUN_FAKE_TOKEN_DO_NOT_EXPORT_7a9f3';
function host() {
  return {
    localOnly: true,
    externalDisclosures: [],
    report: {
      schema: 'shun.support-context.v1',
      os: { name: 'Windows', build: '26200' },
      device: { model: 'Actual Windows model' },
      updates: { last_check: '2026-10-12' },
      redactions: [],
    },
  };
}
function fixture() {
  return {
    localOnly: true,
    report: {
      redactions: [{ field: 'env[0].value', marker: '[REDACTED]' }],
      os: { name: secret, build: 'fixture' },
      device: { model: 'fixture' },
      updates: { last_check: 'fixture' },
    },
  };
}

test('uses real host sections and only bounded adversarial redaction metadata', () => {
  const report = combineHostAndFixture(host(), fixture());
  assert.equal(report.os.name, 'Windows');
  assert.equal(report.device.model, 'Actual Windows model');
  assert.deepEqual(report.redactions, [{ field: 'env[0].value', marker: '[REDACTED]' }]);
  assert.equal(JSON.stringify(report).includes(secret), false);
  assert.equal(FIXTURE_SOURCE, 'inputs/B-040/support-context.json');
  assert.equal(REPORT_RELATIVE, 'candidate/B-040/support-report.json');
});

test('rejects a nonlocal host collector result instead of inventing zero disclosure', () => {
  assert.throws(
    () => combineHostAndFixture({ ...host(), externalDisclosures: ['https://leak.example'] }, fixture()),
    /B040_REAL_HOST_COLLECTION_NOT_LOCAL/,
  );
  assert.throws(
    () => combineHostAndFixture({ ...host(), localOnly: false }, fixture()),
    /B040_REAL_HOST_COLLECTION_NOT_LOCAL/,
  );
});

test('rejects missing audit markers and unreviewed report metadata', () => {
  assert.throws(
    () => combineHostAndFixture(host(), { ...fixture(), report: { redactions: [] } }),
    /B040_ADVERSARIAL_REDACTION_MISSING/,
  );
  assert.throws(
    () => combineHostAndFixture(
      { ...host(), report: { ...host().report, os: { name: 'Windows', build: '1', bearer: secret } } },
      fixture(),
    ),
    undefined,
  );
});

test('does not run collector on a non-Windows host', async (t) => {
  if (process.platform === 'win32') {
    t.skip('real Windows collection belongs to the explicit local host gate');
    return;
  }
  const { runB040 } = await import('./b040-run.mjs');
  await assert.rejects(
    () => runB040({ fixtureRoot: '/unused', observationFile: '/unused-observation' }),
    /B040_REAL_WINDOWS_REQUIRED/,
  );
});
