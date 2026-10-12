// T10 B-040 real-host + sealed test-source adapter.
// Only consumes T09 public capability-inputs.json, never private/gold.json.
// A fixture-oracle PASS is NOT proof of zero network disclosure or T10 PASS.
import { readFile, writeFile, mkdir, realpath } from 'node:fs/promises';
import { resolve, relative, join, isAbsolute } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import {
  collectWindowsSupportContext,
  minimizeSupportContext,
  SupportReportSchema,
} from '../../packages/vertical-support/src/index.ts';

export const FIXTURE_SOURCE = 'inputs/B-040/support-context.json';
export const REPORT_RELATIVE = 'candidate/B-040/support-report.json';

function requireScoped(root, path) {
  const rel = relative(root, path);
  if (!rel || rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) {
    throw new Error('B040_PATH_SCOPE_REFUSED');
  }
}

async function loadPublicFixture(root) {
  const publicInput = JSON.parse(await readFile(join(root, 'public/capability-inputs.json'), 'utf8'));
  const subject = publicInput?.['B-040'];
  if (subject?.capability_id !== 'system.collect_support_context' ||
      subject?.privacy !== 'local-only' || subject?.source !== FIXTURE_SOURCE) {
    throw new Error('B040_PUBLIC_INPUT_MISMATCH');
  }
  const inputPath = resolve(root, FIXTURE_SOURCE);
  requireScoped(root, inputPath);
  const actual = await realpath(inputPath);
  requireScoped(root, actual);
  return JSON.parse(await readFile(actual, 'utf8'));
}

export function combineHostAndFixture(host, adversarial) {
  // These come from the *real* production collector and a *separate*
  // public adversarial fixture reduction, respectively.
  if (host?.localOnly !== true || !Array.isArray(host?.externalDisclosures) ||
      host.externalDisclosures.length !== 0) {
    throw new Error('B040_REAL_HOST_COLLECTION_NOT_LOCAL');
  }
  if (adversarial?.localOnly !== true ||
      !Array.isArray(adversarial?.report?.redactions) ||
      adversarial.report.redactions.length === 0) {
    throw new Error('B040_ADVERSARIAL_REDACTION_MISSING');
  }
  return SupportReportSchema.parse({
    schema: 'shun.support-context.v1',
    os: host.report.os,
    device: host.report.device,
    updates: host.report.updates,
    redactions: [...host.report.redactions, ...adversarial.report.redactions],
  });
}

export async function runB040({ fixtureRoot, observationFile }) {
  // Never provide a fake platform or execution callback to the public
  // collector. A non-Windows host is a hard failure, not simulated PASS.
  if (process.platform !== 'win32') {
    throw new Error('B040_REAL_WINDOWS_REQUIRED');
  }
  const root = await realpath(resolve(fixtureRoot));
  const observation = resolve(observationFile);
  requireScoped(root, join(root, REPORT_RELATIVE));
  const obsRelative = relative(root, observation);
  if (!obsRelative.startsWith('..') && !isAbsolute(obsRelative)) {
    throw new Error('B040_OBSERVATION_MUST_BE_OUTSIDE_FIXTURE_ROOT');
  }

  // Fixture lock MUST have been verified before this function runs. It is
  // intentionally not regenerated or resealed here.
  const fixtureRaw = await loadPublicFixture(root);
  const host = await collectWindowsSupportContext();
  const adversarial = minimizeSupportContext(fixtureRaw);
  const report = combineHostAndFixture(host, adversarial);
  const target = join(root, REPORT_RELATIVE);
  await mkdir(resolve(root, 'candidate/B-040'), { recursive: true });
  await writeFile(target, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });

  const evidence = {
    report_path: REPORT_RELATIVE,
    local_only: host.localOnly,
    external_disclosures: host.externalDisclosures,
    // This is a collector self-report. Independent Windows network capture
    // remains mandatory before any real-host zero-disclosure PASS claim.
    independent_network_capture: 'NOT_RUN',
    real_host_validation: 'NOT_RUN',
    fixture_oracle_status: 'NOT_RUN',
  };
  await writeFile(observation, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
  return { reportPath: target, observationFile: observation };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = new Map();
  for (let index = 2; index + 1 < process.argv.length; index += 2) {
    args.set(process.argv[index], process.argv[index + 1]);
  }
  const fixtureRoot = args.get('--root');
  const observationFile = args.get('--observation');
  if (!fixtureRoot || !observationFile || args.size !== 2) {
    console.error('Usage: node tests/integration/b040-run.mjs --root <verified T09 root> --observation <external new JSON>');
    process.exitCode = 2;
  } else {
    try {
      const result = await runB040({ fixtureRoot, observationFile });
      console.log(JSON.stringify({ ...result, scope: 'FIXTURE_ORACLE_CANDIDATE_ONLY', host_validation: 'NOT_RUN' }));
    } catch (error) {
      console.error(error instanceof Error ? error.message : 'B040_ADAPTER_FAILED');
      process.exitCode = 1;
    }
  }
}
