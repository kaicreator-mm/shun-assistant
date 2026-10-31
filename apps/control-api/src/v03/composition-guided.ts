/** Trusted Host-only initial Guided Case admission. Never available via HTTP.
 * The selected source is pinned by an operator-controlled SHA256 environment
 * value, not a Goal/Planner response; SQLite remains authoritative on restart.
 */
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import type { HostGuidedService } from
  '../../../../packages/domain-host/src/guided/host-guided-service.ts';

const HEX = /^[0-9a-f]{64}$/;

export function provisionGuidedCaseFromHostFile(input: {
  readonly service: HostGuidedService;
  readonly file: string;
  readonly sha256: string;
}): { readonly status: 'CURRENT' | 'RESTORED'; readonly stepId: string } {
  if (!isAbsolute(input.file) || !HEX.test(input.sha256)) {
    throw new Error('GUIDED_HOST_CASE_MUST_BE_PINNED');
  }
  const file = resolve(input.file);
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(file) !== file ||
      stat.size > 262_144) throw new Error('GUIDED_HOST_CASE_UNTRUSTED_FILE');
  const bytes = readFileSync(file);
  if (createHash('sha256').update(bytes).digest('hex') !== input.sha256) {
    throw new Error('GUIDED_HOST_CASE_DIGEST_REFUSED');
  }
  const value = JSON.parse(bytes.toString('utf8')) as {
    observation: unknown;
    semanticSelection: unknown;
    scope: unknown;
  };
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('|') !==
        ['observation', 'scope', 'semanticSelection'].sort().join('|')) {
    throw new Error('GUIDED_HOST_CASE_SCHEMA_REFUSED');
  }
  const current = input.service.state().currentStep;
  if (current) {
    const observation = value.observation as { taskId?: unknown; caseRef?: unknown };
    if (observation?.taskId !== current.taskId ||
        JSON.stringify(observation.caseRef) !== JSON.stringify(current.caseRef)) {
      throw new Error('GUIDED_HOST_CASE_RESTART_IDENTITY_MISMATCH');
    }
    return { status: 'RESTORED', stepId: current.stepId };
  }
  const staged = input.service.stageTrustedSelection(value);
  if (staged.status !== 'CURRENT') {
    throw new Error('GUIDED_HOST_CASE_STAGE_REFUSED:' + staged.code);
  }
  return { status: 'CURRENT', stepId: staged.step.stepId };
}
