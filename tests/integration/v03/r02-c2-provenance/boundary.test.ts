import { describe, expect, it } from 'vitest';
import * as publicComputer from '../../../../packages/domain-computer/src/index.ts';
import * as publicHost from '../../../../packages/domain-host/src/index.ts';
import computerManifest from '../../../../packages/domain-computer/package.json' with { type: 'json' };
import hostManifest from '../../../../packages/domain-host/package.json' with { type: 'json' };
import { createPrivateHostObservationIssuer } from
  '../../../../packages/domain-host/src/observation/private-host-observation.ts';

describe('R02-C2 Host issuer public capability boundary', () => {
  it('does not export a Host issuer from either public workspace package', () => {
    expect('issueHostObjectObservation' in publicComputer).toBe(false);
    expect('createPrivateHostObservationIssuer' in publicHost).toBe(false);
    expect(computerManifest.exports).toEqual({ '.': './src/index.ts' });
    expect(hostManifest.exports).toEqual({ '.': './src/index.ts' });
  });

  it('issues only a scoped, current result from the trusted Host observer', async () => {
    let calls = 0;
    const issuer = createPrivateHostObservationIssuer({
      async observe(taskId) {
        calls++;
        return {
          sourceRef: 'host-observation:r02',
          revision: 'revision-1',
          taskId,
          observedObjectRefs: ['FOLDER:workspace'],
          observedAtUnixMs: 100,
          expiresAtUnixMs: 200,
        };
      },
    });
    expect(await issuer.issue('safe-task', 120)).toMatchObject({
      taskId: 'safe-task',
      sourceRef: 'host-observation:r02',
      observedObjectRefs: ['FOLDER:workspace'],
    });
    expect(await issuer.issue('safe-task', 200)).toBeNull();
    expect(await issuer.issue('../malicious', 120)).toBeNull();
    expect(calls).toBe(2);
  });
});
