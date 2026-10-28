import type { GoalProposal, GoalRequest } from '@shun/contracts';
import { ShunRegistry } from '@shun/resolver';
import { describe, expect, it } from 'vitest';
import {
  bindingDef,
  capabilityDef,
  goalRequest,
  providerDef,
} from '../../../packages/resolver/test/scenarios.ts';
import { admitTypedCloudProposal } from '../src/cloud-proposal-admission.ts';

function registry() {
  return ShunRegistry.fromSnapshot({
    capabilities: [capabilityDef({ capabilityId: 'image.batch_process' })],
    providers: [providerDef({ providerId: 'imageProvider.imagemagick' })],
    bindings: [bindingDef({
      bindingId: 'b-im',
      providerId: 'imageProvider.imagemagick',
      capabilityId: 'image.batch_process',
    })],
    environment: {
      environmentId: 'env',
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      arch: 'X64',
      observationRevision: 'obs-1',
      runtimeCapabilities: [],
      privilegeMode: 'FILTERED_ADMIN',
      guiSession: true,
      filesystemCapabilities: [],
      networkPolicy: 'POLICY_CONTROLLED',
      resources: { cpuCores: 4, memoryMb: 8192, freeDiskMb: 102400 },
    },
  });
}

function request(): GoalRequest {
  const r = goalRequest({ goal: 'make vacation photos smaller' });
  r.policyContext.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
  return r;
}

function typed(input: GoalRequest): GoalProposal {
  return {
    proposalId: 'model-proposal',
    // This is untrusted model-authored evidence and MUST be overwritten.
    plannerEvidence: { operationId: 'forged', modelEvidence: 'forged-model' },
    goalContract: {
      taskId: input.taskId,
      objective: 'image.batch_process: make my vacation photos smaller',
      objects: input.objects,
      constraints: input.constraints,
      privacyPolicy: input.policyContext.privacyPolicy,
      environmentPolicy: input.policyContext.environmentPolicy,
      ambiguityDisposition: 'READY',
    },
  };
}

function cloud(response: unknown, enabled = true) {
  let calls = 0;
  return {
    status: () => ({
      enabled, provider: 'deepseek' as const,
      model: 'deepseek-flash' as const, osConsentRequired: true as const,
    }),
    interpretGoal: async (_goal: string) => {
      calls++;
      return {
        ok: true as const,
        taskId: 'cloud-trusted-attempt',
        status: 'UNTRUSTED_REMOTE_PROPOSAL' as const,
        proposalText: typeof response === 'string' ? response : JSON.stringify(response),
        model: 'deepseek-flash' as const,
        costState: 'UNKNOWN_COST' as const,
        executed: false as const,
      };
    },
    calls: () => calls,
  };
}

describe('#212 T08-derived typed remote proposal admission, no action authority', () => {
  it('rejects LOCAL_ONLY before invoking a model or consent port', async () => {
    const r = request();
    r.policyContext.privacyPolicy.localOnly = true;
    const model = cloud(typed(r));
    const result = await admitTypedCloudProposal({ request: r, cloud: model, registry: registry() });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REFUSED', code: 'SCOPE_REFUSED',
      effectExecuted: false, authorizationGranted: false,
    });
    expect(model.calls()).toBe(0);
  });

  it('rejects disabled trusted host before model invocation', async () => {
    const r = request();
    const model = cloud(typed(r), false);
    const result = await admitTypedCloudProposal({ request: r, cloud: model, registry: registry() });
    expect(result.status).toBe('PROPOSAL_REFUSED');
    expect(model.calls()).toBe(0);
  });

  it('uses existing resolver to admit strict typed data, never an execution grant', async () => {
    const r = request();
    const model = cloud(typed(r));
    const result = await admitTypedCloudProposal({
      request: r, cloud: model, registry: registry(), objectExists: () => true,
    });
    expect(model.calls()).toBe(1);
    expect(result.status).toBe('TYPED_PROPOSAL_ONLY');
    if (result.status !== 'TYPED_PROPOSAL_ONLY') return;
    expect(result.normalization.status).toBe('READY');
    expect(result.effectExecuted).toBe(false);
    expect(result.authorizationGranted).toBe(false);
    expect(result.proposal.plannerEvidence).toEqual({
      operationId: 'cloud-trusted-attempt',
      modelEvidence: 'requested=deepseek-flash;immutable_model_revision=UNATTESTED',
    });
  });

  it('refuses raw prose rather than creating a typed goal from arbitrary model text', async () => {
    const r = request();
    const result = await admitTypedCloudProposal({
      request: r, cloud: cloud('please run a shell command to clean C:'),
      registry: registry(),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REFUSED', code: 'SCHEMA_REFUSED', effectExecuted: false,
    });
    expect(JSON.stringify(result)).not.toContain('shell command');
  });

  it('rejects model-added object scope and remote-controlled privacy changes', async () => {
    const r = request();
    const outOfScope = typed(r);
    outOfScope.goalContract.objects.push({ kind: 'DIRECTORY', ref: 'D:\\private' });
    const policy = typed(r);
    policy.goalContract.privacyPolicy = {
      localOnly: true, externalDisclosure: 'FORBIDDEN',
    };
    for (const malicious of [outOfScope, policy]) {
      const result = await admitTypedCloudProposal({
        request: r, cloud: cloud(malicious),
        registry: registry(), objectExists: () => true,
      });
      expect(result).toMatchObject({
        status: 'PROPOSAL_REFUSED', code: 'SCOPE_REFUSED',
        authorizationGranted: false,
      });
    }
  });

  it('keeps a valid typed model proposal NOT_READY when observed object proof is absent', async () => {
    const r = request();
    const result = await admitTypedCloudProposal({
      request: r, cloud: cloud(typed(r)), registry: registry(),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_NOT_READY', code: 'UNRESOLVED',
      authorizationGranted: false, effectExecuted: false,
    });
  });
});
