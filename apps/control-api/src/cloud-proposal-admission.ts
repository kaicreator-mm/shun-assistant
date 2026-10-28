// #212 T08-derived source correction: admit already-consented remote model
// text into the existing typed resolver as *proposal data only*.
// No localhost route, issuer, model send, action grant, or side effect is
// exposed here. The host injects its genuine TrustedCloudInterpreter; a
// browser/LLM cannot inject a trustworthy CloudInterpretPort.
import {
  canonicalJson,
  GoalProposalSchema,
  GoalRequestSchema,
  type GoalProposal,
  type GoalRequest,
} from '@shun/contracts';
import {
  interpretGoalViaPlanner,
  remotePlannerAdapter,
  type ShunRegistry,
} from '@shun/resolver';
import type { CloudInterpretPort } from './cloud-interpret.ts';

export type CloudTypedProposalAdmission =
  | {
      status: 'TYPED_PROPOSAL_ONLY';
      proposal: GoalProposal;
      /** Existing resolver result; READY is not user/effect authority. */
      normalization: { status: 'READY' };
      effectExecuted: false;
      authorizationGranted: false;
    }
  | {
      status: 'PROPOSAL_NOT_READY' | 'PROPOSAL_REFUSED';
      code: 'UNRESOLVED' | 'REMOTE_UNAVAILABLE' | 'SCOPE_REFUSED' | 'SCHEMA_REFUSED';
      effectExecuted: false;
      authorizationGranted: false;
    };

const refused = (code: 'REMOTE_UNAVAILABLE' | 'SCOPE_REFUSED' | 'SCHEMA_REFUSED'):
  CloudTypedProposalAdmission => ({
  status: 'PROPOSAL_REFUSED',
  code,
  effectExecuted: false,
  authorizationGranted: false,
});

const equal = (a: unknown, b: unknown): boolean => canonicalJson(a) === canonicalJson(b);

/**
 * Called ONLY by trusted host composition with an original human GoalRequest.
 * The existing cloud port independently obtains private OS disclosure consent,
 * verifies current signed policy/budget and returns untrusted text. This
 * adapter may normalize a strict model-proposed GoalContract; it cannot
 * authorize or submit an effect. A separate user's plan/ActionController
 * approval and independently observed poststate remain mandatory.
 */
export async function admitTypedCloudProposal(input: {
  request: GoalRequest;
  cloud: Pick<CloudInterpretPort, 'status' | 'interpretGoal'>;
  registry: ShunRegistry;
  objectExists?: (ref: string) => boolean;
}): Promise<CloudTypedProposalAdmission> {
  try {
    const parsedRequest = GoalRequestSchema.safeParse(input.request);
    if (!parsedRequest.success) return refused('SCOPE_REFUSED');
    const request = parsedRequest.data;
    if (
      request.policyContext.privacyPolicy.localOnly ||
      request.policyContext.privacyPolicy.externalDisclosure === 'FORBIDDEN' ||
      request.constraints.other?.offline === true
    ) return refused('SCOPE_REFUSED');

    // This gate precedes the paid model call; no silent remote fallback.
    if (input.cloud.status().enabled !== true) return refused('REMOTE_UNAVAILABLE');
    const remote = await input.cloud.interpretGoal(request.goal);
    if (!remote.ok || remote.status !== 'UNTRUSTED_REMOTE_PROPOSAL' ||
      remote.executed !== false || remote.model !== 'deepseek-flash' ||
      remote.costState !== 'UNKNOWN_COST' || input.cloud.status().enabled !== true
    ) return refused('REMOTE_UNAVAILABLE');

    // No guessing, prose-to-command conversion, or model-issued grants.
    let json: unknown;
    try {
      json = JSON.parse(remote.proposalText);
    } catch {
      return refused('SCHEMA_REFUSED');
    }
    const parsed = GoalProposalSchema.safeParse(json);
    if (!parsed.success) return refused('SCHEMA_REFUSED');
    const contract = parsed.data.goalContract;
    const requestedObjects = new Set(request.objects.map((o) => `${o.kind}:${o.ref}`));
    if (
      contract.taskId !== request.taskId ||
      !equal(contract.privacyPolicy, request.policyContext.privacyPolicy) ||
      !equal(contract.environmentPolicy, request.policyContext.environmentPolicy) ||
      !equal(contract.constraints, request.constraints) ||
      !equal(contract.verificationIntent ?? null, request.verificationIntent ?? null) ||
      contract.lifecyclePolicy !== undefined ||
      contract.objects.some((o) => !requestedObjects.has(`${o.kind}:${o.ref}`))
    ) return refused('SCOPE_REFUSED');

    // Never trust model-supplied provenance. Bind it to the actual cloud
    // attempt returned by the separately private-consented host port.
    const proposal: GoalProposal = {
      proposalId: parsed.data.proposalId,
      goalContract: contract,
      plannerEvidence: {
        operationId: remote.taskId,
        modelEvidence: 'requested=deepseek-flash;immutable_model_revision=UNATTESTED',
      },
    };
    const normalized = await interpretGoalViaPlanner({
      request,
      registry: input.registry,
      objectExists: input.objectExists,
      adapter: remotePlannerAdapter({ interpretGoal: async () => proposal }),
    });
    if (normalized.status !== 'PROPOSAL_ACCEPTED') return refused('SCOPE_REFUSED');
    if (normalized.normalization.status !== 'READY') {
      return {
        status: 'PROPOSAL_NOT_READY',
        code: 'UNRESOLVED',
        effectExecuted: false,
        authorizationGranted: false,
      };
    }
    return {
      status: 'TYPED_PROPOSAL_ONLY',
      proposal: normalized.proposal,
      normalization: { status: 'READY' },
      effectExecuted: false,
      authorizationGranted: false,
    };
  } catch {
    // All errors are fixed strings; never reflect model/OS/user paths.
    return refused('REMOTE_UNAVAILABLE');
  }
}
