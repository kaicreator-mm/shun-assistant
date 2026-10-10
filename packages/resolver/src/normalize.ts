// Goal-first normalization (L2 §4.1, C-000 resolver flow step 1–2).
//
// Deterministic and planner-free: the raw GoalRequest becomes the normalized
// GoalContract authority form only when it names exactly one registered
// capability, its objects resolve, its policies are self-consistent and the
// resolved capability is semantically verifiable. Ambiguity is first-class:
// every non-ready outcome is typed with both the ambiguity disposition and the
// frozen shared resolution failure code — never a silent guess.
import type {
  AmbiguityDisposition,
  GoalContract,
  GoalRequest,
  ResolutionFailure,
} from '@shun/contracts';
import type { ShunRegistry } from './registry.ts';

export type GoalNormalization =
  | { status: 'READY'; goalContract: GoalContract }
  | {
      status: 'NOT_READY';
      disposition: AmbiguityDisposition;
      failureCode: ResolutionFailure;
      detail: string;
    };

function notReady(
  disposition: AmbiguityDisposition,
  failureCode: ResolutionFailure,
  detail: string,
): GoalNormalization {
  return { status: 'NOT_READY', disposition, failureCode, detail };
}

export function normalizeGoal(input: {
  request: GoalRequest;
  registry: ShunRegistry;
  /** Observed-fact callback resolving object references; absent ⇒ assume resolvable (structured direct invocation). */
  objectExists?: (ref: string) => boolean;
}): GoalNormalization {
  const { request, registry, objectExists } = input;

  // Self-consistent privacy policy: local-only collection with allowed
  // external disclosure is a contradiction, not a configuration.
  if (
    request.policyContext.privacyPolicy.localOnly &&
    request.policyContext.privacyPolicy.externalDisclosure === 'ALLOWED'
  ) {
    return notReady(
      'NEEDS_CLARIFICATION',
      'GOAL_AMBIGUOUS',
      'privacy policy is contradictory: localOnly=true with externalDisclosure ALLOWED',
    );
  }

  // Objects must resolve, or the resolver reports which object is missing
  // (C-000 precondition). A proof source is REQUIRED whenever objects are
  // referenced (P2-01): the previous default — absent callback ⇒ assume
  // resolvable — silently treated unverified references as resolved. The
  // zero-object request keeps its fast path.
  if (request.objects.length > 0 && objectExists === undefined) {
    return notReady(
      'UNRESOLVED_OBJECT',
      'OBJECT_UNRESOLVED',
      `no observed-object proof source provided for ${request.objects.length} referenced object(s) — referenced objects require observed-object evidence and fail closed without it`,
    );
  }
  if (objectExists !== undefined) {
    for (const object of request.objects) {
      if (!objectExists(object.ref)) {
        return notReady(
          'UNRESOLVED_OBJECT',
          'OBJECT_UNRESOLVED',
          `referenced object not resolvable: ${object.kind} ${object.ref}`,
        );
      }
    }
  }

  // Capability resolution: exactly one registered capability, else typed ambiguity.
  const matched = registry.matchCapabilities(request.goal);
  if (matched.length === 0) {
    return notReady(
      'UNRESOLVED_CAPABILITY',
      'CAPABILITY_UNRESOLVED',
      'goal names no registered capability id or alias; free-form interpretation requires a PlannerPort backend (L2 §6.3)',
    );
  }
  if (matched.length > 1) {
    return notReady(
      'NEEDS_CLARIFICATION',
      'GOAL_AMBIGUOUS',
      `goal matches multiple capabilities (${matched.map((capability) => capability.capabilityId).join(', ')}); clarification required before resolution`,
    );
  }
  const capability = matched[0];
  if (!capability) {
    throw new Error('normalization invariant violated: empty single match');
  }

  // A goal whose capability declares no mandatory semantic check can never be
  // verified — execution success without semantic verification can never
  // become Task PASS (L2 §4.7), so the goal is unverifiable by construction.
  const requiredChecks = capability.verificationContract.checks.filter((check) => check.required);
  if (requiredChecks.length === 0) {
    return notReady(
      'VERIFICATION_UNSPECIFIABLE',
      'VERIFICATION_UNSPECIFIABLE',
      `capability ${capability.capabilityId} declares no required semantic check — outcome unverifiable`,
    );
  }

  const goalContract: GoalContract = {
    taskId: request.taskId,
    objective: request.goal,
    objects: request.objects,
    constraints: request.constraints,
    privacyPolicy: request.policyContext.privacyPolicy,
    environmentPolicy: request.policyContext.environmentPolicy,
    verificationIntent: request.verificationIntent,
    ambiguityDisposition: 'READY',
  };
  return { status: 'READY', goalContract };
}
