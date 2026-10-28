// #212 T08-derived: a model suggestion can only become a candidate for a
// SEPARATE human choice of the existing fixed local C003 capability.
// This host-only component does not issue grants, approve plans, construct
// actions or verify effects. The original ActionController remains exclusive.
import { randomUUID } from 'node:crypto';
import { win32 } from 'node:path';
import { canonicalJson, type GoalRequest, GoalRequestSchema } from '@shun/contracts';
import type { CloudTypedProposalAdmission } from './cloud-proposal-admission.ts';
import type { ControlBackend } from './ports.ts';

// A host-owned, deliberately narrow fixed action class. Never treat generic
// "inspect"/"diagnose" text as permission to propose even bounded cleanup.
const EXPLICIT_CLEANUP_GOAL =
  'system.storage.diagnose_bounded_action: clean only cache in selected workspace';
const USER_CHOICE = 'C003_BOUNDED_LOCAL_STORAGE' as const;
const LEASE_MS = 60_000;
const MAX_PENDING = 16;

type LocalTaskSubmitter = Pick<ControlBackend, 'meta' | 'submitGoal'>;
type Refusal = 'CANDIDATE_REFUSED' | 'SELECTION_REFUSED' | 'LOCAL_HOST_UNAVAILABLE';

export type CloudLocalChoiceResult =
  | {
      ok: true;
      candidateId: string;
      expiresAt: string;
      userChoice: typeof USER_CHOICE;
    }
  | { ok: false; code: Refusal };

export type CloudLocalAdoptionResult =
  | { ok: true; taskId: string; nextStep: 'EXISTING_PLAN_PREVIEW_AND_ACTION_CONTROLLER' }
  | { ok: false; code: Refusal };

interface Pending {
  expiresMs: number;
}

const reject = (code: Refusal): { ok: false; code: Refusal } => ({ ok: false, code });

/**
 * Construction MUST be in a trusted real-storage Host, never an HTTP body or
 * model-supplied source. An opaque candidate is a one-time UI selection
 * correlation ID, explicitly NOT a plan approval token or grant.
 */
export class CloudLocalC003Adoption {
  readonly #backend: LocalTaskSubmitter;
  readonly #workspace: string;
  readonly #now: () => number;
  readonly #pending = new Map<string, Pending>();

  constructor(input: {
    backend: LocalTaskSubmitter;
    trustedWorkspace: string;
    now?: () => number;
  }) {
    if (
      !win32.isAbsolute(input.trustedWorkspace) ||
      !input.trustedWorkspace.trim() ||
      input.trustedWorkspace !== win32.normalize(input.trustedWorkspace)
    ) {
      throw new Error('C003_TRUSTED_WORKSPACE_REQUIRED');
    }
    this.#backend = input.backend;
    this.#workspace = input.trustedWorkspace;
    this.#now = input.now ?? Date.now;
  }

  /** Called by trusted host after #213's cloud admission, not from a raw DTO
   * or arbitrary user-supplied model text. Never submits an action. */
  offer(input: {
    originalHumanRequest: GoalRequest;
    admission: CloudTypedProposalAdmission;
  }): CloudLocalChoiceResult {
    if (!this.#readyHost()) return reject('LOCAL_HOST_UNAVAILABLE');
    const request = GoalRequestSchema.safeParse(input.originalHumanRequest);
    if (!request.success || input.admission.status !== 'TYPED_PROPOSAL_ONLY')
      return reject('CANDIDATE_REFUSED');

    const original = request.data;
    const proposal = input.admission.proposal.goalContract;
    if (
      original.goal !== proposal.objective ||
      original.goal !== EXPLICIT_CLEANUP_GOAL ||
      // This fixed C003 backend cannot prove it honored any additional user
      // constraints or verification intents. Refuse instead of discarding.
      canonicalJson(original.constraints) !== '{}' ||
      original.verificationIntent !== undefined ||
      canonicalJson(original.policyContext.environmentPolicy) !==
        canonicalJson({ allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false }) ||
      original.policyContext.privacyPolicy.localOnly ||
      original.policyContext.privacyPolicy.externalDisclosure === 'FORBIDDEN' ||
      input.admission.authorizationGranted !== false ||
      input.admission.effectExecuted !== false ||
      input.admission.normalization.status !== 'READY' ||
      proposal.taskId !== original.taskId ||
      proposal.ambiguityDisposition !== 'READY' ||
      !sameObjects(original.objects, proposal.objects) ||
      original.objects.length !== 1 ||
      original.objects[0]?.kind !== 'DIRECTORY' ||
      original.objects[0].ref !== this.#workspace ||
      canonicalJson(proposal.privacyPolicy) !==
        canonicalJson(original.policyContext.privacyPolicy) ||
      canonicalJson(proposal.environmentPolicy) !==
        canonicalJson(original.policyContext.environmentPolicy) ||
      canonicalJson(proposal.constraints) !== canonicalJson(original.constraints) ||
      canonicalJson(proposal.verificationIntent ?? null) !==
        canonicalJson(original.verificationIntent ?? null) ||
      proposal.lifecyclePolicy !== undefined
    )
      return reject('CANDIDATE_REFUSED');

    const now = this.#now();
    for (const [id, pending] of this.#pending) {
      if (pending.expiresMs <= now) this.#pending.delete(id);
    }
    if (this.#pending.size >= MAX_PENDING) return reject('CANDIDATE_REFUSED');

    const candidateId = randomUUID();
    const expiresMs = now + LEASE_MS;
    this.#pending.set(candidateId, { expiresMs });
    return {
      ok: true,
      candidateId,
      expiresAt: new Date(expiresMs).toISOString(),
      userChoice: USER_CHOICE,
    };
  }

  /** A new explicit local user selection only CREATES a pending C003 task.
   * The existing backend must then produce planHash preview and receive its
   * own independent human/policy approval before any effect is authorized.
   * This method cannot call ActionController or create an AuthorizedAction. */
  async select(input: {
    candidateId: string;
    userChoice: string;
  }): Promise<CloudLocalAdoptionResult> {
    const pending = this.#pending.get(input.candidateId);
    if (!pending) return reject('SELECTION_REFUSED');
    // Consume *before* async work, even for a wrong/stale selection or errors.
    // No replay after ambiguous submitGoal failure.
    this.#pending.delete(input.candidateId);
    if (pending.expiresMs <= this.#now() || input.userChoice !== USER_CHOICE)
      return reject('SELECTION_REFUSED');
    if (!this.#readyHost()) return reject('LOCAL_HOST_UNAVAILABLE');

    // Host-chosen fixed local C003 action, NEVER from model or browser text.
    // Existing RealStorageControlBackend.submitGoal independently rechecks
    // actual fixed workspace/currentness and runs ActionController gates.
    const localRequest = GoalRequestSchema.parse({
      taskId: randomUUID(),
      goal: 'storage bounded cleanup',
      objects: [{ kind: 'DIRECTORY', ref: this.#workspace }],
      constraints: {},
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    });
    try {
      const { taskId } = await this.#backend.submitGoal(localRequest);
      if (taskId !== localRequest.taskId) return reject('LOCAL_HOST_UNAVAILABLE');
      return {
        ok: true,
        taskId,
        nextStep: 'EXISTING_PLAN_PREVIEW_AND_ACTION_CONTROLLER',
      };
    } catch {
      return reject('LOCAL_HOST_UNAVAILABLE');
    }
  }

  #readyHost(): boolean {
    const state = this.#backend.meta();
    return state.simulated === false && state.localOnly === true && state.policy.kind === 'ACTIVE';
  }
}

function sameObjects(left: GoalRequest['objects'], right: GoalRequest['objects']): boolean {
  const identities = (objects: GoalRequest['objects']) =>
    objects.map((x) => `${x.kind}:${x.ref}`).sort();
  return canonicalJson(identities(left)) === canonicalJson(identities(right));
}
