/**
 * T03 semantic adapter: untrusted Goal/Proposal data becomes a typed semantic
 * selection only after strict Shun contract parsing, immutable authority-input
 * checks, Host-observation provenance checks, and deterministic registry
 * resolution. This module never calls a PlannerPort, Provider, Kernel, Host
 * effect, or authorization/approval API.
 */
import {
  type CapabilityDefinition,
  CapabilityDefinitionSchema,
  type GoalContract,
  GoalContractSchema,
  type GoalProposal,
  GoalProposalSchema,
  type GoalRequest,
  GoalRequestSchema,
  type ObjectRef,
} from '../../../contracts/src/index.ts';
import { type GoalNormalization, normalizeGoal } from '../../../resolver/src/normalize.ts';
import { RESOLVER_REVISION, type ShunRegistry } from '../../../resolver/src/registry.ts';

export const GOAL_SEMANTIC_SCHEMA = 'shun.goal-semantic.v1' as const;
export const HOST_OBJECT_OBSERVATION_SCHEMA = 'shun.host-object-observation.v1' as const;

export interface HostObjectObservationEvidence {
  readonly schema: typeof HOST_OBJECT_OBSERVATION_SCHEMA;
  /** Opaque durable reference issued by the trusted Host observation adapter. */
  readonly sourceRef: string;
  /** Host-issued observation revision; caller-computed hashes are not currentness proof. */
  readonly revision: string;
  /** Exact task/Case scope this observation was issued for. */
  readonly taskId: string;
  /** Exact typed object identities observed by the Host: KIND:ref. */
  readonly observedObjectRefs: readonly string[];
  /** Host-issued validity window; the semantic selector rechecks it at use time. */
  readonly issuedAtUnixMs: number;
  readonly expiresAtUnixMs: number;
}

export interface GoalSemanticProvenance {
  readonly source: 'REQUEST' | 'PLANNER_PROPOSAL';
  readonly resolverRevision: typeof RESOLVER_REVISION;
  readonly hostObservationRef?: string;
  readonly hostObservationRevision?: string;
  readonly proposalId?: string;
  /** Proposal evidence is retained as attribution only; it grants no authority. */
  readonly plannerEvidence?: NonNullable<GoalProposal['plannerEvidence']>;
}

export interface GoalSemantic {
  readonly schema: typeof GOAL_SEMANTIC_SCHEMA;
  readonly taskId: string;
  readonly goalContract: GoalContract;
  readonly capabilityId: string;
  readonly capabilityRevision: string;
  readonly provenance: GoalSemanticProvenance;
}

export type GoalSemanticRejectionCode =
  | 'REQUEST_SCHEMA_REFUSED'
  | 'PROPOSAL_SCHEMA_REFUSED'
  | 'PROPOSAL_EVIDENCE_MISSING'
  | 'PROPOSAL_TASK_SCOPE_MISMATCH'
  | 'PROPOSAL_OBJECT_SCOPE_CHANGED'
  | 'PROPOSAL_CONSTRAINTS_CHANGED'
  | 'PROPOSAL_PRIVACY_CHANGED'
  | 'PROPOSAL_ENVIRONMENT_CHANGED'
  | 'PROPOSAL_VERIFICATION_CHANGED'
  | 'PROPOSAL_LIFECYCLE_POLICY_UNAUTHORIZED'
  | 'PROPOSAL_NOT_READY'
  | 'HOST_OBSERVATION_REQUIRED'
  | 'HOST_OBSERVATION_INVALID'
  | 'HOST_OBSERVATION_UNTRUSTED_SOURCE'
  | 'HOST_OBSERVATION_EXPIRED'
  | 'HOST_OBSERVATION_REPLAY'
  | 'HOST_OBSERVATION_SCOPE_MISMATCH'
  | 'REGISTRY_CURRENTNESS_INSUFFICIENT'
  | 'CAPABILITY_SELECTION_INVARIANT'
  | 'CAPABILITY_DEFINITION_INVALID';

export type GoalSemanticSelection =
  | {
      readonly status: 'SELECTED';
      readonly semantic: GoalSemantic;
      /** Exact registered capability definition selected from the attested registry. */
      readonly capability: CapabilityDefinition;
    }
  | {
      readonly status: 'NOT_READY';
      readonly normalization: Extract<GoalNormalization, { status: 'NOT_READY' }>;
    }
  | {
      readonly status: 'REJECTED';
      readonly code: GoalSemanticRejectionCode;
      readonly detail: string;
    };

function rejected(code: GoalSemanticRejectionCode, detail: string): GoalSemanticSelection {
  return { status: 'REJECTED', code, detail };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, stableValue(record[key])]),
    );
  }
  return value;
}

function structurallyEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
}

function objectIdentity(object: ObjectRef): string {
  return `${object.kind}:${object.ref}`;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const entry of Object.values(value as Record<string, unknown>)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

/**
 * Module-private registries backing the Host-issued observation capability.
 * Accepted evidence is produced only by issueHostObjectObservation, which is
 * the trusted private Host Observation Port surface; a caller-constructed
 * plain object can never obtain the mark, so structural similarity to the
 * evidence shape is not Host provenance.
 */
const ISSUED_HOST_OBSERVATIONS = new WeakSet<object>();
const CONSUMED_HOST_OBSERVATIONS = new WeakSet<object>();

function safeUnixMs(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

/**
 * The only producer of evidence accepted by selectGoalSemantic. In the
 * single-process trusted-computing base, untrusted inputs (model output,
 * request JSON, UI data) are data and cannot execute code, so they cannot
 * call this issuer; process-internal code that should not mint evidence is
 * kept out by composition: only the trusted Host composition (T11) wires
 * this issuer to its private observation result. The issued value is frozen,
 * marked in a module-private WeakSet, and carries a Host-issued validity
 * window and exact task scope binding.
 */
export function issueHostObjectObservation(raw: unknown): HostObjectObservationEvidence | null {
  try {
    if (!isRecord(raw)) return null;
    const allowed = [
      'schema',
      'sourceRef',
      'revision',
      'taskId',
      'observedObjectRefs',
      'issuedAtUnixMs',
      'expiresAtUnixMs',
    ];
    const keys = Object.keys(raw);
    if (keys.length !== allowed.length || keys.some((key) => !allowed.includes(key))) return null;
    if (raw.schema !== HOST_OBJECT_OBSERVATION_SCHEMA) return null;
    if (
      typeof raw.sourceRef !== 'string' ||
      raw.sourceRef.trim().length === 0 ||
      raw.sourceRef.trim() !== raw.sourceRef
    )
      return null;
    if (
      typeof raw.revision !== 'string' ||
      raw.revision.trim().length === 0 ||
      raw.revision.trim() !== raw.revision
    )
      return null;
    if (
      typeof raw.taskId !== 'string' ||
      raw.taskId.trim().length === 0 ||
      raw.taskId.trim() !== raw.taskId
    )
      return null;
    if (
      !Array.isArray(raw.observedObjectRefs) ||
      !raw.observedObjectRefs.every(
        (entry) => typeof entry === 'string' && entry.length > 0 && entry.trim() === entry,
      )
    )
      return null;
    if (new Set(raw.observedObjectRefs).size !== raw.observedObjectRefs.length) return null;
    if (!safeUnixMs(raw.issuedAtUnixMs) || !safeUnixMs(raw.expiresAtUnixMs)) return null;
    if (raw.expiresAtUnixMs <= raw.issuedAtUnixMs) return null;
    const evidence: HostObjectObservationEvidence = Object.freeze({
      schema: HOST_OBJECT_OBSERVATION_SCHEMA,
      sourceRef: raw.sourceRef,
      revision: raw.revision,
      taskId: raw.taskId,
      observedObjectRefs: Object.freeze([...raw.observedObjectRefs]),
      issuedAtUnixMs: raw.issuedAtUnixMs,
      expiresAtUnixMs: raw.expiresAtUnixMs,
    });
    ISSUED_HOST_OBSERVATIONS.add(evidence);
    return evidence;
  } catch {
    return null;
  }
}

type ParsedHostObservation =
  | { readonly ok: true; readonly evidence: HostObjectObservationEvidence }
  | {
      readonly ok: false;
      readonly code:
        | 'HOST_OBSERVATION_INVALID'
        | 'HOST_OBSERVATION_UNTRUSTED_SOURCE'
        | 'HOST_OBSERVATION_EXPIRED';
    };

/**
 * The Host observation is an issued trusted capability result, not model data.
 * Acceptance requires the module-private issuance mark (never constructible
 * from a plain object), the frozen evidence shape, a live validity window at
 * the caller-provided now, and — checked by the caller — exact task scope.
 */
function parseHostObservation(value: unknown, nowUnixMs: number): ParsedHostObservation {
  if (!safeUnixMs(nowUnixMs)) return { ok: false, code: 'HOST_OBSERVATION_INVALID' };
  if (!isRecord(value)) return { ok: false, code: 'HOST_OBSERVATION_INVALID' };
  if (!ISSUED_HOST_OBSERVATIONS.has(value)) {
    return { ok: false, code: 'HOST_OBSERVATION_UNTRUSTED_SOURCE' };
  }
  const evidence = value as unknown as HostObjectObservationEvidence;
  if (evidence.schema !== HOST_OBJECT_OBSERVATION_SCHEMA) {
    return { ok: false, code: 'HOST_OBSERVATION_INVALID' };
  }
  if (nowUnixMs < evidence.issuedAtUnixMs || nowUnixMs > evidence.expiresAtUnixMs) {
    return { ok: false, code: 'HOST_OBSERVATION_EXPIRED' };
  }
  return { ok: true, evidence };
}

function proposalAuthorityRefusal(
  request: GoalRequest,
  proposal: GoalProposal,
): GoalSemanticSelection | null {
  const proposed = proposal.goalContract;
  if (proposed.taskId !== request.taskId) {
    return rejected(
      'PROPOSAL_TASK_SCOPE_MISMATCH',
      'proposal taskId differs from the user request',
    );
  }
  if (!structurallyEqual(proposed.objects, request.objects)) {
    return rejected(
      'PROPOSAL_OBJECT_SCOPE_CHANGED',
      'proposal changed the exact user-selected object set; model output cannot add, remove, or replace selected folders/objects',
    );
  }
  if (!structurallyEqual(proposed.constraints, request.constraints)) {
    return rejected(
      'PROPOSAL_CONSTRAINTS_CHANGED',
      'proposal changed user constraints; model output cannot weaken or replace request-owned constraints',
    );
  }
  if (!structurallyEqual(proposed.privacyPolicy, request.policyContext.privacyPolicy)) {
    return rejected(
      'PROPOSAL_PRIVACY_CHANGED',
      'proposal changed request-owned privacy policy; model output cannot broaden disclosure',
    );
  }
  if (!structurallyEqual(proposed.environmentPolicy, request.policyContext.environmentPolicy)) {
    return rejected(
      'PROPOSAL_ENVIRONMENT_CHANGED',
      'proposal changed request-owned environment policy',
    );
  }
  if (!structurallyEqual(proposed.verificationIntent, request.verificationIntent)) {
    return rejected(
      'PROPOSAL_VERIFICATION_CHANGED',
      'proposal changed or invented verification intent',
    );
  }
  if (proposed.lifecyclePolicy !== undefined) {
    return rejected(
      'PROPOSAL_LIFECYCLE_POLICY_UNAUTHORIZED',
      'proposal cannot invent a lifecycle/retention policy that has no request or Host authority source',
    );
  }
  if (proposed.ambiguityDisposition !== 'READY') {
    return rejected(
      'PROPOSAL_NOT_READY',
      'proposal cannot self-assert a non-ready or authoritative ambiguity disposition',
    );
  }
  if (proposal.plannerEvidence === undefined) {
    return rejected(
      'PROPOSAL_EVIDENCE_MISSING',
      'planner proposal lacks the frozen plannerEvidence provenance fields',
    );
  }
  return null;
}

/**
 * Select one typed Goal semantic S and one registered Capability B.
 *
 * A proposal may refine only the objective text. All user/Host authority
 * inputs are re-used unchanged. The resolver remains the sole owner of
 * capability matching and normalization. This function is synchronous and
 * never invokes a model/provider or creates a grant, approval, command, or
 * effect.
 */
export function selectGoalSemantic(input: {
  readonly request: unknown;
  readonly registry: ShunRegistry;
  /** Caller-provided current time; the Host observation window is checked against it. */
  readonly nowUnixMs: number;
  /** Only issueHostObjectObservation results are accepted; plain data is refused. */
  readonly hostObservation?: unknown;
  /** Already-produced untrusted proposal data; never a PlannerPort. */
  readonly proposal?: unknown;
}): GoalSemanticSelection {
  const requestResult = GoalRequestSchema.safeParse(input.request);
  if (!requestResult.success) {
    return rejected(
      'REQUEST_SCHEMA_REFUSED',
      'GoalRequest does not satisfy the frozen strict Shun schema',
    );
  }
  const request = requestResult.data;

  if (!input.registry.currentnessAttested) {
    return rejected('REGISTRY_CURRENTNESS_INSUFFICIENT', input.registry.currentnessExplanation);
  }

  let hostObservation: HostObjectObservationEvidence | undefined;
  let observedRefs: Set<string> | undefined;
  if (input.hostObservation !== undefined) {
    if (
      typeof input.hostObservation === 'object' &&
      input.hostObservation !== null &&
      CONSUMED_HOST_OBSERVATIONS.has(input.hostObservation)
    ) {
      return rejected(
        'HOST_OBSERVATION_REPLAY',
        'each Host-issued observation is single-use for one accepted selection; request a fresh Host observation',
      );
    }
    const parsedObservation = parseHostObservation(input.hostObservation, input.nowUnixMs);
    if (!parsedObservation.ok) {
      return rejected(
        parsedObservation.code,
        parsedObservation.code === 'HOST_OBSERVATION_UNTRUSTED_SOURCE'
          ? 'Host observation evidence must come from the private Host Observation Port via issueHostObjectObservation; caller-shaped data is never Host provenance'
          : parsedObservation.code === 'HOST_OBSERVATION_EXPIRED'
            ? 'the Host-issued observation validity window is not live at the provided now'
            : 'Host observation evidence is malformed or contains unrecognized fields',
      );
    }
    hostObservation = parsedObservation.evidence;
    if (hostObservation.taskId !== request.taskId) {
      return rejected(
        'HOST_OBSERVATION_SCOPE_MISMATCH',
        'the Host-issued observation was issued for a different task scope',
      );
    }
    observedRefs = new Set(hostObservation.observedObjectRefs);
  }

  if (request.objects.length > 0) {
    if (!hostObservation || !observedRefs) {
      return rejected(
        'HOST_OBSERVATION_REQUIRED',
        'referenced objects require a Host-issued observation reference and revision',
      );
    }
    const missing = request.objects.filter((object) => !observedRefs?.has(objectIdentity(object)));
    if (missing.length > 0) {
      return rejected(
        'HOST_OBSERVATION_SCOPE_MISMATCH',
        'Host observation does not cover every exact user-selected object; no model evidence can replace Host observation',
      );
    }
  }

  let objective = request.goal;
  let source: GoalSemanticProvenance['source'] = 'REQUEST';
  let proposal: GoalProposal | undefined;
  if (input.proposal !== undefined) {
    const proposalResult = GoalProposalSchema.safeParse(input.proposal);
    if (!proposalResult.success) {
      return rejected(
        'PROPOSAL_SCHEMA_REFUSED',
        'GoalProposal does not satisfy the frozen strict Shun schema; undeclared command/grant fields are refused',
      );
    }
    proposal = proposalResult.data;
    const authorityRefusal = proposalAuthorityRefusal(request, proposal);
    if (authorityRefusal) return authorityRefusal;
    objective = proposal.goalContract.objective;
    source = 'PLANNER_PROPOSAL';
  }

  const objectExists =
    request.objects.length > 0 && observedRefs
      ? (ref: string) =>
          (() => {
            const matching = request.objects.filter((object) => object.ref === ref);
            return (
              matching.length > 0 &&
              matching.every((object) => observedRefs?.has(objectIdentity(object)) === true)
            );
          })()
      : undefined;

  const normalization = normalizeGoal({
    request: { ...request, goal: objective },
    registry: input.registry,
    ...(objectExists === undefined ? {} : { objectExists }),
  });
  if (normalization.status === 'NOT_READY') {
    return { status: 'NOT_READY', normalization };
  }

  const matched = input.registry.matchCapabilities(normalization.goalContract.objective);
  if (matched.length !== 1 || !matched[0]) {
    return rejected(
      'CAPABILITY_SELECTION_INVARIANT',
      `resolver returned READY but registered capability match count was ${matched.length}; fail closed`,
    );
  }
  const registered = input.registry.capability(matched[0].capabilityId);
  if (!registered) {
    return rejected(
      'CAPABILITY_SELECTION_INVARIANT',
      'resolver-selected capability is absent from the current registry',
    );
  }

  const goalContractResult = GoalContractSchema.safeParse(normalization.goalContract);
  if (!goalContractResult.success) {
    return rejected(
      'CAPABILITY_SELECTION_INVARIANT',
      'normalized GoalContract failed the frozen strict schema',
    );
  }
  const capabilityResult = CapabilityDefinitionSchema.safeParse(registered);
  if (!capabilityResult.success) {
    return rejected(
      'CAPABILITY_DEFINITION_INVALID',
      'registry capability does not satisfy the frozen CapabilityDefinition schema',
    );
  }

  const provenance: GoalSemanticProvenance = deepFreeze({
    source,
    resolverRevision: RESOLVER_REVISION,
    ...(hostObservation
      ? {
          hostObservationRef: hostObservation.sourceRef,
          hostObservationRevision: hostObservation.revision,
        }
      : {}),
    ...(proposal
      ? {
          proposalId: proposal.proposalId,
          plannerEvidence: proposal.plannerEvidence,
        }
      : {}),
  });
  const semantic = deepFreeze({
    schema: GOAL_SEMANTIC_SCHEMA,
    taskId: goalContractResult.data.taskId,
    goalContract: goalContractResult.data,
    capabilityId: capabilityResult.data.capabilityId,
    capabilityRevision: capabilityResult.data.revision,
    provenance,
  }) satisfies GoalSemantic;

  // One accepted selection consumes the observation. Retried/failed
  // selections do not consume; a further accepted selection requires a fresh
  // Host-issued observation. Durable cross-process replay fencing stays with
  // the trusted Host observation adapter.
  if (typeof input.hostObservation === 'object' && input.hostObservation !== null) {
    CONSUMED_HOST_OBSERVATIONS.add(input.hostObservation);
  }

  return {
    status: 'SELECTED',
    semantic,
    capability: deepFreeze(capabilityResult.data),
  };
}
