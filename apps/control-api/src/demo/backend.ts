// In-memory reference backend for the control surface (T08 demo double).
//
// NOT the Action Controller: this is a deterministic, clock-injected
// simulation of the workflow around the surface so the T08 deliverable is
// executable and testable before T01–T03 land. The authority rules it
// demonstrates are the frozen ones:
//   - approvals bind to the exact plan hash and are refused on any mismatch;
//   - unknown/expired policy states fail closed — an approval click cannot
//     override them (override forbidden);
//   - a trust failure cannot be converted into authorization by approval;
//   - recovery classifies from journal + post-state only; uncertain
//     destructive actions reconcile before any retry;
//   - residue is summarized readably, with itemized evidence on demand only;
//   - local-only goals disclose nothing externally (no planner evidence).
import {
  type ActionPlan,
  type ApprovalDecision,
  type ExecutionReceipt,
  type GoalContract,
  GoalContractSchema,
  type GoalRequest,
  type RecoveryClassification,
  type TaskState,
  type VerificationReceipt,
} from '@shun/contracts';
import { ControlError } from '../errors.ts';
import type {
  Clock,
  ControlBackend,
  DecisionOutcome,
  Outcome,
  PendingApproval,
  PlanPreview,
  PolicyState,
  ReadableResidue,
  ResidueDetail,
  TaskSnapshot,
} from '../ports.ts';
import {
  previewForPlan,
  requiresExplicitApproval,
  riskStatement,
  worstRiskClass,
} from '../preview.ts';
import {
  buildCleanupResidue,
  buildImageBatchPlan,
  buildStorageCleanupPlan,
  type DemoResidueItem,
  demoIntentFor,
  readableBytes,
} from './plans.ts';

const APPROVAL_WINDOW_MS = 15 * 60 * 1000;

interface DemoApprovalRecord {
  approvalId: string;
  taskId: string;
  planHash: string;
  requestSummary: string;
  evidenceRefs: string[];
  riskClass: PendingApproval['riskClass'];
  createdAt: string;
  expiresAt: string;
  status: 'PENDING' | 'APPROVED' | 'DECLINED' | 'EXPIRED';
}

interface DemoTask {
  taskId: string;
  title: string;
  request: GoalRequest;
  state: TaskState;
  revision: number;
  createdAt: string;
  updatedAt: string;
  progress: TaskSnapshot['progress'];
  clarification?: { question: string };
  failure?: { code: string; message: string };
  plan?: ActionPlan;
  approval?: DemoApprovalRecord;
  execution?: { terminal?: ExecutionReceipt['terminal']; startedAt?: string; finishedAt?: string };
  verification?: VerificationReceipt;
  recovery?: { classification: RecoveryClassification; detail: string; reconciled: boolean };
  residue?: DemoResidueItem[];
  /** Scripted execution outcome for this demo task. */
  script: {
    /** 'interrupt' leaves an uncertain journal window; 'fail-verify' fails semantic verification. */
    interruption?: 'UNCERTAIN';
    verifyFail?: boolean;
    trustBlocked?: boolean;
  };
  history: { journal: string[] };
}

export interface DemoBackendOptions {
  clock?: Clock;
  /** Initial displayed policy state; expiry is derived from the clock when `expiresAt` is set. */
  policy?: PolicyState;
}

const ISO = /^local:[A-Za-z0-9][A-Za-z0-9._/-]*$/;

function isoNow(clock: Clock): string {
  return clock();
}

function plusMs(clock: Clock, ms: number): string {
  return new Date(Date.parse(clock()) + ms).toISOString();
}

function note(at: string, state: TaskState, text?: string): TaskSnapshot['progress'][number] {
  return text ? { at, state, note: text } : { at, state };
}

/**
 * Deterministic reference backend behind the control surface. All mutating
 * transitions are private; the public methods are exactly the ControlBackend
 * seam the API layer talks to.
 */
export class DemoShunBackend implements ControlBackend {
  private clock: Clock;
  private policy: PolicyState;
  private readonly tasks = new Map<string, DemoTask>();
  private readonly evidenceStore = new Map<string, unknown>();
  private seq = 0;

  constructor(options: DemoBackendOptions = {}) {
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.policy = options.policy ?? { kind: 'ACTIVE', revision: 'pol-snap-2026-10-10-a' };
  }

  meta(): { policy: PolicyState; localOnly: true } {
    return { policy: this.policy, localOnly: true };
  }

  /** Test/demo hook: pin the clock so expiry/decision timing is deterministic. */
  advanceClockTo(instant: string): void {
    const fixed = instant;
    this.clock = () => fixed;
  }

  /** Test/demo hook: corrupt or expire the displayed policy state. */
  setPolicy(policy: PolicyState): void {
    this.policy = policy;
  }

  private nextTaskId(now: string): string {
    this.seq += 1;
    return `task-${now.slice(0, 10)}-${String(this.seq).padStart(3, '0')}`;
  }

  private transition(task: DemoTask, state: TaskState, at: string, noteText?: string): void {
    task.state = state;
    task.revision += 1;
    task.updatedAt = at;
    task.progress.push(note(at, state, noteText));
  }

  async submitGoal(request: GoalRequest): Promise<{ taskId: string }> {
    const now = isoNow(this.clock);
    const intent = demoIntentFor(request.goal);
    const taskId = this.nextTaskId(now);
    // The goal contract is normalized through the frozen schema: the surface
    // displays a validated contract, never a raw proposal.
    const contract: GoalContract = GoalContractSchema.parse({
      taskId,
      objective: request.goal,
      objects: request.objects,
      constraints: request.constraints,
      privacyPolicy: request.policyContext.privacyPolicy,
      environmentPolicy: request.policyContext.environmentPolicy,
      lifecyclePolicy:
        request.constraints.retainRemove === 'JIT_REMOVE_AFTER_VERIFIED_USE'
          ? { retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' }
          : undefined,
      verificationIntent: request.verificationIntent,
      ambiguityDisposition: intent === 'clarify' ? 'NEEDS_CLARIFICATION' : 'READY',
    });
    const task: DemoTask = {
      taskId,
      title: contract.objective,
      request,
      state: 'RECEIVED',
      revision: 0,
      createdAt: now,
      updatedAt: now,
      progress: [],
      script: {
        interruption: request.goal.toLowerCase().includes('interrupt') ? 'UNCERTAIN' : undefined,
        verifyFail: request.goal.toLowerCase().includes('fail-verify'),
        trustBlocked: request.goal.toLowerCase().includes('untrusted-provider'),
      },
      history: { journal: [] },
    };
    this.tasks.set(taskId, task);
    this.transition(task, 'RECEIVED', now, `Goal received: “${contract.objective}”`);
    this.transition(task, 'INTERPRETING', now);

    if (intent === 'clarify') {
      task.clarification = {
        question:
          'Your goal looks incomplete. Which files or locations should this task operate on, and what exactly should change?',
      };
      this.transition(task, 'CLARIFICATION', now, task.clarification.question);
      return { taskId };
    }

    this.resolveAndPlan(task, intent, now);
    return { taskId };
  }

  private resolveAndPlan(
    task: DemoTask,
    intent: 'unresolvable' | 'cleanup' | 'images',
    now: string,
  ): void {
    this.transition(task, 'RESOLVING', now);
    if (intent === 'unresolvable') {
      // Typed resolution failure (L2 §13): the goal stays outside the
      // registry — the surface never offers to invent a capability.
      task.failure = {
        code: 'CAPABILITY_UNRESOLVED',
        message:
          'No capability in the current registry matches this goal. Shun will not improvise one; ' +
          'try rephrasing the goal or extend the registry deliberately.',
      };
      this.transition(task, 'FAILED', now, task.failure.message);
      return;
    }

    const plan =
      intent === 'cleanup'
        ? buildStorageCleanupPlan(task.taskId)
        : buildImageBatchPlan(task.taskId);
    task.plan = plan;
    if (intent === 'cleanup') {
      task.residue = buildCleanupResidue();
      // Residue detail is evidence-on-demand: each item's local ref resolves
      // in the evidence store; nothing points outside this process.
      this.evidenceStore.set('local:residue/summary', {
        taskId: task.taskId,
        items: task.residue.length,
      });
      for (const item of task.residue) this.evidenceStore.set(item.evidenceRef, item);
    }
    this.transition(
      task,
      'PLANNED',
      now,
      `A ${intent === 'cleanup' ? 'destructive (R2)' : 'bounded (R1)'} plan is ready.`,
    );

    if (requiresExplicitApproval(worstRiskClass(plan))) {
      const approvalId = `approval-${task.taskId}`;
      const expiresAt = plusMs(this.clock, APPROVAL_WINDOW_MS);
      task.approval = {
        approvalId,
        taskId: task.taskId,
        planHash: plan.planHash,
        requestSummary:
          intent === 'cleanup'
            ? 'Shun wants to delete 6 regenerable cache/log/orphan files (~76.2 MB) under the DemoApp folder. Your documents are excluded and will not be touched.'
            : 'Shun wants to run a bounded plan.',
        evidenceRefs: intent === 'cleanup' ? ['local:residue/summary'] : ['local:plan/binding'],
        riskClass: 'R2',
        createdAt: now,
        expiresAt,
        status: 'PENDING',
      };
      this.transition(
        task,
        'AWAITING_AUTHORIZATION',
        now,
        'Your explicit approval is required before anything runs (R2).',
      );
      return;
    }
    this.execute(task, now);
  }

  private execute(task: DemoTask, now: string): void {
    if (!task.plan) return;
    this.transition(task, 'EXECUTING', now, 'Running the approved plan.');
    task.execution = { startedAt: now };

    if (task.script.interruption === 'UNCERTAIN') {
      // Journal stops inside the [EXEC_START, EXEC_DONE) window: honestly
      // uncertain, never optimism (L2 §9.4).
      task.history.journal.push('EXEC_START');
      task.execution.terminal = 'UNCERTAIN';
      task.recovery = {
        classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        detail:
          'The execution journal stopped inside the step’s execution window. Shun does not know ' +
          'whether the step took effect, and will reconcile from the journal and the actual state before anything is retried.',
        reconciled: false,
      };
      this.transition(task, 'NEEDS_INTERVENTION', now, task.recovery.detail);
      return;
    }

    task.history.journal.push('EXEC_START', 'EXEC_DONE', 'RECEIPT_WRITTEN');
    task.execution.terminal = 'SUCCEEDED';
    task.execution.finishedAt = now;
    this.verify(task, now);
  }

  private verify(task: DemoTask, now: string): void {
    const plan = task.plan;
    if (!plan) return;
    this.transition(task, 'VERIFYING', now);
    const failed = task.script.verifyFail === true;
    const lastCheckIndex = plan.verificationPlan.checks.length - 1;
    task.verification = {
      taskId: task.taskId,
      verifierId: plan.verificationPlan.verifierId,
      verifierRevision: plan.verificationPlan.verifierRevision,
      status: failed ? 'FAIL' : 'PASS',
      checks: plan.verificationPlan.checks.map((check, index) => ({
        checkId: check.checkId,
        status: failed && index === lastCheckIndex ? 'FAIL' : 'PASS',
        detail:
          failed && index === lastCheckIndex
            ? 'Semantic verification failed: the outcome does not meet the precommitted success criteria. The task is not PASS.'
            : undefined,
      })),
      oracleInputs: plan.verificationPlan.oracle ?? {},
      evidenceRefs: [`local:verification/${task.taskId}`],
    };
    this.evidenceStore.set(`local:verification/${task.taskId}`, task.verification);
    if (failed) {
      task.failure = {
        code: 'QUALITY_ORACLE_FAILED',
        message:
          'The result was produced but failed semantic verification. Nothing is reported as success; ' +
          'you can inspect the evidence or discard the output.',
      };
      task.recovery = {
        classification: 'COMPLETED_VERIFIED',
        detail: 'The step ran and its post-state was verified; the outcome failed verification.',
        reconciled: true,
      };
      this.transition(task, 'FAILED', now, task.failure.message);
      return;
    }
    task.recovery = {
      classification: 'COMPLETED_VERIFIED',
      detail: 'Execution completed and the post-state was independently verified.',
      reconciled: true,
    };
    this.transition(task, 'SUCCEEDED', now, 'Verified — the task is complete.');
  }

  // ---- surface reads ----

  async listTasks(): Promise<TaskSnapshot[]> {
    return [...this.tasks.values()].map((task) => this.snapshotOf(task));
  }

  async taskSnapshot(taskId: string): Promise<TaskSnapshot | undefined> {
    const task = this.tasks.get(taskId);
    return task ? this.snapshotOf(task) : undefined;
  }

  private snapshotOf(task: DemoTask): TaskSnapshot {
    const localOnly = task.request.policyContext.privacyPolicy.localOnly;
    const residue = task.residue
      ? summarizeResidue(task.residue, isoNow(this.clock), task.taskId)
      : undefined;
    return {
      taskId: task.taskId,
      title: task.title,
      state: task.state,
      revision: task.revision,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
      progress: [...task.progress],
      clarification: task.clarification,
      failure: task.failure,
      planSummary: task.plan
        ? {
            planHash: task.plan.planHash,
            capabilityId: task.plan.capabilityId,
            riskClass: worstRiskClass(task.plan),
            riskStatement: riskStatement(worstRiskClass(task.plan)),
            actionCount: task.plan.actions.length,
            policySnapshotRevision: task.plan.policySnapshotRevision,
          }
        : undefined,
      approval: task.approval
        ? {
            approvalId: task.approval.approvalId,
            status: task.approval.status,
            summary: task.approval.requestSummary,
            planHash: task.approval.planHash,
            expiresAt: task.approval.expiresAt,
          }
        : undefined,
      execution: task.execution,
      verification: task.verification
        ? {
            status: task.verification.status,
            checks: task.verification.checks.map((check) => ({
              checkId: check.checkId,
              status: check.status,
            })),
          }
        : undefined,
      recovery: task.recovery,
      residueSummary: residue ? { headline: residue.headline, groups: residue.groups } : undefined,
      localOnly: {
        enforced: localOnly,
        externalDisclosure: task.request.policyContext.privacyPolicy.externalDisclosure,
      },
    };
  }

  async taskPreview(taskId: string): Promise<PlanPreview | undefined> {
    const task = this.tasks.get(taskId);
    if (!task?.plan) return undefined;
    return previewForPlan(task.plan, {
      generatedAt: isoNow(this.clock),
      expiresAt: task.approval?.expiresAt,
    });
  }

  async pendingApprovals(): Promise<PendingApproval[]> {
    return [...this.tasks.values()]
      .map((task) => task.approval)
      .filter((approval): approval is DemoApprovalRecord => approval?.status === 'PENDING')
      .map((approval) => this.pendingView(approval));
  }

  async approvalWithPreview(
    approvalId: string,
  ): Promise<{ approval: PendingApproval; preview: PlanPreview } | undefined> {
    const task = [...this.tasks.values()].find(
      (candidate) => candidate.approval?.approvalId === approvalId,
    );
    if (!task?.approval || !task.plan) return undefined;
    return {
      approval: this.pendingView(task.approval),
      preview: previewForPlan(task.plan, {
        generatedAt: isoNow(this.clock),
        expiresAt: task.approval.expiresAt,
      }),
    };
  }

  private pendingView(approval: DemoApprovalRecord): PendingApproval {
    return {
      approvalId: approval.approvalId,
      taskId: approval.taskId,
      planHash: approval.planHash,
      summary: approval.requestSummary,
      evidenceRefs: [...approval.evidenceRefs],
      riskClass: approval.riskClass,
      requiresExplicitApproval: true,
      createdAt: approval.createdAt,
      expiresAt: approval.expiresAt,
    };
  }

  // ---- approval decision (fail-closed ladder) ----

  async decideApproval(input: {
    approvalId: string;
    approved: boolean;
    seenPlanHash: string;
    reason?: string;
  }): Promise<DecisionOutcome> {
    const now = isoNow(this.clock);
    const task = [...this.tasks.values()].find(
      (candidate) => candidate.approval?.approvalId === input.approvalId,
    );
    const approval = task?.approval;
    if (!task || !approval) {
      return {
        ok: false,
        code: 'APPROVAL_NOT_FOUND',
        detail: `No approval “${input.approvalId}” exists.`,
      };
    }
    if (approval.status !== 'PENDING') {
      return {
        ok: false,
        code: 'APPROVAL_ALREADY_DECIDED',
        detail: `Approval “${input.approvalId}” was already ${approval.status.toLowerCase()}.`,
      };
    }

    const policy = this.policy;
    if (policy.kind === 'UNKNOWN') {
      return {
        ok: false,
        code: 'POLICY_STATE_UNKNOWN',
        detail: `The current policy snapshot cannot be established (${policy.reason}). Approval is refused until policy currentness is restored — this cannot be overridden here.`,
      };
    }
    if (policy.kind === 'EXPIRED') {
      return {
        ok: false,
        code: 'POLICY_EXPIRED',
        detail: `The policy snapshot expired at ${policy.expiredAt}. Approval is refused until Shun re-resolves under a current snapshot — this cannot be overridden here.`,
      };
    }

    if (input.seenPlanHash !== approval.planHash) {
      return {
        ok: false,
        code: 'PLAN_HASH_MISMATCH',
        detail:
          'The plan changed after the preview you saw. This decision was not recorded; review the fresh preview and decide again.',
      };
    }
    if (approval.expiresAt && now > approval.expiresAt) {
      approval.status = 'EXPIRED';
      return {
        ok: false,
        code: 'APPROVAL_EXPIRED',
        detail: `The approval window closed at ${approval.expiresAt}. Ask Shun to re-plan and review the fresh preview.`,
      };
    }
    if (input.approved && task.script.trustBlocked) {
      return {
        ok: false,
        code: 'TRUST_BLOCKED',
        detail:
          'A provider trust failure is active for this task. Approval cannot convert untrusted provenance into authorization (fail-closed); the task needs a different, trusted provider.',
      };
    }

    const decision: ApprovalDecision = {
      approvalId: approval.approvalId,
      taskId: approval.taskId,
      planHash: approval.planHash,
      approved: input.approved,
      approvedBy: 'USER_APPROVAL',
      reason: input.reason,
    };
    approval.status = input.approved ? 'APPROVED' : 'DECLINED';
    if (input.approved) {
      task.history.journal.push('APPROVAL_RECORDED');
      this.execute(task, now);
    } else {
      this.transition(
        task,
        'CANCELLED',
        now,
        input.reason ?? 'You declined this plan. Nothing was executed.',
      );
    }
    return { ok: true, value: { decision, taskState: task.state } };
  }

  // ---- cancellation / clarification / recovery ----

  async cancelTask(taskId: string): Promise<Outcome<{ state: TaskState }>> {
    const now = isoNow(this.clock);
    const task = this.tasks.get(taskId);
    if (!task) return { ok: false, code: 'TASK_NOT_FOUND', detail: `No task “${taskId}”.` };
    if (task.state === 'EXECUTING') {
      const cancellable = task.plan?.actions.some(
        (action) => action.cancellation?.supported === true,
      );
      if (!cancellable) {
        return {
          ok: false,
          code: 'CANCEL_UNSUPPORTED',
          detail: 'This plan declared no cancellable steps, so cancellation is not supported.',
        };
      }
      task.history.journal.push('CANCEL_REQUESTED');
      task.execution = {
        terminal: 'CANCELLED',
        startedAt: task.execution?.startedAt,
        finishedAt: now,
      };
      task.recovery = {
        classification: 'FAILED_BEFORE_EFFECT',
        detail: 'Cancelled before the step completed; the journal shows no completed effect.',
        reconciled: true,
      };
      this.transition(task, 'CANCELLED', now, 'Cancelled. Nothing was left half-done.');
      return { ok: true, value: { state: task.state } };
    }
    if (
      task.state === 'AWAITING_AUTHORIZATION' ||
      task.state === 'CLARIFICATION' ||
      task.state === 'RESOLVING' ||
      task.state === 'PLANNED'
    ) {
      if (task.approval?.status === 'PENDING') task.approval.status = 'DECLINED';
      this.transition(task, 'CANCELLED', now, 'Cancelled before execution.');
      return { ok: true, value: { state: task.state } };
    }
    return {
      ok: false,
      code: 'CANCEL_INVALID_STATE',
      detail: `The task is ${task.state}; there is nothing running that can be cancelled from this state.`,
    };
  }

  async answerClarification(
    taskId: string,
    answer: string,
  ): Promise<Outcome<{ state: TaskState }>> {
    const now = isoNow(this.clock);
    const task = this.tasks.get(taskId);
    if (!task) return { ok: false, code: 'TASK_NOT_FOUND', detail: `No task “${taskId}”.` };
    if (task.state !== 'CLARIFICATION' || !task.clarification) {
      return {
        ok: false,
        code: 'CLARIFICATION_NOT_PENDING',
        detail: 'This task is not waiting for clarification.',
      };
    }
    task.clarification = undefined;
    task.title = `${task.title} — clarified: ${answer}`;
    this.transition(task, 'RESOLVING', now, `Clarification received: “${answer}”`);
    const intent = demoIntentFor(answer);
    if (intent === 'clarify') {
      task.failure = {
        code: 'GOAL_AMBIGUOUS',
        message:
          'The clarification still does not identify a concrete object or outcome. Task stopped.',
      };
      this.transition(task, 'FAILED', now, task.failure.message);
      return { ok: true, value: { state: task.state } };
    }
    this.resolveAndPlan(task, intent, now);
    return { ok: true, value: { state: task.state } };
  }

  async reconcileTask(
    taskId: string,
  ): Promise<Outcome<{ classification: RecoveryClassification }>> {
    const now = isoNow(this.clock);
    const task = this.tasks.get(taskId);
    if (!task) return { ok: false, code: 'TASK_NOT_FOUND', detail: `No task “${taskId}”.` };
    if (task.recovery?.classification !== 'MAY_HAVE_EXECUTED_UNCERTAIN') {
      return {
        ok: false,
        code: 'RECOVERY_NOT_APPLICABLE',
        detail: 'There is no uncertain side effect to reconcile for this task.',
      };
    }
    // Reconcile from journal + post-state only (L2 §9.4). The demo post-state
    // check finds the declared expected outputs absent → the step provably
    // never completed its effect.
    task.recovery = {
      classification: 'FAILED_BEFORE_EFFECT',
      detail:
        'Reconciliation compared the journal and the actual state against the plan’s declared expected state: ' +
        'the step never took effect. A retry is now provably safe.',
      reconciled: true,
    };
    task.execution = { terminal: 'FAILED', startedAt: task.execution?.startedAt, finishedAt: now };
    task.failure = {
      code: 'EXECUTION_INTERRUPTED',
      message:
        'Execution was interrupted. Reconciliation proved the step did not take effect; the task can be retried safely.',
    };
    this.transition(task, 'FAILED', now, task.recovery.detail);
    return { ok: true, value: { classification: task.recovery.classification } };
  }

  async retryTask(taskId: string): Promise<Outcome<{ state: TaskState }>> {
    const now = isoNow(this.clock);
    const task = this.tasks.get(taskId);
    if (!task) return { ok: false, code: 'TASK_NOT_FOUND', detail: `No task “${taskId}”.` };
    const classification = task.recovery?.classification;
    if (classification === 'MAY_HAVE_EXECUTED_UNCERTAIN') {
      return {
        ok: false,
        code: 'RETRY_BLOCKED_UNCERTAIN',
        detail:
          'It is not yet known whether the interrupted step took effect. Reconcile first — an uncertain destructive action is never blindly retried.',
      };
    }
    if (classification !== 'NOT_STARTED' && classification !== 'FAILED_BEFORE_EFFECT') {
      return {
        ok: false,
        code: 'RECOVERY_NOT_APPLICABLE',
        detail: 'This task has no recovery-pending side effect to retry.',
      };
    }
    task.script.interruption = undefined;
    this.transition(
      task,
      'EXECUTING',
      now,
      'Retrying the same action identity after a proven-safe recovery check.',
    );
    this.execute(task, now);
    return { ok: true, value: { state: task.state } };
  }

  // ---- residue / evidence (local-only disclosure) ----

  async residueSummary(
    taskId: string,
    detail: boolean,
  ): Promise<ResidueDetail | ReadableResidue | undefined> {
    const task = this.tasks.get(taskId);
    if (!task?.residue) return undefined;
    return summarizeResidue(task.residue, isoNow(this.clock), task.taskId, detail);
  }

  async evidence(ref: string): Promise<Outcome<{ ref: string; record: unknown }>> {
    // Local-only disclosure: only the `local:` scheme resolves, and only
    // inside this process's evidence store. URLs, paths and traversal
    // segments are never fetched.
    if (!ISO.test(ref) || ref.includes('..')) {
      return {
        ok: false,
        code: 'EVIDENCE_REF_INVALID',
        detail:
          'Evidence references must be local (“local:…”). This surface never fetches external evidence.',
      };
    }
    const record = this.evidenceStore.get(ref);
    if (record === undefined)
      return { ok: false, code: 'EVIDENCE_NOT_FOUND', detail: `No local evidence “${ref}”.` };
    return { ok: true, value: { ref, record } };
  }

  /** Demo hook so tests can store a fixture under a local ref. */
  putEvidence(ref: string, record: unknown): void {
    if (!ISO.test(ref))
      throw new ControlError('EVIDENCE_REF_INVALID', 'ref must be a local: reference');
    this.evidenceStore.set(ref, record);
  }
}

/** Readable aggregation (L2 §12): counts and human bytes; itemized detail only on demand. */
export function summarizeResidue(
  items: DemoResidueItem[],
  generatedAt: string,
  taskId: string,
  detail = false,
): ResidueDetail | ReadableResidue {
  const deletable = items.filter((item) => !item.classification.startsWith('PROTECTED'));
  const protectedItems = items.filter((item) => item.classification.startsWith('PROTECTED'));
  const groups = new Map<string, { count: number; bytes: number }>();
  for (const item of deletable) {
    const label =
      item.kind === 'CACHE'
        ? 'Regenerable cache files'
        : item.kind === 'LOG'
          ? 'Rotated log files'
          : 'Leftover files from removed software';
    const group = groups.get(label) ?? { count: 0, bytes: 0 };
    group.count += 1;
    group.bytes += item.sizeBytes;
    groups.set(label, group);
  }
  const totalBytes = deletable.reduce((sum, item) => sum + item.sizeBytes, 0);
  const base: ReadableResidue = {
    taskId,
    generatedAt,
    headline:
      `Found ${deletable.length} leftover items in ${groups.size} groups (${readableBytes(totalBytes)}). ` +
      `${protectedItems.length} protected file${protectedItems.length === 1 ? '' : 's'} detected — protected files are never touched by cleanup plans.`,
    groups: [...groups.entries()].map(([label, group]) => ({
      label,
      count: group.count,
      readableBytes: readableBytes(group.bytes),
    })),
    protectedUntouchedCount: protectedItems.length,
    detailAvailable: true,
  };
  if (!detail) return base;
  return {
    ...base,
    items: items.map((item) => ({
      path: item.path,
      kind: item.kind,
      sizeBytes: item.sizeBytes,
      classification: item.classification,
      evidenceRef: item.evidenceRef,
    })),
  };
}
