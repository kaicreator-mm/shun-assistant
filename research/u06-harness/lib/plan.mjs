// U-06 demo: ActionPlan / AuthorizedAction / approval construction.
// Shapes follow shun-assistant docs/architecture/L2-v0.1.md §4.5–4.7.
// planHash = sha256(canonical JSON of ActionPlan without its planHash field).
import { createHash } from "node:crypto";

export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

export function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// plan: ActionPlan without planHash. Returns ActionPlan with planHash bound.
// The hash covers the plan with the planHash key fully absent (key, not null).
export function planWithoutHash(plan) {
  const copy = { ...plan };
  delete copy.planHash;
  return copy;
}

export function withPlanHash(plan) {
  const planHash = sha256(canonical(planWithoutHash(plan)));
  return { ...planWithoutHash(plan), planHash };
}

// Approval record: authorization bound to the exact planHash (L2 §4.6).
export function makeApproval({ planHash, approver, ttlSeconds = 600, authorizationKind = "explicit-approval" }) {
  const now = new Date().toISOString();
  return {
    approvalId: "appr-" + sha256(planHash + now).slice(0, 12),
    authorizationKind,
    planHash,
    approver,
    approvedAt: now,
    expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
  };
}

// AuthorizedAction envelope (L2 §4.6) + attached plan so the privileged helper
// can recompute the hash across the boundary (the plan travels as typed JSON on
// disk, never as shell command text).
export function makeAuthorizedAction({ plan, approval, requiredPrivilege, scope, timeoutMs, steps, fault = null, cancelFile = null }) {
  const action = {
    kind: "u06.sequence",
    requiredPrivilege,
    scope,
    timeoutMs,
    cancelFile,
    steps,
    fault,
  };
  return {
    schemaVersion: "u06-demo/1",
    taskId: plan.taskId,
    actionId: "act-" + sha256(plan.planHash + steps.length + steps[0]?.op).slice(0, 12),
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    authorizationKind: approval.authorizationKind,
    authorizationRef: { approvalId: approval.approvalId, approvalFile: null },
    expiresAt: approval.expiresAt,
    action,
    plan,
    approval,
  };
}

// Action Controller-side validation (mirror of the helper's own checks).
// The helper re-validates everything inside the privileged boundary; this
// pre-check exists so refusals that need no privilege never trigger UAC.
export function validateAuthorizedAction(env) {
  const problems = [];
  if (env.schemaVersion !== "u06-demo/1") problems.push("schemaVersion");
  if (!/^[0-9a-f]{64}$/.test(env.planHash || "")) problems.push("planHash format");
  if (env.authorizationKind !== "explicit-approval") problems.push("authorizationKind must be explicit-approval");
  if (env.action?.kind !== "u06.sequence") problems.push("unknown action kind");
  const ops = new Set([
    "proc.elevated-context-check",
    "fs.write", "fs.delete", "fs.verify",
    "reg.create", "reg.set", "reg.delete", "reg.verify",
    "winget.inventory", "winget.install", "winget.uninstall", "winget.verify",
  ]);
  for (const step of env.action?.steps ?? []) {
    if (!ops.has(step.op)) problems.push("unknown op: " + step.op);
  }
  if (!Array.isArray(env.action?.steps) || env.action.steps.length === 0) problems.push("no steps");
  // planHash integrity: the attached plan must hash to the envelope planHash
  const recomputed = sha256(canonical(planWithoutHash(env.plan ?? {})));
  if (recomputed !== env.planHash) problems.push("plan hash mismatch (plan tampered)");
  // approval binding
  if (env.approval?.planHash !== env.planHash) problems.push("approval not bound to this planHash");
  if (env.authorizationRef?.approvalId !== env.approval?.approvalId) problems.push("authorizationRef mismatch");
  return { ok: problems.length === 0, problems };
}
