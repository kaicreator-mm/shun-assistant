/**
 * DomainHarness v0.9 N01 — Standard Basic's PURE WorkflowRouter decision.
 * This is an ESM-import-free package-internal source slice, not a public
 * Host port, a runnable Kernel, or an installed/qualified package by itself.
 * A selected Kernel MUST revalidate returned IDs, selected bindings, the
 * basis digest, and H-authorized caller/permit before any admission/effect.
 */
export const WORKFLOW_ROUTER_RESULT_KINDS = Object.freeze([
  'selected', 'missing', 'ambiguous', 'denied',
]);

export class WorkflowRouterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'WorkflowRouterError';
    this.code = code;
  }
}

const ID = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const SHA = /^sha256:[0-9a-f]{64}$/;
const BAD_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const MAX_LIST = 64;
const MAX_DEPTH = 16;

function refuse(code, message) {
  throw new WorkflowRouterError(code, message);
}

// Snapshot ordinary records before interpreting policy data. Accessors are
// rejected without reading; Proxy traps are not a sandbox and must be
// excluded by the protected Host before this pure package boundary.
function data(value, path = '$', depth = 0, seen = new WeakSet()) {
  if (depth > MAX_DEPTH) refuse('ROUTER_DATA_INVALID', `${path} depth exceeded`);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') refuse('ROUTER_DATA_INVALID', `${path} is not plain data`);
  if (seen.has(value)) refuse('ROUTER_DATA_INVALID', `${path} contains a cycle`);
  seen.add(value);
  try {
    const proto = Object.getPrototypeOf(value);
    if (Array.isArray(value)) {
      if (proto !== Array.prototype || value.length > MAX_LIST) {
        refuse('ROUTER_DATA_INVALID', `${path} has invalid array shape`);
      }
      const desc = Object.getOwnPropertyDescriptors(value);
      if (Reflect.ownKeys(desc).length !== value.length + 1) {
        refuse('ROUTER_DATA_INVALID', `${path} has array holes or extra keys`);
      }
      return Array.from({ length: value.length }, (_, index) => {
        const item = desc[String(index)];
        if (!item || !item.enumerable || !Object.hasOwn(item, 'value')) {
          refuse('ROUTER_DATA_INVALID', `${path} contains an accessor or hole`);
        }
        return data(item.value, `${path}[${index}]`, depth + 1, seen);
      });
    }
    if (proto !== Object.prototype && proto !== null) {
      refuse('ROUTER_DATA_INVALID', `${path} has an unexpected prototype`);
    }
    const desc = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(desc).length > MAX_LIST) {
      refuse('ROUTER_DATA_INVALID', `${path} has too many keys`);
    }
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(desc)) {
      const item = desc[key];
      if (typeof key !== 'string' || BAD_KEYS.has(key) || !item.enumerable || !Object.hasOwn(item, 'value')) {
        refuse('ROUTER_DATA_INVALID', `${path} has unsafe property`);
      }
      result[key] = data(item.value, `${path}.${key}`, depth + 1, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function obj(value, label, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    refuse('ROUTER_CONTRACT_INVALID', `${label} must be a record`);
  }
  if (Object.keys(value).some(key => !keys.includes(key))) {
    refuse('ROUTER_CONTRACT_INVALID', `${label} contains an unsupported field`);
  }
  return value;
}

function ident(value, label) {
  if (typeof value !== 'string' || !ID.test(value)) {
    refuse('ROUTER_CONTRACT_INVALID', `${label} must be a bounded identifier`);
  }
  return value;
}

/**
 * @param {unknown} request Untrusted plain-data proposal, NOT an authority.
 * @returns {{kind:'selected', operationId:string, capabilityId:string, handlerId:string, basisDigest:string} | {kind:'missing', intentId:string} | {kind:'ambiguous', intentId:string, candidateOperationIds:readonly string[]} | {kind:'denied', reasonCode:string}}
 */
export function routeWorkflowIntent(request) {
  const input = obj(data(request), 'router request', ['intentId', 'basisDigest', 'bindings', 'candidates']);
  const intentId = ident(input.intentId, 'intentId');
  if (typeof input.basisDigest !== 'string' || !SHA.test(input.basisDigest)) {
    refuse('ROUTER_CONTRACT_INVALID', 'basisDigest must be sha256:<64 lowercase hex>');
  }
  if (!Array.isArray(input.bindings) || !Array.isArray(input.candidates)) {
    refuse('ROUTER_CONTRACT_INVALID', 'bindings and candidates must be bounded arrays');
  }
  const allowed = new Map();
  for (const raw of input.bindings) {
    const b = obj(raw, 'selected BUILD binding', ['intentId', 'operationId', 'capabilityId', 'handlerId']);
    const bIntent = ident(b.intentId, 'binding.intentId');
    const op = ident(b.operationId, 'binding.operationId');
    const cap = ident(b.capabilityId, 'binding.capabilityId');
    const handler = ident(b.handlerId, 'binding.handlerId');
    const key = `${bIntent}\u0000${op}`;
    if (allowed.has(key)) refuse('ROUTER_BINDING_DUPLICATE', `duplicate selected operation ${op}`);
    allowed.set(key, { operationId: op, capabilityId: cap, handlerId: handler });
  }
  if (input.candidates.length === 0) return Object.freeze({ kind: 'missing', intentId });
  const candidates = [];
  const seenOps = new Set();
  for (const raw of input.candidates) {
    const c = obj(raw, 'router candidate', ['operationId', 'capabilityId', 'priority', 'eligibility']);
    const operationId = ident(c.operationId, 'candidate.operationId');
    const capabilityId = ident(c.capabilityId, 'candidate.capabilityId');
    if (!Number.isSafeInteger(c.priority) || c.priority < 0 || c.priority > 1_000_000) {
      refuse('ROUTER_CONTRACT_INVALID', 'candidate.priority must be a bounded nonnegative integer');
    }
    if (c.eligibility !== 'eligible' && c.eligibility !== 'denied') {
      refuse('ROUTER_CONTRACT_INVALID', 'candidate.eligibility must be eligible or denied');
    }
    if (seenOps.has(operationId)) refuse('ROUTER_CANDIDATE_DUPLICATE', `duplicate candidate ${operationId}`);
    seenOps.add(operationId);
    const selectedBinding = allowed.get(`${intentId}\u0000${operationId}`);
    if (!selectedBinding || selectedBinding.capabilityId !== capabilityId) {
      refuse('ROUTER_BINDING_MISMATCH', `candidate ${operationId} is not exactly BUILD selected`);
    }
    candidates.push({ ...selectedBinding, priority: c.priority, eligibility: c.eligibility });
  }
  const eligible = candidates.filter(c => c.eligibility === 'eligible');
  if (eligible.length === 0) {
    // Eligibility is a Standard proposal, never Kernel admission authority.
    return Object.freeze({ kind: 'denied', reasonCode: 'ROUTER_ELIGIBILITY_DENIED' });
  }
  const highest = Math.max(...eligible.map(c => c.priority));
  const top = eligible.filter(c => c.priority === highest);
  if (top.length > 1) {
    const candidateOperationIds = Object.freeze(top.map(c => c.operationId).sort());
    return Object.freeze({ kind: 'ambiguous', intentId, candidateOperationIds });
  }
  const chosen = top[0];
  return Object.freeze({
    kind: 'selected', operationId: chosen.operationId,
    capabilityId: chosen.capabilityId, handlerId: chosen.handlerId,
    basisDigest: input.basisDigest,
  });
}
