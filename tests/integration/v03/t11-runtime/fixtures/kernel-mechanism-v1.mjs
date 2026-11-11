/**
 * ============================================================================
 * Kernel Domain Package — v08-kernel-mechanism@1.0.0 mechanism module (T-C)
 * ============================================================================
 *
 * PHYSICAL selected Kernel Domain Package payload for v0.8 (Issue #1002).
 * This file IS the sealed executable module bytes of a `kernel`-kind package
 * under the frozen v0.8 qualified-package ABI (T-A, #1000 @a835cab):
 * `V8_QUALIFIED_ABI['v08-kernel-abi/1']` — required exports
 * `createOccurrenceRuntime` / `MODULE_ID` / `PACKAGE_KIND` / `ABI_VERSION` /
 * `ENDPOINTS` with the `occurrence-runtime` endpoint kind. Role→kind /
 * endpoint-existence / intent-advertiser binding integrity is enforced at
 * BUILD qualification and re-checked at load BEFORE import (P1-BIND-02);
 * this module CONSUMES the sealed bindings as authoritative and keeps NO
 * duplicate binding-validation copy.
 *
 * SELECTED-SOURCE REUSE (exact SHA, no recoding):
 *   - Primary reuse base: #994@b9ea4d1f42246c61d5382328788c50741cac8e43
 *     `experiments/v08-package-kernel-ownership-kpk01/src/producer/payload/kernel-mechanism-v1.mjs`
 *     (whose sections are the verbatim-logic migrations of the frozen v0.7
 *     sources pinned below, proven by KPK-14 side-by-side differential).
 *   - v0.7 blob pins (MIGRATION_MAP.json @ #994@b9ea4d1, all pinned at
 *     version/v0.7@86110c616b8cb18c730553e4cdab7ef555214521):
 *     workflow/predicate.ts e680f125…, admission/admission.ts 955ecf1f…,
 *     admission/effect-journal.ts c6ae1f98…, engine/per-instance-serialized-lane.ts
 *     d5a94501…, instance/persistent-workflow-instance.ts 3e225296…,
 *     engine/workflow-instance-engine.ts 10829999… (plus the non-authoritative
 *     canonical-identity / contracts / governance-subset blobs listed in
 *     MIGRATION_MAP.json). Same-project provenance; no third-party license.
 * Adaptations remain strictly mechanical and individually marked; every
 * authoritative decision path keeps the v0.7 logic and error text verbatim.
 *
 * T-C REPAIRS carried by these bytes (both test-first, RED→GREEN evidence in
 * PR #1002-bound branch `work/v08-tc-kernel-package-cas-v1`):
 *   1. P1-L2-CAS-01 (#999/#1002): `#readEnvelope` preserved `{value,revision}`
 *      (the #994 source returned `doc.value` and dropped `doc.revision`, so
 *      `completeEffect` wrote `mustMatchRevision: undefined` — the Host
 *      treated the undefined CAS guard as an UNCONDITIONAL write and two
 *      competing trusted same-effect terminal completions could overwrite
 *      each other). Terminal effect completion is now a strongly conditional
 *      CAS write; a lost race re-reads the authoritative record and either
 *      returns the SAME authoritative terminal outcome (identical outcome
 *      key) or fails typed (`ADMISSION_EFFECT_JOURNAL_CONFLICT`) — status is
 *      never overwritten by a concurrent terminal, and there is no
 *      unconditional fall-through anywhere on the terminal path.
 *   2. #966 (post-release P2, fixed while porting the effect journal):
 *      VolatileAdmissionEffectJournal and the kernel durable adapter isolate
 *      caller input/return aliases — stored and returned records are
 *      canonical-JSON snapshots, so mutation of caller-held objects can
 *      never contaminate the committed journal state (test-covered).
 *
 * HONEST BOUNDARY (Issue #1002): cross-document atomicity, hostile
 * privileged-store MAC and multi-process proofs are NOT claimed here (T-E
 * owns the real atomic Host primitive, T-G owns multi-process proof). The
 * Host document port consumed below is: get(key) → {value,revision} | null,
 * put(key, value, {mustBeAbsent}|{mustMatchRevision}) → {revision} | typed
 * rejection with `code === 'HOST_CAS_CONFLICT'`, list(prefix) → string[].
 * Doc revisions start at 0 on the creating (mustBeAbsent) write — the
 * instance engine treats snapshot.stateRevision and the Host doc revision as
 * the same counter (the #994 convention, contract-noted for T-E).
 *
 * Kernel ABI (v08-kernel-abi/1) — exported endpoint factory:
 *   createOccurrenceRuntime({ moduleIdentity, hostPorts, sdkEndpoint,
 *   businessEndpoint, observe }) → { openInstance, submitOccurrence,
 *   getSnapshot, getJournalRecords, getMechanismIdentity, counters }
 */

export const MODULE_ID = 'v08-kernel-mechanism@1.0.0';
export const PACKAGE_KIND = 'kernel';
export const ABI_VERSION = 'v08-kernel-abi/1';
export const KERNEL_GENERATION = '1';
export const ENDPOINTS = [
  { endpointId: 'occurrence-runtime', kind: 'occurrence-runtime' },
];

// ===========================================================================
// v0.7 migrated: contracts/json.ts + contracts/identity.ts (canonical JSON)
// Source: packages/domain-harness/src/contracts/identity.ts (verbatim logic)
// ===========================================================================

export class IdentityContractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'IdentityContractError';
    this.code = code;
  }
}

function failCanonical(path, reason) {
  throw new IdentityContractError(
    'INVALID_CANONICAL_JSON',
    `cannot canonicalize ${path}: ${reason}`,
  );
}

function assertNoSymbolKeys(value, path) {
  if (Object.getOwnPropertySymbols(value).length > 0) {
    failCanonical(path, 'symbol-keyed properties are not JSON');
  }
}

function requireDataProperty(value, key, path) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
    failCanonical(path, 'JSON properties must be enumerable data properties');
  }
  return descriptor.value;
}

function canonicalize(value, path, ancestors) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) failCanonical(path, 'number must be finite');
    return value;
  }

  if (Array.isArray(value)) {
    if (ancestors.has(value)) failCanonical(path, 'circular reference');
    assertNoSymbolKeys(value, path);
    ancestors.add(value);

    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const key = String(index);
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        failCanonical(`${path}[${index}]`, 'sparse array entries are not canonical JSON');
      }
      result.push(
        canonicalize(requireDataProperty(value, key, `${path}[${index}]`), `${path}[${index}]`, ancestors),
      );
    }

    const unexpectedKeys = Object.getOwnPropertyNames(value).filter((key) => {
      if (key === 'length') return false;
      if (!/^(0|[1-9]\d*)$/.test(key)) return true;
      const index = Number(key);
      return !Number.isSafeInteger(index) || index < 0 || index >= value.length;
    });
    if (unexpectedKeys.length > 0) {
      failCanonical(path, 'arrays may not carry extra object properties');
    }

    ancestors.delete(value);
    return result;
  }

  if (typeof value === 'object' && value !== null) {
    if (ancestors.has(value)) failCanonical(path, 'circular reference');
    assertNoSymbolKeys(value, path);

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      failCanonical(path, 'semantic objects must be plain JSON objects');
    }

    const ownNames = Object.getOwnPropertyNames(value);
    const nonEnumerable = ownNames.filter(
      (key) => !Object.prototype.propertyIsEnumerable.call(value, key),
    );
    if (nonEnumerable.length > 0) {
      failCanonical(path, 'non-enumerable properties are not canonical JSON');
    }

    ancestors.add(value);
    // Null-prototype avoids special setters such as Object.prototype.__proto__.
    const result = Object.create(null);
    for (const key of ownNames.sort()) {
      result[key] = canonicalize(
        requireDataProperty(value, key, `${path}.${key}`),
        `${path}.${key}`,
        ancestors,
      );
    }

    ancestors.delete(value);
    return result;
  }

  failCanonical(path, `unsupported value type ${typeof value}`);
}

/**
 * Convert JSON-compatible semantic material into a deterministic structure.
 * Object keys are sorted recursively; array order is preserved.
 */
export function canonicalizeJson(value) {
  return canonicalize(value, '$', new Set());
}

/** Deterministic UTF-8 material used as input to content-addressed digests. */
export function canonicalJsonStringify(value) {
  const encoded = JSON.stringify(canonicalizeJson(value));
  if (encoded === undefined) failCanonical('$', 'value did not produce JSON text');
  return encoded;
}

/** Compute a canonical SHA-256 content digest through the portable host seam. */
export async function computeCanonicalJsonDigest(value, sha256) {
  const digest = await sha256.digestUtf8(canonicalJsonStringify(value));
  if (typeof digest !== 'string' || digest.length === 0) {
    throw new IdentityContractError(
      'INVALID_CONTENT_DIGEST',
      'Sha256Port returned an empty or invalid content digest',
    );
  }
  return digest;
}

// ===========================================================================
// v0.7 migrated: workflow/predicate.ts — deterministic predicate engine
// Source: packages/domain-harness/src/workflow/predicate.ts (verbatim logic)
// ===========================================================================

export class PredicateContractViolation extends Error {
  constructor(message) {
    super(message);
    this.name = 'PredicateContractViolation';
    this.code = 'PREDICATE_CONTRACT_VIOLATION';
  }
}

const MISSING = Symbol('domain-harness.predicate.missing');
const MAX_PREDICATE_DEPTH = 64;

const preparedPredicates = new WeakSet();
const preparedWorkflowGuards = new WeakSet();
const preparedHardInvariants = new WeakSet();
const preparedContexts = new WeakSet();
const preparedEvents = new WeakSet();
const preparedInputs = new WeakSet();

function isObjectReference(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

function isJsonObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cloneDataOnlyForPreparation(value, path, seen = new WeakSet()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new PredicateContractViolation(`${path} contains a non-finite number`);
    }
    return value;
  }
  if (typeof value !== 'object') {
    throw new PredicateContractViolation(`${path} must contain JSON data only`);
  }
  if (seen.has(value)) {
    throw new PredicateContractViolation(`${path} contains a cycle`);
  }
  seen.add(value);

  try {
    if (Array.isArray(value)) {
      const result = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined || !('value' in descriptor)) {
          throw new PredicateContractViolation(`${path}[${index}] must be a data property`);
        }
        result.push(cloneDataOnlyForPreparation(descriptor.value, `${path}[${index}]`, seen));
      }
      return result;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new PredicateContractViolation(`${path} must use a plain object prototype`);
    }

    const result = Object.create(null);
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !('value' in descriptor)) {
        throw new PredicateContractViolation(`${path}.${key} accessor properties are forbidden`);
      }
      result[key] = cloneDataOnlyForPreparation(descriptor.value, `${path}.${key}`, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function deepFreezePreparedData(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      deepFreezePreparedData(item);
    }
  } else {
    for (const key of Object.keys(value)) {
      const item = value[key];
      if (item !== undefined) {
        deepFreezePreparedData(item);
      }
    }
  }
  Object.freeze(value);
}

export function prepareDomainPredicate(predicate) {
  const safePredicate = cloneDataOnlyForPreparation(predicate, '$predicate');
  if (!isObjectReference(safePredicate)) {
    throw new PredicateContractViolation('$predicate must be an object');
  }
  deepFreezePreparedData(safePredicate);
  preparedPredicates.add(safePredicate);
  return safePredicate;
}

export function prepareDomainWorkflowGuard(guard) {
  const safeGuard = cloneDataOnlyForPreparation(guard, '$guard');
  if (
    !isObjectReference(safeGuard) ||
    typeof safeGuard.guardId !== 'string' ||
    safeGuard.guardId.length === 0 ||
    !isObjectReference(safeGuard.predicate)
  ) {
    throw new PredicateContractViolation('Workflow Guard must contain a non-empty guardId and predicate object');
  }
  deepFreezePreparedData(safeGuard);
  preparedWorkflowGuards.add(safeGuard);
  preparedPredicates.add(safeGuard.predicate);
  return safeGuard;
}

export function prepareDomainHardInvariantPredicate(invariant) {
  const safeInvariant = cloneDataOnlyForPreparation(invariant, '$hardInvariant');
  if (
    !isObjectReference(safeInvariant) ||
    typeof safeInvariant.invariantId !== 'string' ||
    safeInvariant.invariantId.length === 0 ||
    !isObjectReference(safeInvariant.predicate)
  ) {
    throw new PredicateContractViolation(
      'Hard Invariant must contain a non-empty invariantId and predicate object',
    );
  }
  deepFreezePreparedData(safeInvariant);
  preparedHardInvariants.add(safeInvariant);
  preparedPredicates.add(safeInvariant.predicate);
  return safeInvariant;
}

export function prepareDomainPredicateContext(context) {
  const safeContext = cloneDataOnlyForPreparation(context, '$context');
  if (!isJsonObject(safeContext)) {
    throw new PredicateContractViolation('$context must be a JSON object');
  }
  deepFreezePreparedData(safeContext);
  preparedContexts.add(safeContext);
  return safeContext;
}

export function prepareDomainPredicateEvent(event) {
  const safeEvent = cloneDataOnlyForPreparation(event, '$event');
  if (!isJsonObject(safeEvent)) {
    throw new PredicateContractViolation('$event must be a JSON object');
  }
  const type = safeEvent['type'];
  if (typeof type !== 'string' || type.length === 0) {
    throw new PredicateContractViolation('$event.type must be a non-empty string');
  }
  const payload = safeEvent['payload'];
  if (payload !== undefined && !isJsonObject(payload)) {
    throw new PredicateContractViolation('$event.payload must be a JSON object when present');
  }
  deepFreezePreparedData(safeEvent);
  preparedEvents.add(safeEvent);
  return safeEvent;
}

export function createPreparedDomainPredicateEvaluationInput(context, event) {
  if (
    !isObjectReference(context) ||
    !preparedContexts.has(context) ||
    !isObjectReference(event) ||
    !preparedEvents.has(event)
  ) {
    throw new PredicateContractViolation('predicate input must use prepared context and event data');
  }
  const input = Object.freeze({ context, event });
  preparedInputs.add(input);
  return input;
}

export function prepareDomainPredicateEvaluationInput(input) {
  const context = prepareDomainPredicateContext(input.context);
  const event = prepareDomainPredicateEvent(input.event);
  return createPreparedDomainPredicateEvaluationInput(context, event);
}

export function evaluateDomainPredicate(predicate, input) {
  assertPreparedPredicate(predicate);
  assertPreparedInput(input);
  return evaluateSafePredicate(predicate, input, 0);
}

export function evaluateDomainWorkflowGuard(guard, input) {
  if (
    !isObjectReference(guard) ||
    !preparedWorkflowGuards.has(guard) ||
    !isObjectReference(input) ||
    !preparedInputs.has(input)
  ) {
    return false;
  }
  try {
    return evaluateSafePredicate(guard.predicate, input, 0);
  } catch {
    return false;
  }
}

export function evaluateDomainHardInvariantPredicate(invariant, input) {
  if (
    !isObjectReference(invariant) ||
    !preparedHardInvariants.has(invariant) ||
    !isObjectReference(input) ||
    !preparedInputs.has(input)
  ) {
    return false;
  }
  try {
    return evaluateSafePredicate(invariant.predicate, input, 0);
  } catch {
    return false;
  }
}

function assertPreparedPredicate(predicate) {
  if (!isObjectReference(predicate) || !preparedPredicates.has(predicate)) {
    throw new PredicateContractViolation('predicate must be prepared before authoritative evaluation');
  }
}

function assertPreparedInput(input) {
  if (!isObjectReference(input) || !preparedInputs.has(input)) {
    throw new PredicateContractViolation('predicate input must be prepared before authoritative evaluation');
  }
}

function evaluateSafePredicate(predicate, input, depth) {
  if (depth > MAX_PREDICATE_DEPTH) {
    throw new PredicateContractViolation('predicate nesting exceeds the supported deterministic depth');
  }

  switch (predicate.op) {
    case 'constant':
      return predicate.value;
    case 'exists':
      return resolveOperand(predicate.operand, input) !== MISSING;
    case 'eq':
      return compareEquality(resolveOperand(predicate.left, input), resolveOperand(predicate.right, input));
    case 'neq':
      return !compareEquality(resolveOperand(predicate.left, input), resolveOperand(predicate.right, input));
    case 'gt':
      return compareOrdered(resolveOperand(predicate.left, input), resolveOperand(predicate.right, input)) > 0;
    case 'gte':
      return compareOrdered(resolveOperand(predicate.left, input), resolveOperand(predicate.right, input)) >= 0;
    case 'lt':
      return compareOrdered(resolveOperand(predicate.left, input), resolveOperand(predicate.right, input)) < 0;
    case 'lte':
      return compareOrdered(resolveOperand(predicate.left, input), resolveOperand(predicate.right, input)) <= 0;
    case 'not':
      return !evaluateSafePredicate(predicate.predicate, input, depth + 1);
    case 'all':
      return predicate.predicates.every((candidate) => evaluateSafePredicate(candidate, input, depth + 1));
    case 'any':
      return predicate.predicates.some((candidate) => evaluateSafePredicate(candidate, input, depth + 1));
    default:
      throw new PredicateContractViolation('unknown predicate operator');
  }
}

function resolveOperand(operand, input) {
  switch (operand.source) {
    case 'literal':
      return operand.value;
    case 'context':
      return readPath(input.context, operand.path);
    case 'event':
      return readPath(input.event, operand.path);
    default:
      throw new PredicateContractViolation('unknown predicate operand source');
  }
}

function readPath(root, path) {
  let current = root;
  for (const segment of path) {
    if (typeof segment !== 'string' || segment.length === 0) {
      throw new PredicateContractViolation('predicate path segments must be non-empty strings');
    }
    if (current === null || typeof current !== 'object') {
      return MISSING;
    }
    if (!Object.prototype.hasOwnProperty.call(current, segment)) {
      return MISSING;
    }
    current = current[segment];
  }
  return current;
}

function compareEquality(left, right) {
  if (left === MISSING || right === MISSING) {
    return left === right;
  }
  return dataEquals(left, right);
}

function compareOrdered(left, right) {
  if (left === MISSING || right === MISSING) {
    throw new PredicateContractViolation('ordered comparison cannot use a missing operand');
  }
  if (typeof left === 'number' && typeof right === 'number') {
    return left === right ? 0 : left > right ? 1 : -1;
  }
  if (typeof left === 'string' && typeof right === 'string') {
    return left === right ? 0 : left > right ? 1 : -1;
  }
  throw new PredicateContractViolation('ordered comparison requires two numbers or two strings');
}

function dataEquals(left, right) {
  if (left === right) {
    return true;
  }
  if (left === null || right === null || typeof left !== 'object' || typeof right !== 'object') {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    return left.every((value, index) => {
      const other = right[index];
      return other !== undefined && dataEquals(value, other);
    });
  }

  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  return leftKeys.every((key, index) => {
    if (key !== rightKeys[index]) {
      return false;
    }
    const leftValue = left[key];
    const rightValue = right[key];
    return leftValue !== undefined && rightValue !== undefined && dataEquals(leftValue, rightValue);
  });
}

// ===========================================================================
// v0.7 migrated: governance/identity.ts — bounded baseline identity subset
// Source: packages/domain-harness/src/governance/identity.ts
// (assertGovernanceBaselineIdentity / governanceBaselineKey /
//  sameGovernanceBaselineIdentity / verifyGovernanceBaselineBody only)
// ===========================================================================

export class GovernanceContractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'GovernanceContractError';
    this.code = code;
  }
}

function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new GovernanceContractError(
      'INVALID_GOVERNANCE_IDENTITY',
      `${field} must be a non-empty string`,
    );
  }
  return value;
}

function isContentDigest(value) {
  return typeof value === 'string' && value.length > 0;
}

export function assertGovernanceBaselineIdentity(identity) {
  requireNonEmptyString(identity.domainId, 'domainId');
  requireNonEmptyString(identity.governanceId, 'governanceId');
  requireNonEmptyString(identity.schemaVersion, 'schemaVersion');
  if (!isContentDigest(identity.contentDigest)) {
    throw new GovernanceContractError(
      'INVALID_GOVERNANCE_IDENTITY',
      'contentDigest must be a non-empty exact content digest',
    );
  }
  if (identity.version !== undefined) requireNonEmptyString(identity.version, 'version');
}

/** Exact registry key. Lifecycle version labels are deliberately excluded. */
export function governanceBaselineKey(identity) {
  assertGovernanceBaselineIdentity(identity);
  return canonicalJsonStringify({
    domainId: identity.domainId,
    governanceId: identity.governanceId,
    schemaVersion: identity.schemaVersion,
    contentDigest: identity.contentDigest,
  });
}

export function sameGovernanceBaselineIdentity(left, right) {
  return governanceBaselineKey(left) === governanceBaselineKey(right);
}

function semanticDigestMaterial(schemaVersion, semantics) {
  return { schemaVersion, semantics };
}

export async function computeGovernanceBaselineIdentity(input, sha256) {
  const domainId = requireNonEmptyString(input.domainId, 'domainId');
  const governanceId = requireNonEmptyString(input.governanceId, 'governanceId');
  const schemaVersion = requireNonEmptyString(input.schemaVersion, 'schemaVersion');
  const version = input.version === undefined
    ? undefined
    : requireNonEmptyString(input.version, 'version');
  const contentDigest = await computeCanonicalJsonDigest(
    semanticDigestMaterial(schemaVersion, input.semantics),
    sha256,
  );

  return version === undefined
    ? { domainId, governanceId, schemaVersion, contentDigest }
    : { domainId, governanceId, schemaVersion, version, contentDigest };
}

export async function verifyGovernanceBaselineBody(body, sha256) {
  assertGovernanceBaselineIdentity(body.identity);
  const expected = await computeCanonicalJsonDigest(
    semanticDigestMaterial(body.identity.schemaVersion, body.semantics),
    sha256,
  );
  if (expected !== body.identity.contentDigest) {
    throw new GovernanceContractError(
      'GOVERNANCE_DIGEST_MISMATCH',
      `Governance Baseline ${body.identity.governanceId} content digest does not match canonical semantics`,
    );
  }
}

// ===========================================================================
// v0.7 migrated: admission/contracts.ts — runtime shapes + typed taxonomy
// Source: packages/domain-harness/src/admission/contracts.ts
// (CentralAdmissionError and the shapes consumed by admitCentralDecision)
// ===========================================================================

export class CentralAdmissionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CentralAdmissionError';
    this.code = code;
  }
}

// ===========================================================================
// v0.7 migrated: admission/admission.ts — the central authoritative path
// Source: packages/domain-harness/src/admission/admission.ts
// (deriveDurableControlTurnId, admissionResolverEvidence, predicate shape
//  validation, pinned baseline requirement, transition selection,
//  executeEffectIntents, admitCentralDecision)
// [KPK-01 adaptation] ports may carry an optional `trace` counter bag; guard /
// hard-invariant evaluation sites bump it for mechanism ownership evidence.
// Everything else is verbatim.
// ===========================================================================

function requireComponent(value, label) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new CentralAdmissionError(
      'ADMISSION_INVALID_TURN_SOURCE',
      `${label} must be a non-empty string`,
    );
  }
  return encodeURIComponent(value);
}

function requireOrdinal(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CentralAdmissionError(
      'ADMISSION_INVALID_TURN_SOURCE',
      `${label} must be a positive safe integer`,
    );
  }
  return value;
}

/**
 * Deterministic Durable Control Turn identity (frozen L2 §13.2). Replaying the
 * same source derives the same id; distinct sources never collide. Synchronous
 * engine microsteps settle inside the containing turn — every effect/query/AI
 * operation identity derives from this id plus a stable operation ordinal.
 */
export function deriveDurableControlTurnId(target, source) {
  const base = `turn:${requireComponent(target.workflowId, 'workflowId')}:${requireComponent(target.instanceKey, 'instanceKey')}`;
  switch (source.kind) {
    case 'message':
      return `${base}:message:${requireComponent(source.sourceMessageId, 'sourceMessageId')}`;
    case 'child-terminal':
      if (source.terminalKind !== 'done' && source.terminalKind !== 'error') {
        throw new CentralAdmissionError(
          'ADMISSION_INVALID_TURN_SOURCE',
          'terminalKind must be done or error',
        );
      }
      return `${base}:child:${requireComponent(source.parentActorId, 'parentActorId')}:${requireComponent(source.childActorId, 'childActorId')}:${requireOrdinal(source.invocationOrdinal, 'invocationOrdinal')}:${source.terminalKind}`;
    case 'timer':
      return `${base}:timer:${requireComponent(source.timerId, 'timerId')}:${requireOrdinal(source.fireOrdinal, 'fireOrdinal')}`;
    case 'callback':
      return `${base}:callback:${requireComponent(source.externalCorrelationId, 'externalCorrelationId')}:${requireOrdinal(source.callbackOrdinal, 'callbackOrdinal')}`;
    case 'recovery':
      return `${base}:recovery:${requireComponent(source.durableRecoveryActionId, 'durableRecoveryActionId')}:${requireOrdinal(source.resumeOrdinal, 'resumeOrdinal')}`;
    default:
      throw new CentralAdmissionError('ADMISSION_INVALID_TURN_SOURCE', 'unknown turn source kind');
  }
}

const NON_MESSAGE_TURN_SOURCE_FIELDS = {
  timer: ['timerId', 'fireOrdinal'],
  callback: ['externalCorrelationId', 'callbackOrdinal'],
  'child-terminal': ['parentActorId', 'childActorId', 'invocationOrdinal', 'terminalKind'],
  // [#1006 HF16 authorized poison recovery] The trusted Host seam supplies
  // the recovery source ONLY from its durable CAS-authorized recovery-action
  // record; the public send path never constructs one.
  recovery: ['durableRecoveryActionId', 'resumeOrdinal'],
};

/**
 * [#1062 shared durable-control seam] Strict validation of a NON-message turn
 * source supplied by the trusted Host seam (`request.turnSource`). The public
 * send path constructs no turnSource; message turns keep deriving from
 * messageId. The exact field set is enforced (no extra/missing fields) and
 * every component value is validated by the SAME single authority that derives
 * the turn id (`deriveDurableControlTurnId` runs on a probe target), so a
 * turnSource accepted here is byte-deterministically replayable and can never
 * smuggle foreign material into the turn identity.
 *
 * [#1006 HF16] `recovery` is admitted here as the corrective poison-recovery
 * turn source: the Host coordinator's durable CAS-authorized recovery-action
 * record is the authorization credential, and the derived deterministic turn
 * id gives duplicate/restart redeliveries the same turn-disposition
 * idempotence every other durable control turn enjoys. The Kernel's own
 * fail-closed poison policy is unchanged: a durably failed effect row is
 * never re-executed by ANY turn (the corrective turn runs its own effects
 * under its own identity).
 */
export function strictTurnSource(source) {
  if (!isJsonRecord(source)) {
    throw new CentralAdmissionError('ADMISSION_INVALID_TURN_SOURCE', 'turnSource must be a JSON record');
  }
  const kind = source.kind;
  if (kind === 'message') {
    throw new CentralAdmissionError(
      'ADMISSION_INVALID_TURN_SOURCE',
      'a turnSource of kind message is not accepted at this seam: message turns derive from messageId',
    );
  }
  const fields = NON_MESSAGE_TURN_SOURCE_FIELDS[kind];
  if (fields === undefined) {
    throw new CentralAdmissionError('ADMISSION_INVALID_TURN_SOURCE', `unknown turn source kind ${JSON.stringify(kind)}`);
  }
  for (const key of Object.keys(source)) {
    if (key !== 'kind' && !fields.includes(key)) {
      throw new CentralAdmissionError(
        'ADMISSION_INVALID_TURN_SOURCE',
        `turn source ${String(kind)} carries the unsupported field ${key}`,
      );
    }
  }
  for (const field of fields) {
    if (!hasOwn(source, field)) {
      throw new CentralAdmissionError(
        'ADMISSION_INVALID_TURN_SOURCE',
        `turn source ${String(kind)} is missing the required field ${field}`,
      );
    }
  }
  // Single validation authority: deriveDurableControlTurnId itself validates
  // every component (non-empty strings, positive safe integers, done|error).
  deriveDurableControlTurnId({ workflowId: 'shape-probe', instanceKey: 'shape-probe' }, source);
  return snapshotJson(source);
}

/**
 * The turn source of ONE occurrence request: the trusted-seam turnSource when
 * the Host supplies one (timer/callback/child-terminal durable control
 * delivery), else the plain message source derived from the messageId. Every
 * in-payload turn-id derivation site funnels through here — there is exactly
 * one way a turn identity is constructed.
 */
function occurrenceTurnOf(request) {
  return request.turnSource === undefined
    ? { kind: 'message', sourceMessageId: request.messageId }
    : strictTurnSource(request.turnSource);
}

/**
 * §21 handoff: resolver telemetry/LLM-avoidance evidence for the turn receipt.
 * [#1003 FR07-KH2, review B2] The legacy numeric `freshModelCallCount` is no
 * longer read: only the structured trusted `modelCallEvidence` (normalized by
 * admissionModelCallEvidence) and, for a K continuation, the K-built
 * continuation evidence (turns, queries, K-attested dependencies) are carried.
 */
export function admissionResolverEvidence(resolved) {
  return {
    source: resolved.source,
    llmAvoided: resolved.llmAvoided,
    modelCallEvidence: admissionModelCallEvidence(resolved.modelCallEvidence),
    cacheRead: resolved.cacheDisposition.read,
    ...(resolved.cacheDisposition.write === undefined
      ? {}
      : { cacheWrite: resolved.cacheDisposition.write }),
    telemetryEventCount: resolved.telemetry.length,
    ...(resolved.continuation === undefined
      ? {}
      : { continuation: JSON.parse(canonicalJsonStringify(resolved.continuation)) }),
  };
}

const PREDICATE_OPS = new Set([
  'constant', 'exists', 'eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'not', 'all', 'any',
]);
const OPERAND_SOURCES = new Set(['context', 'event', 'literal']);
const MAX_SHAPE_DEPTH = 64;

function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertOperandShape(operand, path, fail) {
  if (!isPlainObject(operand)) fail(`${path} must be an operand object`);
  const source = operand['source'];
  if (typeof source !== 'string' || !OPERAND_SOURCES.has(source)) {
    fail(`${path}.source must be context, event or literal`);
  }
  if (source === 'literal') {
    if (!Object.prototype.hasOwnProperty.call(operand, 'value')) fail(`${path}.value is required for a literal operand`);
    try {
      canonicalizeJson(operand['value']);
    } catch (error) {
      fail(`${path}.value must be canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    return;
  }
  const pathValue = operand['path'];
  if (
    !Array.isArray(pathValue)
    || pathValue.some((segment) => typeof segment !== 'string' || segment.length === 0)
  ) {
    fail(`${path}.path must be an array of non-empty strings`);
  }
}

/**
 * Recursive DomainPredicate shape validation. Evaluation trusts the shape
 * (e.g. `constant` returns its value raw), so admission validates the full
 * predicate tree before any authoritative evaluation — a digest-consistent
 * but type-malformed predicate can never become a truthy Hard Invariant or a
 * fail-open guard (T-019 review P2-2).
 */
function assertDomainPredicateShape(predicate, path, fail, depth = 0) {
  if (depth > MAX_SHAPE_DEPTH) fail(`${path} exceeds the supported predicate depth`);
  if (!isPlainObject(predicate)) fail(`${path} must be a predicate object`);
  const op = predicate['op'];
  if (typeof op !== 'string' || !PREDICATE_OPS.has(op)) {
    fail(`${path}.op is not a known predicate operator`);
  }
  switch (op) {
    case 'constant':
      if (typeof predicate['value'] !== 'boolean') fail(`${path}.value must be a boolean`);
      return;
    case 'exists':
      assertOperandShape(predicate['operand'], `${path}.operand`, fail);
      return;
    case 'eq':
    case 'neq':
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      assertOperandShape(predicate['left'], `${path}.left`, fail);
      assertOperandShape(predicate['right'], `${path}.right`, fail);
      return;
    case 'not':
      assertDomainPredicateShape(predicate['predicate'], `${path}.predicate`, fail, depth + 1);
      return;
    case 'all':
    case 'any': {
      const predicates = predicate['predicates'];
      if (!Array.isArray(predicates)) fail(`${path}.predicates must be an array`);
      predicates.forEach((candidate, index) => {
        assertDomainPredicateShape(candidate, `${path}.predicates[${index}]`, fail, depth + 1);
      });
      return;
    }
    default:
      fail(`${path}.op is not a known predicate operator`);
  }
}

function invalidHardInvariant(message) {
  throw new CentralAdmissionError('ADMISSION_INVALID_HARD_INVARIANTS', message);
}

/**
 * The pinned baseline body is the only Hard Invariant source. Structurally
 * malformed content fails closed loudly; evaluation-time errors are denied by
 * the T-006 evaluator (false), which is already the safe direction.
 */
function readPinnedHardInvariants(body) {
  const raw = body.semantics['hardInvariants'];
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new CentralAdmissionError(
      'ADMISSION_INVALID_HARD_INVARIANTS',
      'pinned baseline semantics.hardInvariants must be an array when present',
    );
  }
  return raw.map((entry, index) => {
    if (!isPlainObject(entry)) {
      throw new CentralAdmissionError(
        'ADMISSION_INVALID_HARD_INVARIANTS',
        `hardInvariants[${index}] must be an object`,
      );
    }
    if (typeof entry['invariantId'] !== 'string' || entry['invariantId'].length === 0) {
      throw new CentralAdmissionError(
        'ADMISSION_INVALID_HARD_INVARIANTS',
        `hardInvariants[${index}].invariantId must be a non-empty string`,
      );
    }
    assertDomainPredicateShape(
      entry['predicate'],
      `hardInvariants[${index}].predicate`,
      invalidHardInvariant,
    );
    return {
      invariantId: entry['invariantId'],
      predicate: entry['predicate'],
    };
  });
}

async function requirePinnedBaseline(request, ports, sha256) {
  // T-014 gate: pinned governance for EVERY authoritative admission. Pin
  // absence/invalidity propagates as GovernanceExecutionBindingError.
  const pin = await ports.governance.requirePinnedExecution(request.workflowInstanceId);
  const body = await ports.baselines.getBody(pin.governanceBaseline);
  if (body === undefined) {
    throw new CentralAdmissionError(
      'ADMISSION_PINNED_BASELINE_UNAVAILABLE',
      `exact pinned Governance Baseline ${pin.governanceBaseline.governanceId}@${pin.governanceBaseline.contentDigest} is unavailable; no substitution is permitted`,
    );
  }
  try {
    await verifyGovernanceBaselineBody(body, sha256);
  } catch (error) {
    throw new CentralAdmissionError(
      'ADMISSION_PINNED_BASELINE_UNAVAILABLE',
      `exact pinned Governance Baseline body is corrupt: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!sameGovernanceBaselineIdentity(body.identity, pin.governanceBaseline)) {
    throw new CentralAdmissionError(
      'ADMISSION_PINNED_BASELINE_UNAVAILABLE',
      'resolved Governance Baseline body does not match the exact GovernanceExecutionPin',
    );
  }
  return { bindingDigest: pin.bindingDigest, hardInvariants: readPinnedHardInvariants(body) };
}

function sameTrigger(left, right) {
  return canonicalJsonStringify(left) === canonicalJsonStringify(right);
}

function deny(reason, turnId, bindingDigest, resolver, extras = {}) {
  return {
    status: 'denied',
    denial: {
      reason,
      durableControlTurnId: turnId,
      governanceBindingDigest: bindingDigest,
      ...(extras.invariantId === undefined ? {} : { invariantId: extras.invariantId }),
      ...(extras.transitionKey === undefined ? {} : { transitionKey: extras.transitionKey }),
      ...(extras.guardId === undefined ? {} : { guardId: extras.guardId }),
      ...(extras.contextField === undefined ? {} : { contextField: extras.contextField }),
      resolver,
    },
  };
}

function evaluateHardInvariants(hardInvariants, input, trace) {
  for (const invariant of hardInvariants) {
    const prepared = prepareDomainHardInvariantPredicate(invariant);
    // [KPK-01 adaptation] mechanism ownership measurement only.
    if (trace !== undefined) trace.hardInvariantEvaluations += 1;
    if (!evaluateDomainHardInvariantPredicate(prepared, input)) {
      return invariant.invariantId;
    }
  }
  return undefined;
}

function selectAdmittedTransition(request, input, trace) {
  const state = request.definition.states.find((candidate) => candidate.stateKey === request.currentStateKey);
  if (state === undefined) {
    throw new CentralAdmissionError(
      'ADMISSION_UNKNOWN_STATE',
      `current state ${request.currentStateKey} is not declared in workflow ${request.definition.workflowKey}`,
    );
  }
  const guards = new Map((request.definition.guards ?? []).map((guard) => [guard.guardId, guard]));
  const candidates = (state.transitions ?? []).filter((transition) => sameTrigger(transition.trigger, request.trigger));
  if (candidates.length === 0) return { noCandidate: true };

  let lastRejected;
  for (const candidate of candidates) {
    let guardPasses = true;
    let guardId;
    if (candidate.guardId !== undefined) {
      const guard = guards.get(candidate.guardId);
      if (guard === undefined) {
        throw new CentralAdmissionError(
          'ADMISSION_UNKNOWN_GUARD',
          `transition ${candidate.transitionKey} references unknown guard ${candidate.guardId}`,
        );
      }
      guardId = guard.guardId;
      // Definition integrity: a malformed guard predicate must never become a
      // fail-open constant or a silent denial (T-019 review P2-2).
      assertDomainPredicateShape(
        guard.predicate,
        `guard ${guard.guardId}.predicate`,
        (message) => {
          throw new CentralAdmissionError('ADMISSION_INVALID_PREDICATE_SHAPE', message);
        },
      );
      // [KPK-01 adaptation] mechanism ownership measurement only.
      if (trace !== undefined) trace.guardEvaluations += 1;
      guardPasses = evaluateDomainWorkflowGuard(prepareDomainWorkflowGuard(guard), input);
    }
    if (guardPasses) return { admitted: candidate };
    lastRejected = {
      transitionKey: candidate.transitionKey,
      ...(guardId === undefined ? {} : { guardId }),
    };
  }
  return { rejected: lastRejected ?? { transitionKey: candidates[0]?.transitionKey ?? '' } };
}

// ===========================================================================
// [v0.10 C01 #1177] External Effect binding configuration. A Business effect
// binding may declare `external` to route its dispatch through the selected
// K→C external Effect Operation: the kernel then mints a LIVE one-time Effect
// Permit document (see effectPermitAdmin) before the executor runs and
// consumes it (exact-revision CAS) as soon as the dispatch settles. The
// config is bounded data only — ttl, await policy and an optional extra
// operation allowlist; no authority is configurable from here.
// ===========================================================================
function normalizeExternalEffectConfig(raw) {
  if (raw === undefined || raw === null) return null;
  if (!isJsonRecord(raw)) {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_EXTERNAL_INVALID',
      'an external effect binding config must be a plain record',
    );
  }
  const permitTtlMs = raw.permitTtlMs === undefined ? 60_000 : raw.permitTtlMs;
  if (!Number.isSafeInteger(permitTtlMs) || permitTtlMs < 1 || permitTtlMs > 3_600_000) {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_EXTERNAL_INVALID',
      'external.permitTtlMs must be a safe integer within 1..3600000 milliseconds',
    );
  }
  const awaitPolicy = raw.await === undefined ? 'phase' : raw.await;
  if (awaitPolicy !== 'phase' && awaitPolicy !== 'terminal') {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_EXTERNAL_INVALID',
      "external.await must be 'phase' (honest accepted/running envelopes) or 'terminal' (fail-closed pending)",
    );
  }
  const extra = raw.operations === undefined ? [] : raw.operations;
  if (!Array.isArray(extra) || extra.length > 8
    || extra.some((op) => typeof op !== 'string' || op.length === 0 || op.length > 128)) {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_EXTERNAL_INVALID',
      'external.operations must be a bounded array of non-empty operation id strings',
    );
  }
  return { permitTtlMs, awaitPolicy, operations: [...extra] };
}

async function executeEffectIntents(intents, request, ports, turnId) {
  const outcomes = [];
  let ordinal = 0;
  for (const intent of intents) {
    ordinal += 1;
    const effectId = `${turnId}/effect/${ordinal}`;
    const binding = ports.effectTools.resolve(intent.effectType);
    if (binding === undefined) {
      const unbound = new CentralAdmissionError(
        'ADMISSION_EFFECT_TOOL_UNBOUND',
        `no mutation-capable tool binding is declared for effect type ${intent.effectType}`,
      );
      // [#1108 K01 R1 P1] Provable: no executor was ever invoked.
      unbound.zeroExternalEffect = true;
      throw unbound;
    }
    const record = {
      effectId,
      target: request.target,
      durableControlTurnId: turnId,
      operationOrdinal: ordinal,
      effectType: intent.effectType,
      effectSemantics: binding.effectSemantics,
      status: 'started',
      attempt: 1,
      input: intent.input,
      ...(intent.idempotencyKey === undefined ? {} : { idempotencyKey: intent.idempotencyKey }),
      startedAt: request.now,
    };

    let begun;
    try {
      begun = await ports.effectJournal.beginEffect(record);
    } catch (error) {
      if (error instanceof CentralAdmissionError) {
        // [#1108 K01 R1 P1] A typed journal begin refusal happens BEFORE any
        // executor invocation — provably zero external effect.
        error.zeroExternalEffect = true;
        throw error;
      }
      const conflict = new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect journal begin failed for ${effectId}: ${error instanceof Error ? error.message : String(error)}`,
      );
      conflict.zeroExternalEffect = true;
      throw conflict;
    }
    const durable = begun.record;

    if (durable.status === 'completed') {
      // §18: a completed durable effect found during recovery is reused; the
      // mutation is never re-executed (V8/V12 — no evidence port involved).
      outcomes.push({
        effectId,
        effectType: durable.effectType,
        disposition: 'replayed',
        ...(durable.idempotencyKey === undefined ? {} : { idempotencyKey: durable.idempotencyKey }),
        ...(durable.output === undefined ? {} : { output: durable.output }),
      });
      continue;
    }
    if (durable.status === 'failed') {
      const replayRefusal = new CentralAdmissionError(
        'ADMISSION_EFFECT_FAILED',
        `effect ${effectId} has a durably failed outcome; operator recovery owns any retry`,
      );
      // [#1108 K01 R1] This REPLAY attempt itself executed nothing; whether
      // the fence may be released follows the ORIGINAL failure's persisted
      // classification (the dispatcher-attested zero-external-effect marker
      // rides the durable failure record). An unclassified (possibly landed)
      // original keeps the fence held.
      if (isJsonRecord(durable.error) && durable.error.zeroExternalEffect === true) {
        replayRefusal.zeroExternalEffect = true;
      }
      throw replayRefusal;
    }
    if (begun.disposition === 'existing' && durable.effectSemantics === 'non-idempotent') {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_AMBIGUOUS',
        `effect ${effectId} was started but never committed; re-executing a non-idempotent effect is forbidden`,
      );
    }

    // [v0.10 C01 #1177] Live K-issued permit for an external effect binding:
    // minted AFTER the journal begin/replay gates and BEFORE the executor
    // runs. A mint refusal is journaled as a proven zero-external-effect
    // failure first (mirroring the executor-failure discipline below), then
    // throws typed — the fence policy can act on it, and no executor ran.
    let permit = null;
    if (binding.external !== null && ports.effectPermitAdmin !== undefined) {
      try {
        const minted = await ports.effectPermitAdmin.mint({
          effectId,
          turnId,
          effectType: intent.effectType,
          effectSemantics: binding.effectSemantics,
          external: binding.external,
          resource: binding.resource,
          target: request.target,
          attempt: record.attempt,
          issuedAt: request.now,
        });
        permit = { effectId, revision: minted.revision };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        let marked = false;
        try {
          await ports.effectJournal.completeEffect(
            effectId,
            { status: 'failed', error: { message, zeroExternalEffect: true }, completedAt: request.now },
          );
          marked = true;
        } catch {
          // The failure record itself is not durable: doubly unknown — no
          // zero-external-effect proof is attached and the fence stays held.
        }
        const typed = error instanceof CentralAdmissionError && error.code === 'ADMISSION_EFFECT_PERMIT_CONFLICT'
          ? error
          : new CentralAdmissionError(
              'ADMISSION_EFFECT_PERMIT_CONFLICT',
              `effect permit mint for ${effectId} failed: ${message}`,
            );
        if (marked) {
          typed.zeroExternalEffect = true;
        }
        throw typed;
      }
    }

    let output;
    // [#1108 K01 R1 P1 / R2 P1] The dispatch probe: the runtime's own executor
    // marks whether the Business handler ever invoked the physical resource
    // port, and collects one kernel-minted per-call attestation object per
    // port call (the ONLY channel a trusted host dispatcher can mark its own
    // pre-handler refusals through — see probeProvesZeroExternalEffect).
    const externalDispatchProbe = { supported: false, invoked: false, dispatchAttests: [] };
    try {
      output = await ports.effectTools.execute({
        effectId,
        target: request.target,
        durableControlTurnId: turnId,
        operationOrdinal: ordinal,
        binding,
        input: intent.input,
        ...(intent.idempotencyKey === undefined ? {} : { idempotencyKey: intent.idempotencyKey }),
        logicalTime: request.now,
        attempt: record.attempt,
        externalDispatchProbe,
      });
      canonicalizeJson(output);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // [#1108 K01 R1 P1] Classify BEFORE the failure record is made durable:
      // the proof (or its absence) persists IN the journal record so a later
      // same-turn replay refusal can restore the same fence policy.
      const zeroEffect = probeProvesZeroExternalEffect(externalDispatchProbe);
      const failure = { message, ...(zeroEffect ? { zeroExternalEffect: true } : {}) };
      try {
        await ports.effectJournal.completeEffect(
          effectId,
          { status: 'failed', error: failure, completedAt: request.now },
        );
      } catch (commitError) {
        // Never lose the journal-unreadable signal: the host must see that the
        // failure record itself is not durable (P3-2). The outcome is doubly
        // unknown (the failure record could not even be made durable), so no
        // zero-external-effect proof is attached.
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect ${effectId} failed (${message}) and the failure record could not be committed: ${commitError instanceof Error ? commitError.message : String(commitError)}`,
        );
      }
      // [#1108 K01 R1 P1] A journal `failed` record reflects a THROWN adapter
      // call, NOT proof that the remote resource performed zero mutations.
      // Only the probe-backed classification above proves a zero-external-
      // effect fault; a possibly-landed lost-ACK outcome carries NO proof and
      // the admission fence policy in admitCentralDecision keeps the fence
      // held (fail-closed UNKNOWN until reconciliation).
      // [v0.10 C01] The executor failed; the live permit is still consumed
      // (dead) once the failure record IS durable. A consume failure here is
      // MORE uncertain than the failure itself: surface the journal-conflict
      // class (UNKNOWN), never a clean FAILED the zero-ambiguity fence
      // release could act on.
      if (permit !== null) {
        try {
          await ports.effectPermitAdmin.consume(permit.effectId, permit.revision);
        } catch (consumeError) {
          throw new CentralAdmissionError(
            'ADMISSION_EFFECT_JOURNAL_CONFLICT',
            `effect ${effectId} failed (${message}) and its permit consume is ambiguous: ${consumeError instanceof Error ? consumeError.message : String(consumeError)}`,
          );
        }
      }
      const typed = new CentralAdmissionError(
        'ADMISSION_EFFECT_FAILED',
        `effect ${effectId} (${intent.effectType}) failed: ${message}`,
      );
      if (zeroEffect) {
        typed.zeroExternalEffect = true;
      }
      throw typed;
    }

    // [v0.10 C01 #1177] Consume the live permit BEFORE the journal completes:
    // an ambiguous consume surfaces as a typed journal conflict (the UNKNOWN
    // class) — the executor output is discarded, nothing terminal is claimed,
    // and the journal stays `started` so every replay gate stays honest.
    if (permit !== null) {
      try {
        await ports.effectPermitAdmin.consume(permit.effectId, permit.revision);
      } catch (error) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect permit consume for ${effectId} is ambiguous after the executor settled: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    let committed;
    try {
      committed = await ports.effectJournal.completeEffect(
        effectId,
        { status: 'completed', output, completedAt: request.now },
      );
    } catch (error) {
      // Never repeat the external mutation in this attempt; a fresh attempt
      // re-reads the durable journal and either replays or fails closed.
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect journal commit for ${effectId} is ambiguous: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    outcomes.push({
      effectId,
      effectType: intent.effectType,
      disposition: 'executed',
      ...(intent.idempotencyKey === undefined ? {} : { idempotencyKey: intent.idempotencyKey }),
      ...(committed.output === undefined ? {} : { output: committed.output }),
    });
  }
  return outcomes;
}

/**
 * The single central authoritative admission path (frozen L2 §15, Amendment
 * A1 §8.1): structured result → current schema → pinned Governance Baseline
 * Hard Invariants → current guard → transition → durable effect intent.
 *
 * Every resolver source (rule / exact cache / promoted subworkflow / Business
 * Harness) passes the same gates, so no source can bypass admission. The
 * admitted output is a plan for the parent Durable Control Turn publication;
 * admission itself never mutates workflow state, message dispositions or
 * control snapshots, and holds no resolver/evidence handle — guard rejection
 * is final, with no hidden resolver retry (S7).
 */
export async function admitCentralDecision(request, ports) {
  const turnId = deriveDurableControlTurnId(request.target, request.turn);
  const pinned = await requirePinnedBaseline(request, ports, ports.sha256);
  const resolver = admissionResolverEvidence(request.resolved);
  const trace = ports.trace; // [KPK-01 adaptation] measurement only

  const input = createPreparedDomainPredicateEvaluationInput(
    prepareDomainPredicateContext(request.context),
    prepareDomainPredicateEvent(request.event),
  );

  let schemaValid;
  try {
    schemaValid = request.decisionSchema.isValid(request.resolved.structuredDecision);
  } catch (error) {
    // The schema is caller authority; its failure fails the admission closed
    // inside the typed taxonomy rather than escaping as a naked error (P3-1).
    throw new CentralAdmissionError(
      'ADMISSION_EVALUATION_INPUT_INVALID',
      `decision schema evaluation failed closed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!schemaValid) {
    return deny('schema', turnId, pinned.bindingDigest, resolver);
  }

  const failedInvariant = evaluateHardInvariants(pinned.hardInvariants, input, trace);
  if (failedInvariant !== undefined) {
    return deny('hard-invariant', turnId, pinned.bindingDigest, resolver, { invariantId: failedInvariant });
  }

  const selection = selectAdmittedTransition(request, input, trace);
  if ('noCandidate' in selection) {
    return deny('no-candidate-transition', turnId, pinned.bindingDigest, resolver);
  }
  if ('rejected' in selection) {
    return deny('guard', turnId, pinned.bindingDigest, resolver, selection.rejected);
  }

  // [Controller 090 repair] Per-occurrence dynamic effect input/idempotency
  // binding is resolved HERE: after authorized transition admission, before
  // any journal write or effect dispatch. Static intents pass through with
  // exact v0.7 behavior; dynamic failures fail closed typed with zero
  // journal/resource activity.
  const effectIntents = resolveAdmissionEffectIntents(
    selection.admitted.effectIntents ?? [],
    request,
    ports.effectBindings,
  );

  // [#1005 D3-K] Declarative state-context projection: resolved after
  // authorized admission and before any journal write or effect dispatch;
  // committed by the caller's state CAS together with the target state.
  const context = resolveAdmissionContextProjection(selection.admitted, request, ports.contextProjections);
  if (context?.conflict !== undefined) {
    return deny('context-projection-conflict', turnId, pinned.bindingDigest, resolver, {
      transitionKey: selection.admitted.transitionKey,
      contextField: context.conflict.field,
    });
  }

  // [#1006 HF21] Production Effect/Journal authority gate: an admitted turn
  // that would mint durable production effects requires the occurrence's
  // exact PRODUCTION runtime authority class. A SIMULATION pin refuses typed
  // HERE — after authorized transition admission, BEFORE any journal write or
  // effect dispatch — leaving zero physical Effect. The gate is consumed from
  // the governance port (the ONE pin authority); a port that cannot express
  // production effect authority fails closed, never open.
  if (effectIntents.length > 0) {
    const requireProductionEffectAuthority = ports.governance?.requireProductionEffectAuthority;
    if (typeof requireProductionEffectAuthority !== 'function') {
      throw new CentralAdmissionError(
        'AUTHORITY_CLASS_FORBIDDEN',
        'the governance port carries no production effect authority gate; an effect-bearing admission fails closed',
      );
    }
    await requireProductionEffectAuthority.call(ports.governance, request.workflowInstanceId);
  }

  // [v0.8.1 R02] Pre-effect admission fence: the caller's durable claim on
  // the exact snapshot this decision was evaluated against. A stale
  // admission (another runtime over the same durable store claimed or
  // committed after this snapshot) loses HERE, typed — before any journal
  // begin or effect dispatch. [#1108 K01] The claim is also the protected
  // grant: once held, no rival can take the fence at this stateRevision, so
  // the effects below dispatch under a live grant the commit will still find
  // held (#requireHeldAdmissionFence).
  let heldAdmissionFence;
  if (typeof ports.admissionFence === 'function') {
    heldAdmissionFence = await ports.admissionFence(turnId);
  }

  let effects;
  try {
    effects = await executeEffectIntents(
      effectIntents,
      request,
      ports,
      turnId,
    );
  } catch (error) {
    // [#1108 K01 R1 P1 / R2 P1] Fence liveness on the failure path: release
    // ONLY on a PROVEN zero-external-effect fault. The thrown error carries
    // `zeroExternalEffect` solely when the dispatch probe proved the Business
    // handler never invoked the physical resources port, or EVERY port call
    // it made was attested by the trusted dispatcher as its own pre-handler
    // refusal — AND every begun effect of the turn is durably `failed` (an
    // earlier `completed`/`started` record keeps the fence held). A lost-ACK
    // / uncertain outcome carries NO proof — the external non-idempotent
    // mutation may already have landed, so the fence stays held: fail-closed
    // UNKNOWN until reconciliation (same-turn replay through the journal, or
    // a trusted-seam recovery turn over a durably all-failed holder). An
    // unreadable journal, an unwired release port, or a failed removal also
    // keeps it held. The original typed effect error is never masked.
    if (isJsonRecord(heldAdmissionFence)
      && typeof ports.admissionFenceRelease === 'function'
      && error !== null && typeof error === 'object' && error.zeroExternalEffect === true) {
      try {
        let ambiguous = false;
        for (let ordinal = 1; ordinal <= effectIntents.length; ordinal += 1) {
          const record = await ports.effectJournal?.getEffect(`${turnId}/effect/${String(ordinal)}`);
          if (record !== null && record !== undefined && record.status !== 'failed') {
            ambiguous = true;
            break;
          }
        }
        if (!ambiguous) {
          await ports.admissionFenceRelease(heldAdmissionFence);
        }
      } catch {
        // keep held — fail-closed
      }
    }
    throw error;
  }

  return {
    status: 'admitted',
    admitted: {
      durableControlTurnId: turnId,
      governanceBindingDigest: pinned.bindingDigest,
      transitionKey: selection.admitted.transitionKey,
      targetState: selection.admitted.targetState,
      effects,
      resolver,
      ...(context === undefined ? {} : { contextProjection: context.projection }),
    },
  };
}

// ===========================================================================
// [Controller 090 bounded repair (#993) — kernel-owned NEW mechanism code,
// NOT a v0.7 migration] Per-occurrence dynamic Admission Effect input
// binding and business idempotency-key binding (data-only, allowlisted,
// wiring-pinned).
//
// Closes the #972-documented contract limitation (#972@6096530583 CELL1,
// #972@6098188937 §C): the sealed kernel previously journaled and dispatched
// the transition-declared STATIC `intent.input`/`intent.idempotencyKey` on
// every occurrence, so per-request business data (approval amount/requestId,
// inventory sku/qty) could never reach the effect side. A Business package
// may now declare on a transition effect intent:
//
//   inputFrom:          { <effectField>: { source: 'event'|'decision', path } }
//   idempotencyKeyFrom: { template: 'reserve:quote:{requestId}' }
//
// Rules — all enforced by THIS kernel module, no other component gains
// authority:
//   - `event` paths may only address the rule-authorized projection
//     (['type'] or ['payload', <payloadFromInput key>]); `decision` paths
//     only the typed decision shape (['outcome'] or ['data', <same
//     authorized key>], because the Standard SDK projects decision.data
//     from the same authorized payload projection).
//   - Template literals are restricted to [A-Za-z0-9._:-]; every
//     {placeholder} must reference a declared inputFrom field.
//   - Static `input` and `inputFrom` (resp. `idempotencyKey` and
//     `idempotencyKeyFrom`) are mutually exclusive authorities.
//   - Validation happens ONCE at wiring (createOccurrenceRuntime — inside
//     the trusted DomainHarness.load installation boundary) and the
//     validated declaration is deep-frozen into a WeakMap keyed by the
//     exact intent objects: live mutation after wiring is IGNORED (the
//     snapshot is authoritative) and NEW binding syntax appearing on an
//     intent that was never wired fails typed at resolution
//     (ADMISSION_EFFECT_BINDING_UNVALIDATED).
//   - Resolution happens ONLY inside admitCentralDecision AFTER authorized
//     transition admission and BEFORE any journal write or effect dispatch;
//     a resolved idempotency key must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}
//     or the occurrence fails typed BEFORE the journal. Nothing is
//     string-evaluated; the resolved input must be canonical JSON; no Host
//     port, resource, doc store or UX payload participates in resolution.
// ===========================================================================

// Controller 093: reject hostile JSON-declared own destination keys at Kernel
// wiring before any effect-input assignment / journal / resource dispatch.
const EFFECT_DESTINATION_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const EFFECT_DESTINATION_FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor']);
const ADMISSION_EFFECT_IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TEMPLATE_PLACEHOLDER_PATTERN = /^[A-Za-z0-9_]+$/;
const TEMPLATE_LITERAL_PATTERN = /^[A-Za-z0-9._:-]*$/;

function invalidEffectBinding(message) {
  throw new CentralAdmissionError('ADMISSION_EFFECT_BINDING_INVALID', message);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

/** Parse a key template into literal/placeholder segments (validated shapes only). */
function parseEffectKeyTemplate(template) {
  const segments = [];
  let index = 0;
  while (index < template.length) {
    const open = template.indexOf('{', index);
    if (open === -1) {
      const tail = template.slice(index);
      if (tail.length > 0) segments.push({ literal: tail });
      break;
    }
    const literal = template.slice(index, open);
    if (literal.length > 0) segments.push({ literal });
    const close = template.indexOf('}', open + 1);
    if (close === -1) {
      invalidEffectBinding('idempotencyKeyFrom.template has an unterminated {placeholder}');
    }
    const placeholder = template.slice(open + 1, close);
    if (!TEMPLATE_PLACEHOLDER_PATTERN.test(placeholder)) {
      invalidEffectBinding(`idempotencyKeyFrom.template placeholder {${placeholder}} is not a plain field name`);
    }
    segments.push({ placeholder });
    index = close + 1;
  }
  if (segments.length === 0) invalidEffectBinding('idempotencyKeyFrom.template is empty');
  return segments;
}

function validatedAuthorizedKeys(rule) {
  const projection = rule?.payloadFromInput;
  if (!isPlainObject(projection)) {
    invalidEffectBinding(`rule ${String(rule?.ruleId)}: payloadFromInput must be an object to authorize a dynamic effect binding`);
  }
  return new Set(Object.keys(projection));
}

function validateEffectBindingPath(spec, field, authorizedKeys) {
  if (!isPlainObject(spec)) invalidEffectBinding(`inputFrom.${field} must be an object`);
  for (const key of Object.keys(spec)) {
    if (key !== 'source' && key !== 'path') {
      invalidEffectBinding(`inputFrom.${field} may only declare source and path`);
    }
  }
  if (spec.source !== 'event' && spec.source !== 'decision') {
    invalidEffectBinding(`inputFrom.${field}.source must be 'event' or 'decision'`);
  }
  const path = spec.path;
  if (
    !Array.isArray(path)
    || path.length === 0
    || path.length > 2
    || path.some((segment) => typeof segment !== 'string' || segment.length === 0)
  ) {
    invalidEffectBinding(`inputFrom.${field}.path must be one or two non-empty string segments`);
  }
  const withinEventProjection = (path.length === 1 && path[0] === 'type')
    || (path.length === 2 && path[0] === 'payload' && authorizedKeys.has(path[1]));
  const withinDecisionShape = (path.length === 1 && path[0] === 'outcome')
    || (path.length === 2 && path[0] === 'data' && authorizedKeys.has(path[1]));
  const allowed = spec.source === 'event' ? withinEventProjection : withinDecisionShape;
  if (!allowed) {
    invalidEffectBinding(
      `inputFrom.${field} ${spec.source} path [${path.join(', ')}] is outside the rule-authorized projection`,
    );
  }
}

function snapshotEffectBinding(intent, authorizedKeys) {
  const inputFrom = intent.inputFrom;
  if (!isPlainObject(inputFrom) || Object.keys(inputFrom).length === 0) {
    invalidEffectBinding('inputFrom must be a non-empty object of field bindings');
  }
  for (const [field, spec] of Object.entries(inputFrom)) {
    if (!EFFECT_DESTINATION_NAME.test(field) || EFFECT_DESTINATION_FORBIDDEN.has(field)) {
      invalidEffectBinding(`inputFrom destination field ${JSON.stringify(field)} must be a safe 1..64-character ASCII identifier, excluding prototype-sensitive names`);
    }
    validateEffectBindingPath(spec, field, authorizedKeys);
  }
  if (intent.idempotencyKeyFrom !== undefined) {
    if (!isPlainObject(intent.idempotencyKeyFrom) || Object.keys(intent.idempotencyKeyFrom).some((key) => key !== 'template')) {
      invalidEffectBinding('idempotencyKeyFrom may only declare template');
    }
    const template = intent.idempotencyKeyFrom.template;
    if (typeof template !== 'string' || template.length === 0 || template.length > 128) {
      invalidEffectBinding('idempotencyKeyFrom.template must be a 1..128 character string');
    }
    for (const segment of parseEffectKeyTemplate(template)) {
      if (segment.literal !== undefined && !TEMPLATE_LITERAL_PATTERN.test(segment.literal)) {
        invalidEffectBinding(
          `idempotencyKeyFrom.template literal "${segment.literal}" contains characters outside [A-Za-z0-9._:-]`,
        );
      }
      if (segment.placeholder !== undefined && !hasOwn(inputFrom, segment.placeholder)) {
        invalidEffectBinding(
          `idempotencyKeyFrom.template placeholder {${segment.placeholder}} is not a declared inputFrom field`,
        );
      }
    }
  }
  let frozenInputFrom;
  try {
    frozenInputFrom = cloneDataOnlyForPreparation(inputFrom, '$effectInputFrom');
  } catch (error) {
    invalidEffectBinding(`inputFrom must be JSON data only: ${error instanceof Error ? error.message : String(error)}`);
  }
  deepFreezePreparedData(frozenInputFrom);
  const snapshot = { inputFrom: frozenInputFrom };
  if (intent.idempotencyKeyFrom !== undefined) {
    snapshot.idempotencyKeyFrom = Object.freeze({ template: intent.idempotencyKeyFrom.template });
  }
  return Object.freeze(snapshot);
}

function definitionDeclaresDynamicBinding(definition) {
  for (const state of definition?.states ?? []) {
    for (const transition of state.transitions ?? []) {
      for (const intent of transition.effectIntents ?? []) {
        if (hasOwn(intent, 'inputFrom') || hasOwn(intent, 'idempotencyKeyFrom')) return true;
      }
    }
  }
  return false;
}

/**
 * Wiring-time validation of every dynamic effect-intent binding reachable
 * from the business policy, executed once inside createOccurrenceRuntime
 * (the trusted DomainHarness.load installation boundary). A malformed,
 * unauthorized or ambiguous declaration fails the load typed BEFORE any
 * instance can exist (KPK-10-class installation refusal; the producer and
 * Microkernel keep NO duplicate semantic validator).
 */
function wireAdmissionEffectBindings(businessEndpoint) {
  const registry = new WeakMap();

  const wireDefinition = (definition, rule, intentType) => {
    for (const state of definition?.states ?? []) {
      for (const transition of state.transitions ?? []) {
        for (const intent of transition.effectIntents ?? []) {
          if (!hasOwn(intent, 'inputFrom') && !hasOwn(intent, 'idempotencyKeyFrom')) continue;
          if (hasOwn(intent, 'input') && hasOwn(intent, 'inputFrom')) {
            invalidEffectBinding(`intent ${intentType}, transition ${transition.transitionKey}: static input and inputFrom are mutually exclusive`);
          }
          if (hasOwn(intent, 'idempotencyKey') && hasOwn(intent, 'idempotencyKeyFrom')) {
            invalidEffectBinding(`intent ${intentType}, transition ${transition.transitionKey}: static idempotencyKey and idempotencyKeyFrom are mutually exclusive`);
          }
          if (hasOwn(intent, 'idempotencyKeyFrom') && !hasOwn(intent, 'inputFrom')) {
            invalidEffectBinding(`intent ${intentType}, transition ${transition.transitionKey}: idempotencyKeyFrom requires inputFrom (placeholders reference declared fields)`);
          }
          const snapshot = snapshotEffectBinding(intent, validatedAuthorizedKeys(rule));
          const existing = registry.get(intent);
          if (existing !== undefined) {
            if (canonicalJsonStringify(existing) !== canonicalJsonStringify(snapshot)) {
              invalidEffectBinding(`intent ${intentType}: the same effect intent object is wired against conflicting rule authorizations`);
            }
          } else {
            registry.set(intent, snapshot);
          }
        }
      }
    }
  };

  for (const [intentType, binding] of Object.entries(businessEndpoint.intentBindings ?? {})) {
    const rule = (businessEndpoint.rules ?? {})[binding.ruleId];
    const definition = binding.definition ?? businessEndpoint.workflowDefinition;
    if (rule === undefined) {
      if (definitionDeclaresDynamicBinding(definition)) {
        invalidEffectBinding(`intent ${intentType}: a dynamic effect binding requires rule ${String(binding.ruleId)} to exist`);
      }
      continue;
    }
    wireDefinition(definition, rule, intentType);
  }
  return registry;
}

const BINDING_VALUE_MISSING = Symbol('v08-kernel.effect-binding.missing');

function readBindingPath(root, path) {
  let current = root;
  for (const segment of path) {
    if (current === null || typeof current !== 'object' || !hasOwn(current, segment)) {
      return BINDING_VALUE_MISSING;
    }
    current = current[segment];
  }
  return current;
}

/**
 * Resolve the per-occurrence dynamic effect inputs and idempotency keys for
 * the ADMITTED transition's effect intents. Called only from
 * admitCentralDecision AFTER authorized transition admission and BEFORE any
 * journal write or effect dispatch. Intents without dynamic declarations
 * pass through untouched (exact v0.7 static behavior). The wiring snapshot
 * is the ONLY trusted declaration source; a per-occurrence failure fails
 * closed typed with zero journal/resource activity.
 */
function resolveAdmissionEffectIntents(intents, request, wiring) {
  if (intents.length === 0) return intents;
  return intents.map((intent) => {
    if (!hasOwn(intent, 'inputFrom') && !hasOwn(intent, 'idempotencyKeyFrom')) {
      return intent; // static intent — v0.7-identical passthrough
    }
    const snapshot = wiring?.get(intent);
    if (snapshot === undefined) {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_BINDING_UNVALIDATED',
        `effect intent for ${intent.effectType} carries dynamic-binding syntax that was never validated at wiring; post-wiring injected declarations are refused`,
      );
    }
    const decision = request.resolved?.structuredDecision?.decision;
    const input = {};
    for (const [field, spec] of Object.entries(snapshot.inputFrom)) {
      const root = spec.source === 'event' ? request.event : decision;
      const value = root === undefined || root === null
        ? BINDING_VALUE_MISSING
        : readBindingPath(root, spec.path);
      if (value === BINDING_VALUE_MISSING) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_BINDING_UNRESOLVED',
          `effect input field ${field} (${spec.source} path ${spec.path.join('.')}) is not present on this occurrence; dynamic bindings fail closed before any journal write`,
        );
      }
      try {
        canonicalizeJson(value);
      } catch (error) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_BINDING_UNRESOLVED',
          `effect input field ${field} must be canonical JSON: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      input[field] = value;
    }
    let idempotencyKey;
    if (snapshot.idempotencyKeyFrom !== undefined) {
      let composed = '';
      for (const segment of parseEffectKeyTemplate(snapshot.idempotencyKeyFrom.template)) {
        if (segment.literal !== undefined) {
          composed += segment.literal;
          continue;
        }
        const value = input[segment.placeholder];
        if (value === null || typeof value === 'object' || typeof value === 'function' || typeof value === 'bigint' || typeof value === 'symbol') {
          throw new CentralAdmissionError(
            'ADMISSION_EFFECT_IDEMPOTENCY_KEY_INVALID',
            `idempotency key placeholder {${segment.placeholder}} must compose from a string, number or boolean value`,
          );
        }
        composed += String(value);
      }
      if (!ADMISSION_EFFECT_IDEMPOTENCY_KEY_PATTERN.test(composed)) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_IDEMPOTENCY_KEY_INVALID',
          `resolved idempotency key is not a safe token ([A-Za-z0-9][A-Za-z0-9._:-]{0,127}); refusing before any journal write`,
        );
      }
      idempotencyKey = composed;
    }
    return {
      effectType: intent.effectType,
      input,
      ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
    };
  });
}

// ===========================================================================
// [#1005 D3-K — kernel-owned NEW mechanism code, NOT a v0.7 migration]
// Declarative state-context projection (durable cross-stage lineage).
//
// Accepted minimal design: #1005@6130149429 (unlocked #1005@6151644929).
// Before this, a committed transition rewrote `context: current.state.context`
// unchanged, so no accepted stage could durably carry evidence (changeId,
// reviewedSha, validationId, testedSha …) to the next stage, and a guard could
// only compare an event with itself. A Business transition may now declare
//
//   contextProjection: { <contextField>: { source: 'event'|'decision',
//                                          path, type? } }
//
// with exactly the effect-binding path discipline (event ['payload', key] /
// decision ['data', key] inside THIS intent's rule-authorized projection, or
// ['type'] / ['outcome']). All rules are enforced HERE:
//   - validated ONCE at wiring and deep-frozen into a WeakMap keyed by the
//     exact transition object; live mutation is ignored and projection syntax
//     on an unwired transition refuses typed;
//   - resolved inside admitCentralDecision AFTER schema / hard-invariant /
//     guard admission and BEFORE any Journal write or Effect dispatch; a
//     missing or mistyped value fails typed with zero Journal/Effect;
//   - write-once lineage: a field already present in the committed context
//     may only be re-projected with the identical value, otherwise the
//     transition is denied ('context-projection-conflict') pre-effect;
//   - committed into the next state context by the SAME state CAS write that
//     moves the state (commitAcceptedTransitionInLane) — no second write, so a
//     crash/UNKNOWN before the CAS commits neither state nor lineage, and a
//     replay re-resolves the identical projection from the identical event.
// `callerRole` (K-injected predicate context) is never a projection target.
// ===========================================================================

const CONTEXT_PROJECTION_TYPES = new Set(['string', 'number', 'boolean', 'object', 'array', 'null']);
const CONTEXT_PROJECTION_RESERVED = new Set(['callerRole']);

function invalidContextProjection(message) {
  throw new CentralAdmissionError('ADMISSION_CONTEXT_PROJECTION_INVALID', message);
}

function contextValueType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function snapshotContextProjection(transition, rule, intentType) {
  const declared = transition.contextProjection;
  const label = `intent ${intentType}, transition ${String(transition.transitionKey)}`;
  if (!isPlainObject(declared) || Object.keys(declared).length === 0) {
    invalidContextProjection(`${label}: contextProjection must be a non-empty object of field projections`);
  }
  const projection = rule?.payloadFromInput;
  if (!isPlainObject(projection)) {
    invalidContextProjection(`${label}: rule ${String(rule?.ruleId)} must declare payloadFromInput to authorize a context projection`);
  }
  const authorizedKeys = new Set(Object.keys(projection));
  const fields = {};
  for (const [field, spec] of Object.entries(declared)) {
    if (!EFFECT_DESTINATION_NAME.test(field) || EFFECT_DESTINATION_FORBIDDEN.has(field) || CONTEXT_PROJECTION_RESERVED.has(field)) {
      invalidContextProjection(`${label}: context field ${JSON.stringify(field)} must be a safe 1..64-character identifier and not a reserved Kernel context key`);
    }
    if (!isPlainObject(spec) || Object.keys(spec).some((key) => key !== 'source' && key !== 'path' && key !== 'type')) {
      invalidContextProjection(`${label}: contextProjection.${field} may only declare source, path and type`);
    }
    if (spec.source !== 'event' && spec.source !== 'decision') {
      invalidContextProjection(`${label}: contextProjection.${field}.source must be 'event' or 'decision'`);
    }
    const path = spec.path;
    if (!Array.isArray(path) || path.length === 0 || path.length > 2 || path.some((segment) => typeof segment !== 'string' || segment.length === 0)) {
      invalidContextProjection(`${label}: contextProjection.${field}.path must be one or two non-empty string segments`);
    }
    const allowed = spec.source === 'event'
      ? (path.length === 1 && path[0] === 'type') || (path.length === 2 && path[0] === 'payload' && authorizedKeys.has(path[1]))
      : (path.length === 1 && path[0] === 'outcome') || (path.length === 2 && path[0] === 'data' && authorizedKeys.has(path[1]));
    if (!allowed) {
      invalidContextProjection(`${label}: contextProjection.${field} ${spec.source} path [${path.join(', ')}] is outside the rule-authorized projection`);
    }
    if (spec.type !== undefined && !CONTEXT_PROJECTION_TYPES.has(spec.type)) {
      invalidContextProjection(`${label}: contextProjection.${field}.type ${String(spec.type)} is not a JSON type`);
    }
    fields[field] = { source: spec.source, path: [...path], ...(spec.type === undefined ? {} : { type: spec.type }) };
  }
  deepFreezePreparedData(fields);
  return fields;
}

/**
 * Wiring-time validation of every context projection reachable from the
 * Business policy (createOccurrenceRuntime only — the trusted load boundary).
 */
function wireAdmissionContextProjections(businessEndpoint) {
  const registry = new WeakMap();
  for (const [intentType, binding] of Object.entries(businessEndpoint.intentBindings ?? {})) {
    const rule = (businessEndpoint.rules ?? {})[binding.ruleId];
    const definition = binding.definition ?? businessEndpoint.workflowDefinition;
    for (const state of definition?.states ?? []) {
      for (const transition of state.transitions ?? []) {
        if (!hasOwn(transition, 'contextProjection')) continue;
        const snapshot = snapshotContextProjection(transition, rule, intentType);
        const existing = registry.get(transition);
        if (existing !== undefined) {
          if (canonicalJsonStringify(existing) !== canonicalJsonStringify(snapshot)) {
            invalidContextProjection(`intent ${intentType}: the same transition object is wired against conflicting rule authorizations`);
          }
        } else {
          registry.set(transition, snapshot);
        }
      }
    }
  }
  return registry;
}

/**
 * Resolve the admitted transition's context projection (admitCentralDecision
 * only: after admission, before any Journal/Effect). The wiring-time frozen
 * snapshot is the FIRST authority — a live `contextProjection` property
 * deleted after wiring keeps the pinned projection; only a never-wired
 * transition carrying live projection syntax refuses typed. Returns
 * `undefined` when nothing was wired or declared, `{conflict}` for a
 * write-once violation, or `{projection}` — the canonical fields to merge
 * into the next context.
 */
function resolveAdmissionContextProjection(transition, request, wiring) {
  // [#1005 D3-K R2 — review #5508191410 P1] The wiring snapshot outranks the
  // live property: checking the live declaration first let a post-wiring
  // `delete transition.contextProjection` bypass the frozen projection.
  const fields = wiring?.get(transition);
  if (fields === undefined) {
    if (!hasOwn(transition, 'contextProjection')) return undefined;
    throw new CentralAdmissionError(
      'ADMISSION_CONTEXT_PROJECTION_UNVALIDATED',
      `transition ${String(transition.transitionKey)} carries context-projection syntax that was never validated at wiring; post-wiring injected declarations are refused`,
    );
  }
  const decision = request.resolved?.structuredDecision?.decision;
  const committed = request.context ?? {};
  const projection = {};
  for (const [field, spec] of Object.entries(fields)) {
    const root = spec.source === 'event' ? request.event : decision;
    const value = root === undefined || root === null ? BINDING_VALUE_MISSING : readBindingPath(root, spec.path);
    if (value === BINDING_VALUE_MISSING) {
      throw new CentralAdmissionError(
        'ADMISSION_CONTEXT_PROJECTION_UNRESOLVED',
        `context field ${field} (${spec.source} path ${spec.path.join('.')}) is not present on this occurrence; nothing is journaled or committed`,
      );
    }
    let canonical;
    try {
      canonical = canonicalizeJson(value);
    } catch (error) {
      throw new CentralAdmissionError(
        'ADMISSION_CONTEXT_PROJECTION_UNRESOLVED',
        `context field ${field} must be canonical JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (spec.type !== undefined && contextValueType(value) !== spec.type) {
      throw new CentralAdmissionError(
        'ADMISSION_CONTEXT_PROJECTION_UNRESOLVED',
        `context field ${field} must be of type ${spec.type}; nothing is journaled or committed`,
      );
    }
    if (hasOwn(committed, field) && canonicalJsonStringify(committed[field]) !== canonicalJsonStringify(canonical)) {
      return { conflict: { field } };
    }
    projection[field] = JSON.parse(JSON.stringify(canonical));
  }
  return { projection };
}

// ===========================================================================
// v0.7 migrated: admission/effect-journal.ts — VolatileAdmissionEffectJournal
// Source: packages/domain-harness/src/admission/effect-journal.ts (verbatim)
// ===========================================================================

function requireNonEmpty(value, label) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_JOURNAL_CONFLICT',
      `${label} must be a non-empty string`,
    );
  }
}

function validateRecord(record) {
  requireNonEmpty(record.effectId, 'effectId');
  requireNonEmpty(record.target.workflowId, 'workflowId');
  requireNonEmpty(record.target.instanceKey, 'instanceKey');
  requireNonEmpty(record.durableControlTurnId, 'durableControlTurnId');
  requireNonEmpty(record.effectType, 'effectType');
  if (!Number.isSafeInteger(record.operationOrdinal) || record.operationOrdinal <= 0) {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_JOURNAL_CONFLICT',
      'operationOrdinal must be a positive safe integer',
    );
  }
  if (!Number.isSafeInteger(record.attempt) || record.attempt <= 0) {
    throw new CentralAdmissionError(
      'ADMISSION_EFFECT_JOURNAL_CONFLICT',
      'attempt must be a positive safe integer',
    );
  }
}

function effectIdentityKey(record) {
  return canonicalJsonStringify({
    effectId: record.effectId,
    target: {
      workflowId: record.target.workflowId,
      instanceKey: record.target.instanceKey,
    },
    durableControlTurnId: record.durableControlTurnId,
    operationOrdinal: record.operationOrdinal,
    effectType: record.effectType,
    effectSemantics: record.effectSemantics,
    input: record.input,
    idempotencyKey: record.idempotencyKey ?? null,
  });
}

function sameIdentity(left, right) {
  return effectIdentityKey(left) === effectIdentityKey(right);
}

function outcomeKey(record) {
  return canonicalJsonStringify({
    status: record.status,
    output: record.output ?? null,
    error: record.error ?? null,
  });
}

/**
 * Portable deterministic logical-reference effect journal. It mirrors the
 * frozen re-begin/complete semantics so host adapters can be parity-tested; it
 * makes no host durability claim (T-022/T-023 own real durability proof).
 */
export class VolatileAdmissionEffectJournal {
  #records = new Map();

  // [T-C, #966] Input/return alias isolation: every stored record and every
  // returned record is a canonical deep snapshot, so caller-held objects can
  // never contaminate committed state and exposed results can never mutate
  // it (existing canonical utility — no alternate serializer).
  async getEffect(effectId) {
    const existing = this.#records.get(effectId);
    return existing === undefined ? null : snapshotJson(existing);
  }

  async beginEffect(record) {
    validateRecord(record);
    if (record.status !== 'started') {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        'beginEffect requires a started record',
      );
    }
    const existing = this.#records.get(record.effectId);
    if (existing !== undefined) {
      if (!sameIdentity(existing, record)) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect ${record.effectId} already exists with an incompatible identity`,
        );
      }
      return { disposition: 'existing', record: snapshotJson(existing) };
    }
    const stored = snapshotJson(record);
    this.#records.set(record.effectId, stored);
    return { disposition: 'created', record: snapshotJson(stored) };
  }

  async completeEffect(effectId, outcome) {
    requireNonEmpty(effectId, 'effectId');
    // Store-side canonical-JSON gate (P3-4): a journaled outcome must always be
    // canonical-JSON-safe, independent of the caller's own checks.
    try {
      canonicalJsonStringify(
        outcome.status === 'completed' ? { output: outcome.output } : { error: outcome.error },
      );
    } catch (error) {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect ${effectId} outcome must be canonical JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const existing = this.#records.get(effectId);
    if (existing === undefined) {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `cannot complete effect ${effectId} that was never begun`,
      );
    }
    const completed = snapshotJson(outcome.status === 'completed'
      ? {
          ...existing,
          status: 'completed',
          output: outcome.output,
          completedAt: outcome.completedAt,
        }
      : {
          ...existing,
          status: 'failed',
          error: outcome.error,
          completedAt: outcome.completedAt,
        });
    if (existing.status !== 'started') {
      if (outcomeKey(existing) !== outcomeKey(completed)) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect ${effectId} is already settled with a conflicting outcome`,
        );
      }
      return snapshotJson(existing);
    }
    this.#records.set(effectId, completed);
    return snapshotJson(completed);
  }

  getRecords() {
    return [...this.#records.values()]
      .map((record) => snapshotJson(record))
      .sort((left, right) =>
        left.effectId < right.effectId ? -1 : left.effectId > right.effectId ? 1 : 0);
  }
}

// ===========================================================================
// [KPK-01 experiment, kernel-owned] Durable effect journal adapter over the
// generic Host document-store port.
//
// The Host supplies raw durable document storage ONLY (get/put with
// compare-and-swap revision). ALL journal semantics — effect identity,
// re-begin compatibility, idempotent completion, conflict-fail-closed and the
// canonical-JSON gate — are owned by this Kernel Package code (ported from
// v0.7 effect-journal.ts above). The stored document is an envelope
// { kernelModuleSha256, record }; the inner record stays exactly the v0.7
// shape for golden comparison. A record pinned to a different kernel module
// SHA fails with typed code unavailability (KPK-09: no silent cross-version
// replay).
// ===========================================================================

function journalDocKey(effectId) {
  return `v08-kernel:effect-journal:${effectId}`;
}

/**
 * [T-C, P1-L2-CAS-01] Typed rejection contract of the Host document port:
 * a conditional write ({mustBeAbsent} | {mustMatchRevision}) that loses its
 * compare-and-swap race rejects with an error carrying
 * `code === 'HOST_CAS_CONFLICT'`. Any other rejection is a Host fault and is
 * rethrown untouched (never silently retried, never fallen through).
 */
function isHostCasConflict(error) {
  return typeof error === 'object' && error !== null && error.code === 'HOST_CAS_CONFLICT';
}

/** [T-C, #966] Canonical deep snapshot: isolated JSON data only (no aliasing). */
function snapshotJson(value) {
  return JSON.parse(canonicalJsonStringify(value));
}

export class KernelDurableEffectJournal {
  #docs;
  #moduleSha256;
  #counters;
  #docKeys;

  constructor(docs, moduleSha256, counters, docKeys = legacyKernelDocKeys()) {
    this.#docs = docs;
    this.#moduleSha256 = moduleSha256;
    this.#counters = counters;
    this.#docKeys = docKeys;
  }

  /**
   * [v0.10 K02] The journal doc-key builder of THIS runtime (legacy
   * `v08-kernel:` keys or the deployment-scoped grammar).
   */
  get docKeys() {
    return this.#docKeys;
  }

  /**
   * [T-C, P1-L2-CAS-01] The Host read returns the FULL {value, revision}
   * pair. The #994 source returned `doc.value` and dropped `doc.revision`,
   * which made every subsequent terminal write pass
   * `mustMatchRevision: undefined` — an unconditional write under the Host
   * contract — so two competing trusted same-effect terminal completions
   * could BOTH land and overwrite each other. The revision is now preserved
   * end-to-end and every write below is a strongly conditional CAS.
   */
  async #readEnvelope(effectId) {
    const doc = await this.#docs.get(this.#docKeys.journal(effectId));
    return doc === null ? null : { value: doc.value, revision: doc.revision };
  }

  async getEffect(effectId) {
    const envelope = await this.#readEnvelope(effectId);
    return envelope === null ? null : snapshotJson(envelope.value.record);
  }

  async beginEffect(record) {
    validateRecord(record);
    if (record.status !== 'started') {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        'beginEffect requires a started record',
      );
    }
    const existing = await this.#readEnvelope(record.effectId);
    if (existing !== null) {
      if (existing.value.kernelModuleSha256 !== this.#moduleSha256) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect ${record.effectId} is pinned to kernel module ${existing.value.kernelModuleSha256} which is unavailable under the loaded kernel module ${this.#moduleSha256}; typed code unavailability — no silent cross-version replay`,
        );
      }
      if (!sameIdentity(existing.value.record, record)) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect ${record.effectId} already exists with an incompatible identity`,
        );
      }
      return { disposition: 'existing', record: snapshotJson(existing.value.record) };
    }
    if (this.#counters !== undefined) this.#counters.journalBegins += 1;
    try {
      await this.#docs.put(this.#docKeys.journal(record.effectId), {
        kernelModuleSha256: this.#moduleSha256,
        record: snapshotJson(record),
      }, { mustBeAbsent: true });
    } catch (error) {
      // [T-C] Lost the conditional create against a concurrent begin: re-read
      // the authoritative envelope and settle honestly — same identity ⇒
      // existing; anything else fails typed. Never fall through to a second
      // unconditional write.
      if (!isHostCasConflict(error)) throw error;
      const winner = await this.#readEnvelope(record.effectId);
      if (
        winner !== null
        && winner.value.kernelModuleSha256 === this.#moduleSha256
        && sameIdentity(winner.value.record, record)
      ) {
        return { disposition: 'existing', record: snapshotJson(winner.value.record) };
      }
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect ${record.effectId} begin lost its conditional create race against an incompatible record`,
      );
    }
    return { disposition: 'created', record: snapshotJson(record) };
  }

  async completeEffect(effectId, outcome) {
    requireNonEmpty(effectId, 'effectId');
    try {
      canonicalJsonStringify(
        outcome.status === 'completed' ? { output: outcome.output } : { error: outcome.error },
      );
    } catch (error) {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect ${effectId} outcome must be canonical JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const envelope = await this.#readEnvelope(effectId);
    if (envelope === null) {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `cannot complete effect ${effectId} that was never begun`,
      );
    }
    if (envelope.value.kernelModuleSha256 !== this.#moduleSha256) {
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect ${effectId} is pinned to kernel module ${envelope.value.kernelModuleSha256} which is unavailable under the loaded kernel module ${this.#moduleSha256}; typed code unavailability — no silent cross-version replay`,
      );
    }
    const existing = envelope.value.record;
    // [T-C, #966] The completed record is a fresh canonical snapshot; the
    // caller's outcome object never aliases committed state.
    const completed = snapshotJson(outcome.status === 'completed'
      ? { ...existing, status: 'completed', output: outcome.output, completedAt: outcome.completedAt }
      : { ...existing, status: 'failed', error: outcome.error, completedAt: outcome.completedAt });
    if (existing.status !== 'started') {
      if (outcomeKey(existing) !== outcomeKey(completed)) {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_JOURNAL_CONFLICT',
          `effect ${effectId} is already settled with a conflicting outcome`,
        );
      }
      return snapshotJson(existing);
    }
    if (this.#counters !== undefined) this.#counters.journalCompletes += 1;
    try {
      // [T-C, P1-L2-CAS-01] STRONGLY CONDITIONAL terminal write: the CAS
      // expectation is the exact revision read above. A concurrent terminal
      // completion bumps the revision, so at most ONE of the competing
      // completions can land — the terminal status is never overwritten.
      await this.#docs.put(this.#docKeys.journal(effectId), {
        kernelModuleSha256: this.#moduleSha256,
        record: completed,
      }, { mustMatchRevision: envelope.revision });
    } catch (error) {
      if (!isHostCasConflict(error)) throw error;
      // Lost the terminal race. Re-read the authoritative record and settle
      // honestly: the SAME authoritative terminal outcome is returned
      // idempotently; a DIFFERENT outcome fails typed. There is NO
      // unconditional fall-through on the terminal path.
      const winner = await this.#readEnvelope(effectId);
      if (winner !== null && winner.value.kernelModuleSha256 === this.#moduleSha256) {
        const settled = winner.value.record;
        if (settled.status !== 'started') {
          if (outcomeKey(settled) !== outcomeKey(completed)) {
            throw new CentralAdmissionError(
              'ADMISSION_EFFECT_JOURNAL_CONFLICT',
              `effect ${effectId} is already settled with a conflicting outcome`,
            );
          }
          return snapshotJson(settled);
        }
      }
      throw new CentralAdmissionError(
        'ADMISSION_EFFECT_JOURNAL_CONFLICT',
        `effect ${effectId} terminal completion lost its conditional CAS race; the authoritative record must be re-read before any further terminal claim`,
      );
    }
    // [T-C, #966] The returned record is a snapshot DISTINCT from the stored
    // one: a caller mutating the result can never reach committed state.
    return snapshotJson(completed);
  }

  async getRecords() {
    const keys = await this.#docs.list(this.#docKeys.journalPrefix());
    const envelopes = await Promise.all(keys.map((key) => this.#docs.get(key)));
    return envelopes
      .filter((doc) => doc !== null)
      .map((doc) => snapshotJson(doc.value.record))
      .sort((left, right) =>
        left.effectId < right.effectId ? -1 : left.effectId > right.effectId ? 1 : 0);
  }
}

// ===========================================================================
// v0.7 migrated: engine/per-instance-serialized-lane.ts (verbatim)
// Source: packages/domain-harness/src/engine/per-instance-serialized-lane.ts
// ===========================================================================

function workflowAddressKey(address) {
  return JSON.stringify([address.workflowId, address.instanceKey]);
}

/**
 * Portable keyed scheduler: work for the same WorkflowAddress is chained, while
 * distinct addresses have independent promise tails and can progress concurrently.
 */
export class PerInstanceSerializedLane {
  #tails = new Map();

  run(address, operation) {
    const key = workflowAddressKey(address);
    const previous = this.#tails.get(key) ?? Promise.resolve();
    const result = previous.catch(() => undefined).then(operation);
    const tail = result.then(
      () => undefined,
      () => undefined,
    );

    this.#tails.set(key, tail);
    void tail.then(() => {
      if (this.#tails.get(key) === tail) {
        this.#tails.delete(key);
      }
    });

    return result;
  }
}

// ===========================================================================
// [#1063 HF20] ordered durable mutation observation — the Kernel-internal
// contract twin of `src/host-v8/hf20-mutation-observation.ts` (semantic
// twin only: the payload is self-contained sealed bytes and imports
// nothing). The observation window rides the SAME instance document the
// authoritative state CAS writes (create seeds INSTANCE_OPENED; every
// commitAcceptedTransitionInLane appends MUTATION_COMMITTED inside the same
// single-key CAS value), so a record can never exist without its committed
// stateRevision and vice versa — one physical row, one counter, one
// transaction. Ordering authority is `sequence` alone; eviction of the
// retained tail is the explicit RETENTION_TRUNCATED gap; cursors are
// stream-bound opaque tokens re-validated against the CURRENT window.
// ===========================================================================

const HF20_MUTATION_OBSERVATION_CONTRACT_VERSION = 'hf20-mutation-observation/1';
const HF20_MUTATION_OBSERVATION_RETENTION_LIMIT = 64;
const HF20_MUTATION_OBSERVATION_KINDS = ['INSTANCE_OPENED', 'MUTATION_COMMITTED'];

function isHf20SafeNonNegativeInteger(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isHf20MutationObservationWindow(value) {
  if (!isJsonRecord(value)) return false;
  if (value.contractVersion !== HF20_MUTATION_OBSERVATION_CONTRACT_VERSION) return false;
  if (!isHf20SafeNonNegativeInteger(value.mutationSequence)) return false;
  if (!Array.isArray(value.records)) return false;
  if (value.records.length > HF20_MUTATION_OBSERVATION_RETENTION_LIMIT) return false;
  if (value.records.length > value.mutationSequence) return false;
  const expectedFirst = value.mutationSequence - value.records.length + 1;
  for (let index = 0; index < value.records.length; index += 1) {
    const record = value.records[index];
    if (!isJsonRecord(record)) return false;
    if (!('sequence' in record) || !('kind' in record) || !('stateRevisionAfter' in record) || !('committedAt' in record)) {
      return false;
    }
    if (!isHf20SafeNonNegativeInteger(record.sequence) || record.sequence !== expectedFirst + index) return false;
    if (typeof record.kind !== 'string' || !HF20_MUTATION_OBSERVATION_KINDS.includes(record.kind)) return false;
    if (!isHf20SafeNonNegativeInteger(record.stateRevisionAfter)) return false;
    if (record.stateRevisionBefore !== undefined && !isHf20SafeNonNegativeInteger(record.stateRevisionBefore)) return false;
    if (record.sourceMessageId !== undefined && (typeof record.sourceMessageId !== 'string' || record.sourceMessageId.length === 0)) return false;
    if (typeof record.committedAt !== 'string' || record.committedAt.length === 0) return false;
    if (record.kind === 'INSTANCE_OPENED' && record.stateRevisionAfter !== 0) return false;
    if (record.kind === 'MUTATION_COMMITTED' && record.stateRevisionBefore !== record.stateRevisionAfter - 1) return false;
  }
  return true;
}

function newHf20ObservationWindow() {
  return {
    contractVersion: HF20_MUTATION_OBSERVATION_CONTRACT_VERSION,
    mutationSequence: 0,
    records: [],
  };
}

/**
 * The PURE append reducer the commit path runs INSIDE its CAS write value.
 * There is deliberately no separate append entry point: an observation
 * record that did not ride the authoritative commit would be exactly the
 * best-effort second-document shape HF20 forbids.
 */
function appendHf20MutationObservation(window, intent, committedAt) {
  if (!isHf20MutationObservationWindow(window)) {
    throw new CentralAdmissionError(
      'WINDOW_INVALID',
      'the stored mutation-observation window is structurally invalid; the commit fails closed',
    );
  }
  if (!HF20_MUTATION_OBSERVATION_KINDS.includes(intent.kind)) {
    throw new CentralAdmissionError('WINDOW_INVALID', `unknown mutation observation kind ${String(intent.kind)}`);
  }
  if (!isHf20SafeNonNegativeInteger(intent.stateRevisionAfter)) {
    throw new CentralAdmissionError('WINDOW_INVALID', 'stateRevisionAfter must be a safe non-negative integer');
  }
  if (typeof committedAt !== 'string' || committedAt.length === 0) {
    throw new CentralAdmissionError('WINDOW_INVALID', 'committedAt must be a non-empty string');
  }
  const record = {
    sequence: window.mutationSequence + 1,
    kind: intent.kind,
    stateRevisionAfter: intent.stateRevisionAfter,
    ...(intent.stateRevisionBefore === undefined ? {} : { stateRevisionBefore: intent.stateRevisionBefore }),
    ...(intent.sourceMessageId === undefined ? {} : { sourceMessageId: intent.sourceMessageId }),
    committedAt,
  };
  if (record.kind === 'INSTANCE_OPENED' && record.stateRevisionAfter !== 0) {
    throw new CentralAdmissionError('WINDOW_INVALID', 'INSTANCE_OPENED must commit at stateRevisionAfter 0');
  }
  if (record.kind === 'MUTATION_COMMITTED' && record.stateRevisionBefore !== record.stateRevisionAfter - 1) {
    throw new CentralAdmissionError('WINDOW_INVALID', 'MUTATION_COMMITTED must advance the document revision by exactly one');
  }
  return {
    window: {
      contractVersion: HF20_MUTATION_OBSERVATION_CONTRACT_VERSION,
      mutationSequence: record.sequence,
      records: [...window.records, record].slice(-HF20_MUTATION_OBSERVATION_RETENTION_LIMIT),
    },
    record,
  };
}

// Opaque cursor codec — base64url over UTF-8 JSON {v,s,a}, implemented with
// no Node/global dependency (the payload keeps its sealed-bytes portability;
// the encoding is wire-identical to any standard base64url implementation).
const HF20_CURSOR_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function utf8EncodeHf20(text) {
  const bytes = [];
  for (let index = 0; index < text.length; index += 1) {
    let code = text.charCodeAt(index);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length
      && text.charCodeAt(index + 1) >= 0xdc00 && text.charCodeAt(index + 1) <= 0xdfff) {
      code = 0x10000 + ((code - 0xd800) << 10) + (text.charCodeAt(index + 1) - 0xdc00);
      index += 1;
      bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return bytes;
}

function utf8DecodeHf20(bytes) {
  let text = '';
  for (let index = 0; index < bytes.length;) {
    const lead = bytes[index];
    index += 1;
    let code;
    if (lead < 0x80) {
      code = lead;
    } else if (lead >= 0xc0 && lead < 0xe0) {
      code = ((lead & 0x1f) << 6) | (bytes[index] & 0x3f);
      index += 1;
    } else if (lead >= 0xe0 && lead < 0xf0) {
      code = ((lead & 0x0f) << 12) | ((bytes[index] & 0x3f) << 6) | (bytes[index + 1] & 0x3f);
      index += 2;
    } else {
      code = ((lead & 0x07) << 18) | ((bytes[index] & 0x3f) << 12) | ((bytes[index + 1] & 0x3f) << 6) | (bytes[index + 2] & 0x3f);
      index += 3;
    }
    if (code > 0xffff) {
      code -= 0x10000;
      text += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    } else {
      text += String.fromCharCode(code);
    }
  }
  return text;
}

function base64UrlEncodeHf20(text) {
  const bytes = utf8EncodeHf20(text);
  let encoded = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const b0 = bytes[index];
    const b1 = index + 1 < bytes.length ? bytes[index + 1] : undefined;
    const b2 = index + 2 < bytes.length ? bytes[index + 2] : undefined;
    encoded += HF20_CURSOR_ALPHABET[b0 >> 2];
    encoded += HF20_CURSOR_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    encoded += HF20_CURSOR_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    encoded += HF20_CURSOR_ALPHABET[b2 & 0x3f];
  }
  return encoded;
}

function base64UrlDecodeHf20(encoded) {
  let bitBuffer = 0;
  let bitCount = 0;
  const bytes = [];
  for (const character of encoded) {
    const value = HF20_CURSOR_ALPHABET.indexOf(character);
    if (value < 0) {
      throw new CentralAdmissionError('CURSOR_MALFORMED', `the cursor token carries a non-base64url character`);
    }
    bitBuffer = (bitBuffer * 64) + value;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push(Math.floor(bitBuffer / (2 ** bitCount)) & 0xff);
      bitBuffer %= (2 ** bitCount);
    }
  }
  return bytes;
}

function encodeHf20Cursor(stream, after) {
  if (typeof stream !== 'string' || stream.length === 0) {
    throw new CentralAdmissionError('CURSOR_MALFORMED', 'a cursor requires a non-empty stream identity');
  }
  if (!isHf20SafeNonNegativeInteger(after)) {
    throw new CentralAdmissionError('CURSOR_MALFORMED', 'a cursor requires a safe non-negative exclusive-after sequence');
  }
  return base64UrlEncodeHf20(JSON.stringify({ v: 1, s: stream, a: after }));
}

function decodeHf20Cursor(cursor) {
  if (typeof cursor !== 'string' || cursor.length === 0) {
    throw new CentralAdmissionError('CURSOR_MALFORMED', 'a cursor token must be a non-empty string');
  }
  let payload;
  try {
    payload = JSON.parse(utf8DecodeHf20(base64UrlDecodeHf20(cursor)));
  } catch (error) {
    if (error instanceof CentralAdmissionError) throw error;
    throw new CentralAdmissionError('CURSOR_MALFORMED', 'the cursor token is not decodable base64url JSON');
  }
  if (!isJsonRecord(payload) || payload.v !== 1 || typeof payload.s !== 'string' || payload.s.length === 0
    || !isHf20SafeNonNegativeInteger(payload.a)) {
    throw new CentralAdmissionError('CURSOR_MALFORMED', 'the cursor token does not carry the {v,s,a} contract shape');
  }
  return { stream: payload.s, after: payload.a };
}

function clampHf20ReadLimit(limit) {
  if (limit === undefined) return 100;
  if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1) {
    throw new CentralAdmissionError('READ_LIMIT_INVALID', 'the read limit must be an integer ≥ 1');
  }
  return Math.min(limit, 1000);
}

function projectHf20ObservationPage(window, request) {
  if (!isHf20MutationObservationWindow(window)) {
    throw new CentralAdmissionError('WINDOW_INVALID', 'the stored mutation-observation window is structurally invalid; fail closed');
  }
  if (typeof request.stream !== 'string' || request.stream.length === 0) {
    throw new CentralAdmissionError('CURSOR_STREAM_MISMATCH', 'a read requires the exact stream identity being read');
  }
  const limit = clampHf20ReadLimit(request.limit);
  let after = 0;
  if (request.afterCursor !== undefined) {
    const decoded = decodeHf20Cursor(request.afterCursor);
    if (decoded.stream !== request.stream) {
      throw new CentralAdmissionError(
        'CURSOR_STREAM_MISMATCH',
        `the cursor was minted for stream ${decoded.stream}, not ${request.stream}; substitution fails closed`,
      );
    }
    if (decoded.after > window.mutationSequence) {
      throw new CentralAdmissionError(
        'CURSOR_BEYOND_WATERMARK',
        `the cursor claims sequence ${String(decoded.after)} but the stream's committed watermark is ${String(window.mutationSequence)}; no such progress was ever committed`,
      );
    }
    after = decoded.after;
  }
  const highWatermark = window.mutationSequence;
  const retained = window.records;
  const earliestAvailable = retained.length > 0 ? retained[0].sequence : undefined;
  const truncated = after < highWatermark
    && earliestAvailable !== undefined
    && after < earliestAvailable - 1;
  const records = retained.filter((record) => record.sequence > after).slice(0, limit);
  const lastRecord = records.length > 0 ? records[records.length - 1] : undefined;
  return {
    records,
    ...(lastRecord !== undefined ? { nextCursor: encodeHf20Cursor(request.stream, lastRecord.sequence) } : {}),
    highWatermark,
    ...(truncated
      ? {
        gap: {
          kind: 'RETENTION_TRUNCATED',
          requestedAfter: after,
          ...(earliestAvailable === undefined ? {} : { earliestAvailable }),
          highWatermark,
        },
      }
      : {}),
  };
}

/**
 * [#1063 HF20 read-scope boundary] The outward projection of one instance
 * snapshot: the K-only carrier fields (`mutationObservations` — HF20;
 * `admittedControlTurns` — #1066 same-CAS turn admission history;
 * `durableOriginalReceipts` — v0.10 K02 same-CAS original-receipt ring) stay
 * INTERNAL next-CAS/replay truth and never leave the Kernel through
 * queryInstance/FR05/Genesis/receipt surfaces; the protected
 * mutation-observation read verb is the ONLY authorized reader of the
 * observation window, and the turn history and receipt ring have no outward
 * reader at all.
 */
function outwardInstanceSnapshot(snapshot) {
  if (!isJsonRecord(snapshot)) return snapshot;
  if (!('mutationObservations' in snapshot) && !('admittedControlTurns' in snapshot)
    && !('durableOriginalReceipts' in snapshot)) return snapshot;
  const outward = {};
  for (const key of Object.keys(snapshot)) {
    if (key === 'mutationObservations' || key === 'admittedControlTurns' || key === 'durableOriginalReceipts') continue;
    outward[key] = snapshot[key];
  }
  return outward;
}

// ===========================================================================
// v0.7 migrated: instance/persistent-workflow-instance.ts +
// engine/workflow-instance-engine.ts
// [KPK-01 adaptation] the v0.7 RuntimeStore port is replaced by the generic
// Host document-store port (get/put CAS/list). The instance snapshot
// discipline — stateRevision sequencing, identity assertions on committed
// reads, one-writer serialized lane — stays entirely in this Kernel Package
// code, verbatim from v0.7. The Host never learns workflow semantics.
// ===========================================================================

// ===========================================================================
// [v0.10 K02 #1168 phase-2] Durable original-receipt carrier — SPLICED into
// the selected kernel after the K01 single-writer release (#1167@36f068e3).
// The spliced discipline (from the phase-1 fragment
// durable-receipt-carrier-v1.mjs, dependency-free restatement):
//   1. Turn identity is input-complete and deployment-scoped: the canonical
//      input digest and the deployment scope tuple join
//      turnDispositionIdentity; the pinned module SHA rides the envelope as
//      buildIdentity (identity stable across releases).
//   2. The original acknowledged receipt of every admitted turn is composed
//      BEFORE the authoritative state CAS and committed INSIDE the same
//      document value (append-only `durableOriginalReceipts` map) — one
//      physical row write makes the state, the revision and the original
//      receipt durable together or not at all.
//   3. The submit lane consults the same-CAS receipt (ring → archive) BEFORE
//      the history/disposition ladder; the post-commit disposition/receipt
//      records stay best-effort observations (archive-only) that never
//      falsify the original and never block admission.
//   4. The bounded in-document receipt ring (default 64 ≥ 4× the frozen
//      16-entry history) replaces the missing-disposition fail-closed
//      eviction block: the oldest entry leaves only once its independent
//      durable archive record exists (archive-gated, fault-tolerant growth —
//      admission never blocks, an admitted turn is never forgotten).
//   5. The six durable doc families route through the injective deployment-
//      scoped key grammar `v010-k02:<app>:<tenant>:<appId>:<pkg>:<kind>:<parts>`
//      when the runtime wires a deployment scope; without one the historical
//      `v08-kernel:` keys are kept byte-for-byte (the unscoped wiring is the
//      compatibility mode — the two-B physical namespace is opt-in until a
//      deployment wires its identity).
// ===========================================================================

const K02_CARRIER_VERSION = 1;
const K02_SCOPED_KEY_ROOT = 'v010-k02';
const K02_SCOPE_FIELDS = ['deployedAppId', 'tenantId', 'appId', 'businessPackageId'];
const K02_SCOPED_DOC_KINDS = [
  'wf-instance',
  'admission-fence',
  'effect-journal',
  'turn-disposition',
  'decision-receipt',
  'receipt-archive',
  // [v0.10 C01 #1177] The K-issued live external Effect Permit rides the same
  // scoped grammar so a scoped deployment keeps its permits inside its own
  // injective key namespace (additive kind; the six K02 kinds are unchanged).
  'effect-permit',
  // [v0.10 C01 #1177 R1 P1-1] The atomic per-(effectId,attempt) external
  // dispatch claim: one effect grounds at most one adapter invocation.
  'effect-dispatch-claim',
];

/**
 * [v0.10 K02] Validate ONE deployment scope tuple. Exactly the four bounded
 * non-empty identifier fields; unknown fields and control characters refuse
 * typed K02_SCOPE_INVALID before any key or document can exist.
 */
function deploymentScopeIdentity(scope) {
  const fail = (message) => new CentralAdmissionError('K02_SCOPE_INVALID', message);
  if (!isJsonRecord(scope)) {
    throw fail('a deployment scope must be a record {deployedAppId, tenantId, appId, businessPackageId}');
  }
  for (const key of Object.keys(scope)) {
    if (!K02_SCOPE_FIELDS.includes(key)) {
      throw fail(`a deployment scope carries the unsupported field ${JSON.stringify(key)}`);
    }
  }
  for (const field of K02_SCOPE_FIELDS) {
    const value = scope[field];
    if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
      throw fail(`scope.${field} must be a bounded non-empty string identifier`);
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f]/.test(value)) {
      throw fail(`scope.${field} must not contain control characters`);
    }
  }
  return Object.freeze({
    deployedAppId: scope.deployedAppId,
    tenantId: scope.tenantId,
    appId: scope.appId,
    businessPackageId: scope.businessPackageId,
  });
}

/**
 * [v0.10 K02] Percent-encode ONE key component so the positional
 * `:`-joined grammar stays injective even when identifiers legitimately
 * carry the separator (package ids like `pkg:quote@1.0.0`).
 */
function encodeK02KeyComponent(value) {
  return value.replace(/%/g, '%25').replace(/:/g, '%3A');
}

function requireK02KeyPart(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) {
    throw new CentralAdmissionError('K02_SCOPE_INVALID', 'a doc key part must be a bounded non-empty string');
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f]/.test(value)) {
    throw new CentralAdmissionError('K02_SCOPE_INVALID', 'a doc key part must not contain control characters');
  }
  return value;
}

/**
 * [v0.10 K02] The closed scoped key grammar:
 * `v010-k02:<app>:<tenant>:<appId>:<pkg>:<kind>:<parts...>`. Positional,
 * percent-encoded, injective across scopes, kinds and parts.
 */
function scopedDocKey(scope, kind, ...parts) {
  const frozen = deploymentScopeIdentity(scope);
  if (!K02_SCOPED_DOC_KINDS.includes(kind)) {
    throw new CentralAdmissionError(
      'K02_SCOPE_INVALID',
      `unknown scoped doc kind ${JSON.stringify(kind)}; the grammar is closed`,
    );
  }
  return [
    K02_SCOPED_KEY_ROOT,
    encodeK02KeyComponent(frozen.deployedAppId),
    encodeK02KeyComponent(frozen.tenantId),
    encodeK02KeyComponent(frozen.appId),
    encodeK02KeyComponent(frozen.businessPackageId),
    encodeK02KeyComponent(kind),
    ...parts.map((part) => encodeK02KeyComponent(requireK02KeyPart(part))),
  ].join(':');
}

/**
 * [v0.10 K02] The per-runtime doc-key builders of the six durable families.
 * Legacy (unscoped) wiring keeps the historical `v08-kernel:` keys
 * byte-for-byte; a wired deployment scope routes every family through the
 * injective scoped grammar. Key builders are chosen ONCE at the runtime
 * wiring boundary — never per call.
 */
function legacyKernelDocKeys() {
  return {
    instance: (address) => instanceDocKey(address),
    admissionFence: (address) => admissionFenceDocKey(address),
    journal: (effectId) => journalDocKey(effectId),
    journalPrefix: () => 'v08-kernel:effect-journal:',
    turnDisposition: (turnId) => turnDispositionDocKey(turnId),
    decisionReceipt: (turnId) => decisionReceiptDocKey(turnId),
    receiptArchive: (turnId) => `v08-kernel:receipt-archive:${turnId}`,
    // [v0.10 C01 #1177] Legacy-family permit key (the v0.10 T00 facade path).
    effectPermit: (effectId) => `v08-kernel:effect-permit:${effectId}`,
    // [v0.10 C01 #1177 R1 P1-1] Atomic external dispatch claim per effect+attempt.
    effectDispatchClaim: (effectId, attempt) => `v08-kernel:effect-dispatch-claim:${effectId}/attempt/${attempt}`,
  };
}

// [v0.10 K02 R1 P2-1] The journal family's list channel needs its OWN
// prefix constructor: a scoped `journal('')` would run an empty key part
// through requireK02KeyPart and refuse typed, breaking the public
// getJournalRecords surface for every scoped deployment.
function scopedDocKeyPrefix(scope, kind) {
  const frozen = deploymentScopeIdentity(scope);
  if (!K02_SCOPED_DOC_KINDS.includes(kind)) {
    throw new CentralAdmissionError(
      'K02_SCOPE_INVALID',
      `unknown scoped doc kind ${JSON.stringify(kind)}; the grammar is closed`,
    );
  }
  return [
    K02_SCOPED_KEY_ROOT,
    encodeK02KeyComponent(frozen.deployedAppId),
    encodeK02KeyComponent(frozen.tenantId),
    encodeK02KeyComponent(frozen.appId),
    encodeK02KeyComponent(frozen.businessPackageId),
    encodeK02KeyComponent(kind),
  ].join(':') + ':';
}

function scopedKernelDocKeys(scope) {
  const frozen = deploymentScopeIdentity(scope);
  return {
    instance: (address) => scopedDocKey(frozen, 'wf-instance', address.workflowId, address.instanceKey),
    admissionFence: (address) => scopedDocKey(frozen, 'admission-fence', address.workflowId, address.instanceKey),
    journal: (effectId) => scopedDocKey(frozen, 'effect-journal', effectId),
    journalPrefix: () => scopedDocKeyPrefix(frozen, 'effect-journal'),
    turnDisposition: (turnId) => scopedDocKey(frozen, 'turn-disposition', turnId),
    decisionReceipt: (turnId) => scopedDocKey(frozen, 'decision-receipt', turnId),
    receiptArchive: (turnId) => scopedDocKey(frozen, 'receipt-archive', turnId),
    effectPermit: (effectId) => scopedDocKey(frozen, 'effect-permit', effectId),
    effectDispatchClaim: (effectId, attempt) => scopedDocKey(frozen, 'effect-dispatch-claim', `${effectId}/attempt/${attempt}`),
  };
}

function instanceDocKey(address) {
  return `v08-kernel:wf-instance:${address.workflowId}:${address.instanceKey}`;
}

// ===========================================================================
// [v0.8.1 R02] Admission fence. The per-instance serialized lane is
// in-process only: two runtimes over ONE durable store (two Host processes
// over one SQLite file) each hold their own lane, so the v0.7
// expectedTargetSequence discipline must be enforced by the durable store
// itself. Every admission (a) claims this per-instance fence document by CAS
// at the revision observed with its snapshot BEFORE any journal begin or
// effect dispatch, and (b) commits the state CAS only at that exact
// snapshot stateRevision while still holding the fence. The fence is a
// SEPARATE document so the instance document revision stays equal to its
// stateRevision (the continuation query read relies on that invariant).
// The v0.8 Host true-CAS store has no cross-document atomic batch: an
// admission whose snapshot predates another claim always loses before
// effects; a claim taken over while its holder is still dispatching (the
// holder's whole effect window overlapping another runtime's fresh
// read→decide→claim) makes the holder lose at commit, journaled exactly
// like the existing crash window — atomicity is never claimed.
// ===========================================================================

function admissionFenceDocKey(address) {
  return `v08-kernel:admission-fence:${address.workflowId}:${address.instanceKey}`;
}

function admissionStateCasConflict(message) {
  return new CentralAdmissionError('ADMISSION_STATE_CAS_CONFLICT', message);
}

function isHostWriteConflict(error) {
  return typeof error === 'object' && error !== null
    && (error.code === 'HOST_CAS_CONFLICT' || error.code === 'HOST_KEY_EXISTS');
}

// [#1108 K01 R1 P1 / R2 P1] Zero-external-effect proof for a FAILED effect
// dispatch. The ONLY trustworthy proof channels are the ones a resource
// adapter can neither forge nor propagate:
//   - the Business handler NEVER invoked the physical resources port
//     (probe.invoked stays false) — nothing could have been dispatched;
//   - EVERY resources-port call the handler made carries a kernel-minted
//     per-call ATTESTATION marked by the trusted host dispatcher for one of
//     its OWN pre-handler refusals (malformed arguments, reserved
//     scoped-physical namespace, unprovisioned key) — refusals thrown
//     BEFORE any resource adapter handler was ever invoked.
// Any error OBJECT or `code` STRING thrown out of a port call proves
// NOTHING: a resource adapter / Business handler can perform the physical
// mutation and only then throw an error carrying any code name — including
// HOST_RESOURCE_PRE_DISPATCH and every code the dispatcher itself owns — as
// an honest collision with no malicious code required (the R2 reviewer's
// tagged lost-ACK counterexample: append the ledger line, then throw
// `code: 'HOST_RESOURCE_MALFORMED'`). Code strings are therefore PERMANENTLY
// disqualified as zero-effect evidence. The attestation object is minted by
// this kernel, threaded per call, marked only by the trusted host
// dispatcher synchronously before its refusal throws, and NEVER forwarded
// to the adapter or its handler — an adapter cannot mark, strip or fake it.
// Everything else (any unattested call, any handler fault, a transport
// timeout, a lost ACK after the mutation landed, the uncertain
// HOST_FAULT_INJECTED injection) is UNCERTAIN and keeps the admission fence
// held: fail-closed.

/**
 * [#1108 K01 R1 P1 / R2 P1] Zero-external-effect PROOF for an execute() that
 * threw. The probe is created by executeEffectIntents and honored by this
 * runtime's own effectTools executor (probe.supported); a foreign executor
 * that ignores it leaves `supported` false and NOTHING is provable —
 * fail-closed. The thrown error is deliberately NOT an input: error codes
 * prove nothing (see the block above).
 *   !invoked            → the Business handler never called the physical
 *                         dispatch port → provably zero external effect
 *   invoked + EVERY call attested pre-handler-refused by the trusted
 *                         dispatcher → provably zero
 *   anything else       → possibly landed (unattested call, handler fault,
 *                         lost ACK) → NOT provable; the admission fence must
 *                         stay held
 */
function probeProvesZeroExternalEffect(probe) {
  if (probe === undefined || probe === null || typeof probe !== 'object') return false;
  if (probe.supported !== true) return false;
  if (probe.invoked !== true) return true;
  const attests = probe.dispatchAttests;
  return Array.isArray(attests) && attests.length > 0
    && attests.every((attest) => attest !== null && typeof attest === 'object'
      && typeof attest.preHandlerRefusal === 'string');
}

export class WorkflowInstanceNotFoundError extends Error {
  constructor(address) {
    super(`Workflow instance not found: ${address.workflowId}/${address.instanceKey}`);
    this.name = 'WorkflowInstanceNotFoundError';
    this.address = address;
  }
}

function workflowAddressesEqual(left, right) {
  return left.workflowId === right.workflowId && left.instanceKey === right.instanceKey;
}

export class PersistentWorkflowInstanceRepository {
  #docs;
  #now;
  #docKeys;

  constructor(docs, now = () => new Date().toISOString(), docKeys = legacyKernelDocKeys()) {
    this.#docs = docs;
    this.#now = now;
    this.#docKeys = docKeys;
  }

  async create(request) {
    const timestamp = this.#now();
    // [#1063 HF20] The observation window rides the created instance
    // document from byte zero: INSTANCE_OPENED commits at stateRevision 0
    // in the SAME mustBeAbsent put that creates the row.
    const opened = appendHf20MutationObservation(
      newHf20ObservationWindow(),
      { kind: 'INSTANCE_OPENED', stateRevisionAfter: 0 },
      timestamp,
    );
    const snapshot = {
      address: { ...request.address },
      correlationId: request.correlationId,
      packageId: request.packageId,
      lifecycle: request.lifecycle ?? 'active',
      stateRevision: 0,
      state: request.initialState,
      mutationObservations: opened.window,
      // [v0.10 K02] The append-only original-receipt ring exists from byte
      // zero (redacted from every outward projection).
      durableOriginalReceipts: {},
      createdAt: timestamp,
      updatedAt: timestamp,
    };

    await this.#docs.put(this.#docKeys.instance(request.address), snapshot, { mustBeAbsent: true });
    return this.require(request.address);
  }

  async resolve(address) {
    const doc = await this.#docs.get(this.#docKeys.instance(address));
    return doc === null ? null : doc.value;
  }

  async require(address) {
    const snapshot = await this.resolve(address);
    if (snapshot === null) {
      throw new WorkflowInstanceNotFoundError(address);
    }
    return snapshot;
  }
}

export class WorkflowInstanceEngine {
  #instances;
  #docs;
  #lane;
  #now;
  #counters;
  #docKeys;
  #durableReceiptRingBound;

  constructor(docs, options = {}) {
    this.#docs = docs;
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#lane = options.lane ?? new PerInstanceSerializedLane();
    this.#docKeys = options.docKeys ?? legacyKernelDocKeys();
    this.#instances = new PersistentWorkflowInstanceRepository(docs, this.#now, this.#docKeys);
    this.#counters = options.counters;
    const ringBound = options.durableReceiptRingBound ?? K02_DURABLE_RECEIPT_RING_BOUND_DEFAULT;
    if (!Number.isSafeInteger(ringBound) || ringBound < 17) {
      throw new CentralAdmissionError(
        'K02_SCOPE_INVALID',
        'durableReceiptRingBound must be a safe integer >= 17 (the once-only acceptance floor)',
      );
    }
    this.#durableReceiptRingBound = ringBound;
  }

  get lane() {
    return this.#lane;
  }

  createInstance(request) {
    if (this.#counters !== undefined) this.#counters.instanceCreates += 1;
    return this.#instances.create(request);
  }

  getInstance(target) {
    if (this.#counters !== undefined) this.#counters.instanceReads += 1;
    return this.#instances.resolve(target);
  }

  /**
   * v0.7 processAcceptedTransition over the generic Host doc port: the commit
   * is a compare-and-swap document write whose expected revision IS the v0.7
   * expectedTargetSequence (single-writer discipline is upheld by the lane).
   */
  processAcceptedTransition(request) {
    return this.#lane.run(request.target, () => this.commitAcceptedTransitionInLane(request));
  }

  /**
   * [v0.8.1 R02] The admission fence revision observed together with an
   * admission snapshot (null: no admission was ever claimed). It is the CAS
   * precondition of that admission's later pre-effect claim.
   */
  async readAdmissionFenceRevision(target) {
    const doc = await this.#docs.get(this.#docKeys.admissionFence(target));
    return doc === null ? null : doc.revision;
  }

  /**
   * [v0.8.1 R02] Pre-effect claim of the admission fence at the snapshot's
   * fence revision, then a fresh check that the instance is still at the
   * snapshot stateRevision. Either failing is a stale admission and refuses
   * typed (ADMISSION_STATE_CAS_CONFLICT) before any journal/effect activity.
   *
   * [#1108 K01] The claim is also REFUSED when the fence document is still
   * held by ANOTHER turn at the SAME stateRevision: that holder is an
   * in-flight (or crashed, not yet reconciled) protected admission whose
   * non-idempotent effects may already be dispatched, and admitCentralDecision
   * commits only later, at #requireHeldAdmissionFence — a rival that
   * CAS-overwrote such a fence here would make the holder lose AFTER its
   * external dispatch (duplicated non-idempotent effect + orphaned
   * unaccounted dispatch). Only a strictly OLDER held fence (its holder
   * committed, so the instance advanced past that revision — a snapshot at a
   * higher stateRevision cannot exist otherwise) is superseded by the revision
   * CAS below, and the SAME turn re-claiming its own fence is the crash
   * recovery replay path. There is no expiry lease: a crashed holder's fence
   * stays held and rivals keep refusing typed until durable reconciliation
   * (same-turn replay through the effect journal, or the zero-ambiguity
   * release path in admitCentralDecision).
   */
  async claimAdmissionFence(request) {
    const { target, turnId, expectedTargetSequence, snapshotFenceRevision } = request;
    const held = await this.#docs.get(this.#docKeys.admissionFence(target));
    // R01-RACE-01 #1205: same canonical turn may attach to its existing
    // fence, NEVER CAS-replacing a live claimant's revision after dispatch.
    if (held !== null && isJsonRecord(held.value)
      && held.value.turnId === turnId && held.value.stateRevision === expectedTargetSequence) {
      if (!Number.isSafeInteger(held.revision)
        || typeof request.turnIdentity !== 'string'
        || held.value.turnIdentity !== request.turnIdentity) {
        throw admissionStateCasConflict('same-turn held fence does not match canonical intent/input identity');
      }
      const current = await this.#instances.require(target);
      if (current.stateRevision !== expectedTargetSequence) {
        throw admissionStateCasConflict('same-turn fence stateRevision changed');
      }
      const recheck = await this.#docs.get(this.#docKeys.admissionFence(target));
      if (recheck === null || !isJsonRecord(recheck.value)
        || recheck.revision !== held.revision || recheck.value.turnId !== turnId
        || recheck.value.turnIdentity !== request.turnIdentity
        || recheck.value.stateRevision !== expectedTargetSequence) {
        throw admissionStateCasConflict('same-turn fence changed during read-only attachment');
      }
      return { turnId, stateRevision: expectedTargetSequence, revision: held.revision };
    }
    if (held !== null && isJsonRecord(held.value)
      && typeof held.value.turnId === 'string'
      && held.value.turnId !== turnId
      && held.value.stateRevision === expectedTargetSequence) {
      // [#1108 K01 R1] Trusted-seam reconciliation supersede: a turn source of
      // kind `recovery` (constructed ONLY by the trusted Host's operator-
      // credentialed, durably CAS-delivered poison-recovery flow) may take the
      // fence of a holder whose EVERY begun effect is durably `failed` — the
      // operator-authorized corrective action IS the durable reconciliation of
      // the failed turn's uncertain external outcome. A holder with any
      // non-failed (or zero) journal records stays protected: in-flight and
      // dispatched turns are never displaced, only terminally-failed ones are
      // reconciled. The revision CAS below still arbitrates the takeover.
      const reconciles = request.reconcilesHeldFence === true
        && await this.#heldFenceIsDurablyFailed(target, held.value.turnId);
      if (!reconciles) {
        throw admissionStateCasConflict(
          `instance ${target.workflowId}/${target.instanceKey} at stateRevision ${expectedTargetSequence} has an admission fence still held by turn ${held.value.turnId}; the competing claim of turn ${turnId} is refused before any journal or effect activity (fail-closed until the holder commits or is reconciled)`,
        );
      }
    }
    let written;
    try {
      written = await this.#docs.put(
        this.#docKeys.admissionFence(target),
        { pinVersion: 1, stateRevision: expectedTargetSequence, turnId, turnIdentity: request.turnIdentity, claimedAt: this.#now() },
        snapshotFenceRevision === null ? { mustBeAbsent: true } : { mustMatchRevision: snapshotFenceRevision },
      );
    } catch (error) {
      if (isHostWriteConflict(error)) {
        throw admissionStateCasConflict(
          `another admission claimed instance ${target.workflowId}/${target.instanceKey} after this admission's snapshot at stateRevision ${expectedTargetSequence}; the stale admission is refused before any journal or effect activity`,
        );
      }
      throw error;
    }
    const current = await this.#instances.require(target);
    if (current.stateRevision !== expectedTargetSequence) {
      throw admissionStateCasConflict(
        `instance ${target.workflowId}/${target.instanceKey} is at stateRevision ${current.stateRevision}; the admission was evaluated against ${expectedTargetSequence} and is refused before any journal or effect activity`,
      );
    }
    return {
      turnId,
      stateRevision: expectedTargetSequence,
      ...(Number.isSafeInteger(written?.revision) ? { revision: written.revision } : {}),
    };
  }

  /**
   * [#1108 K01 R1] Reconciliation gate for claimAdmissionFence: is the given
   * held turn terminally failed — EVERY begun effect of that turn is durably
   * `failed`, and at least one exists? A zero-record holder is NOT terminal
   * (it may still be in-flight pre-journal); any `started`/`completed` record
   * or an unreadable journal refuses (fail-closed).
   */
  async #heldFenceIsDurablyFailed(target, heldTurnId) {
    try {
      const keys = await this.#docs.list(this.#docKeys.journal(`${heldTurnId}/effect/`));
      if (keys.length === 0) return false;
      for (const key of keys) {
        const doc = await this.#docs.get(key);
        const status = isJsonRecord(doc?.value) && isJsonRecord(doc.value.record)
          ? doc.value.record.status
          : undefined;
        if (status !== 'failed') return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * [#1108 K01] Conditional release of a held admission fence by its own
   * claimant, used ONLY on the zero-ambiguity effect-failure path (every begun
   * effect of the turn is durably `failed`; none is `started`/`completed` —
   * see admitCentralDecision). Keeps a transiently failed turn from
   * permanently wedging the instance at its stateRevision now that
   * same-revision takeover is refused. The remove is a CAS on the exact claim
   * revision; a fence without a safe-integer claim revision is never released
   * (an unconditional fence write does not exist). A failed removal leaves the
   * fence held — fail-closed; the caller reports the original typed error.
   */
  async releaseAdmissionFence(target, fence) {
    if (!Number.isSafeInteger(fence.revision)) return;
    await this.#docs.remove(this.#docKeys.admissionFence(target), { mustMatchRevision: fence.revision });
  }

  async #requireHeldAdmissionFence(target, fence) {
    const doc = await this.#docs.get(this.#docKeys.admissionFence(target));
    const held = doc !== null && isJsonRecord(doc.value)
      && doc.value.turnId === fence.turnId
      && doc.value.stateRevision === fence.stateRevision
      && (fence.revision === undefined || doc.revision === fence.revision);
    if (!held) {
      throw admissionStateCasConflict(
        `the admission fence of instance ${target.workflowId}/${target.instanceKey} at stateRevision ${fence.stateRevision} is no longer held by turn ${fence.turnId}`,
      );
    }
  }

  /**
   * [KPK-01 adaptation] Same v0.7 commit body, for a caller that ALREADY
   * holds this instance's serialized lane (the kernel occurrence runtime
   * serializes its whole admission+commit occurrence on the same lane, like
   * the v0.7 control-turn publication did around its engine).
   *
   * [#1066 R1 P1-B] When the caller carries `admittedControlTurn` (any
   * durable turn — [v0.8.1 R01] message turns included), its identity is appended to the
   * bounded `admittedControlTurns` history INSIDE this same authoritative
   * state-CAS write — the turn admission becomes part of the committed
   * instance truth itself, so a crash between this CAS and the independent
   * turn-disposition/marker observations still leaves a durable,
   * authoritative record that the turn was already admitted exactly once.
   */
  async commitAcceptedTransitionInLane(request) {
    const current = await this.#instances.require(request.target);
    // [v0.8.1 R02] The v0.7 expectedTargetSequence fence: the commit lands
    // ONLY on the exact revision the admission was evaluated against — never
    // on a fresh re-read, which would let a stale admission from another
    // runtime overwrite a committed (even FINAL) state.
    const expectedTargetSequence = request.expectedTargetSequence ?? current.stateRevision;
    if (current.stateRevision !== expectedTargetSequence) {
      throw admissionStateCasConflict(
        `instance ${request.target.workflowId}/${request.target.instanceKey} is at stateRevision ${current.stateRevision}; the admission was evaluated against ${expectedTargetSequence}`,
      );
    }
    if (request.admissionFence !== undefined) {
      await this.#requireHeldAdmissionFence(request.target, request.admissionFence);
    }
    const transition = await request.transition(current);
    const updatedAt = this.#now();
    if (this.#counters !== undefined) this.#counters.engineCommits += 1;
    const admittedControlTurns = request.admittedControlTurn === undefined
      ? current.admittedControlTurns
      : [
          ...(Array.isArray(current.admittedControlTurns) ? current.admittedControlTurns : [])
            .filter((entry) => !isJsonRecord(entry) || entry.turnId !== request.admittedControlTurn.turnId),
          {
            turnId: request.admittedControlTurn.turnId,
            identity: request.admittedControlTurn.identity,
            stateRevision: current.stateRevision + 1,
            admittedAt: updatedAt,
          },
        ].slice(-MAX_ADMITTED_CONTROL_TURN_HISTORY);

    // [#1063 HF20] The MUTATION_COMMITTED observation record is computed by
    // the pure reducer INSIDE this same transition body and rides the SAME
    // single-key CAS value below — one physical row write makes the record
    // and the new stateRevision durable together or not at all. A losing
    // writer takes HOST_CAS_CONFLICT from the put BEFORE any durable effect,
    // so a lost/uncommitted turn never yields an observation.
    const mutationObservations = appendHf20MutationObservation(
      current.mutationObservations,
      {
        kind: 'MUTATION_COMMITTED',
        stateRevisionBefore: current.stateRevision,
        stateRevisionAfter: current.stateRevision + 1,
        sourceMessageId: request.messageId,
      },
      updatedAt,
    ).window;

    // [v0.10 K02 anchor 2] The NEXT document value is composed FIRST so the
    // immutable ORIGINAL RECEIPT of the admitted turn can be built against
    // this exact next projection BEFORE the put — the state move, the
    // revision and the original receipt are ONE physical row write: durable
    // together or not at all. The K01 fence precondition above stays first.
    const nextValue = {
      address: current.address,
      correlationId: current.correlationId,
      packageId: current.packageId,
      lifecycle: transition.nextLifecycle ?? current.lifecycle,
      stateRevision: current.stateRevision + 1,
      state: transition.nextState,
      ...(transition.output === undefined ? {} : { output: transition.output }),
      ...(current.output === undefined || transition.output !== undefined ? {} : { output: current.output }),
      lastMessageId: request.messageId,
      createdAt: current.createdAt,
      updatedAt,
      mutationObservations,
      ...(admittedControlTurns === undefined || admittedControlTurns.length === 0 ? {} : { admittedControlTurns }),
    };
    const durableOriginalReceipts = await this.#nextDurableOriginalReceipts(
      current,
      nextValue,
      request.durableOriginalReceipt,
      updatedAt,
    );
    try {
      await this.#docs.put(this.#docKeys.instance(request.target), {
        ...nextValue,
        ...(durableOriginalReceipts === undefined ? {} : { durableOriginalReceipts }),
      }, { mustMatchRevision: expectedTargetSequence });
    } catch (error) {
      if (isHostWriteConflict(error)) {
        throw admissionStateCasConflict(
          `instance ${request.target.workflowId}/${request.target.instanceKey} moved past stateRevision ${expectedTargetSequence} before this commit`,
        );
      }
      throw error;
    }

    const committed = await this.#instances.require(request.target);
    if (!workflowAddressesEqual(committed.address, current.address)) {
      throw new Error('RuntimeStore changed WorkflowAddress while committing an instance transition');
    }
    if (committed.packageId !== current.packageId || committed.correlationId !== current.correlationId) {
      throw new Error('RuntimeStore changed persistent Workflow Instance identity while committing a transition');
    }
    if (committed.stateRevision !== current.stateRevision + 1) {
      throw new Error(
        `RuntimeStore committed invalid stateRevision ${committed.stateRevision}; expected ${current.stateRevision + 1}`,
      );
    }

    return committed;
  }

  /**
   * [v0.10 K02 anchors 2+4] The append-only `durableOriginalReceipts` map of
   * the NEXT document: the current map of the SAME snapshot the CAS is bound
   * to, with the admitted turn's immutable original-receipt envelope appended
   * and the ring bounded by ARCHIVE-GATED eviction — the oldest entry leaves
   * only once its independent durable archive record exists. On an
   * archive-write fault the entry STAYS and the document temporarily grows
   * past the bound: admission NEVER blocks, and an admitted turn is never
   * silently forgotten while the ring or its durable archive retains it. An
   * existing entry under this turnId refuses typed — the map is append-only,
   * never rewritten, whatever the identity.
   */
  async #nextDurableOriginalReceipts(current, nextValue, descriptor, attributedAt) {
    const existing = isJsonRecord(current.durableOriginalReceipts) ? current.durableOriginalReceipts : {};
    if (descriptor === undefined) {
      return Object.keys(existing).length === 0 ? undefined : snapshotJson(existing);
    }
    if (!isJsonRecord(descriptor) || typeof descriptor.turnId !== 'string' || typeof descriptor.identity !== 'string') {
      throw new CentralAdmissionError(
        'K02_SCOPE_INVALID',
        'a durable original-receipt descriptor requires { turnId, identity, intentType, inputDigest, turn, messageId }',
      );
    }
    if (existing[descriptor.turnId] !== undefined) {
      throw new CentralAdmissionError(
        'K02_TURN_RECEIPT_INPUT_CONFLICT',
        `turn ${descriptor.turnId} is already durably admitted in the same-CAS original-receipt ring; one source is exactly one turn and the ring is append-only`,
      );
    }
    const envelope = {
      carrierVersion: 1,
      identity: descriptor.identity,
      intentType: descriptor.intentType,
      turn: descriptor.turn,
      ...(descriptor.buildIdentity === undefined ? {} : { buildIdentity: descriptor.buildIdentity }),
      receipt: {
        status: 'admitted',
        turnId: descriptor.turnId,
        intentType: descriptor.intentType,
        inputDigest: descriptor.inputDigest,
        ...(descriptor.admitted === undefined ? {} : { admitted: snapshotJson(descriptor.admitted) }),
        // The receipt's instance projection is the OUTWARD next projection
        // this very CAS commits — the ACK bytes acknowledge exactly what this
        // write makes durable.
        instance: outwardInstanceSnapshot(nextValue),
        occurrence: { messageId: descriptor.messageId },
        attributedAt,
      },
    };
    const receipts = { ...existing, [descriptor.turnId]: envelope };
    let keys = Object.keys(receipts);
    while (keys.length > this.#durableReceiptRingBound) {
      const oldestKey = keys[0];
      const archived = await this.#ensureDurableReceiptArchived(oldestKey, receipts[oldestKey]);
      if (!archived) {
        if (this.#counters !== undefined) this.#counters.durableRingGrowthEvents += 1;
        break; // fault-tolerant growth: keep the entry; the next admission retries the archive
      }
      delete receipts[oldestKey];
      keys = Object.keys(receipts);
    }
    return receipts;
  }

  /**
   * [v0.10 K02 anchor 4] The eviction-time durable archive write of ONE ring
   * entry (mustBeAbsent). A KEY_EXISTS whose stored identity matches counts
   * as archived (an earlier best-effort copy or eviction wrote it); a
   * different identity is an honest typed anomaly; any other fault KEEPS the
   * ring entry (returns false — fault-tolerant growth, admission proceeds).
   */
  async #ensureDurableReceiptArchived(turnId, envelope) {
    try {
      await this.#docs.put(this.#docKeys.receiptArchive(turnId), envelope, { mustBeAbsent: true });
      if (this.#counters !== undefined) this.#counters.durableReceiptArchiveWrites += 1;
      return true;
    } catch (error) {
      if (typeof error === 'object' && error !== null && error.code === 'HOST_KEY_EXISTS') {
        try {
          const existing = await this.#docs.get(this.#docKeys.receiptArchive(turnId));
          if (existing !== null && isJsonRecord(existing.value) && existing.value.identity === envelope.identity) {
            return true;
          }
        } catch {
          if (this.#counters !== undefined) this.#counters.durableReceiptArchiveFailures += 1;
          return false;
        }
        throw new CentralAdmissionError(
          'K02_TURN_RECEIPT_STORE_FAULT',
          `the original-receipt archive of turn ${turnId} holds a different identity; honest anomaly — fail closed`,
        );
      }
      if (this.#counters !== undefined) this.#counters.durableReceiptArchiveFailures += 1;
      return false; // fault-tolerant growth: keep the ring entry
    }
  }
}

// ===========================================================================
// [KPK-01 experiment, kernel-owned] Governance pin store over the Host doc
// port. Mirrors the T-014 semantics consumed by v0.7 admission: EVERY
// authoritative admission re-requires the exact durable pin; a missing pin
// fails typed. The pin binds the instance to the exact baseline identity AND
// the exact loaded kernel module bytes (digest), so a replaced Kernel Package
// can never silently ride an occurrence pinned to its predecessor.
// ===========================================================================

export class GovernanceExecutionBindingError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'GovernanceExecutionBindingError';
    this.code = code;
  }
}

function pinDocKey(workflowInstanceId) {
  return `v08-kernel:governance-pin:${workflowInstanceId}`;
}

// ===========================================================================
// [#1006 HF21] Selected K SIM/PROD effect authority separation. The runtime
// authority class is an EXPLICIT activation-plane fact bound at instance
// Genesis (the v0.7 T002D #655/#688 semantic reference ported to the selected
// physical K/S/B path): the SAME sealed closure may back PRODUCTION and
// SIMULATION instances, no Definition/policy identity ever implies a class,
// and the class is woven into the ONE existing KernelGovernancePinStore
// bindingDigest — never a second pin/currentness plane, never a parallel
// authority registry, never a GitHub execution-identity check. Only an exact
// PRODUCTION pin can mint authoritative production Effect/Journal: a
// SIMULATION pin — and EQUALLY a classless pin (the historical compatibility
// boundary below) — can never mint one and refuses typed before any
// production Effect/Journal; a forged or substituted class fails typed before
// any production Effect/Journal; the
// class persists across CAS/restart/replay because the pin doc is the same
// physical durable record. Pins activated without a class keep the exact
// legacy (pre-HF21) digest material — the historical classless compatibility
// boundary — and can never be newly minted, upgraded or downgraded through
// this seam (bind-once conflict discipline below).
// ===========================================================================

const PRODUCTION_AUTHORITY_CLASS = 'PRODUCTION';
const SIMULATION_AUTHORITY_CLASS = 'SIMULATION';

/**
 * [#1006 HF21] The class is exactly `PRODUCTION` or `SIMULATION` — never a
 * floating selector, alias, derived/implicit value or a third class. Anything
 * else fails typed AUTHORITY_CLASS_FORBIDDEN before any durable pin write.
 */
export function requireRuntimeAuthorityClass(value, field) {
  if (value !== PRODUCTION_AUTHORITY_CLASS && value !== SIMULATION_AUTHORITY_CLASS) {
    throw new GovernanceExecutionBindingError(
      'AUTHORITY_CLASS_FORBIDDEN',
      `${field} must be exactly 'PRODUCTION' or 'SIMULATION'; ${JSON.stringify(value)} is forbidden`,
    );
  }
  return value;
}

// ===========================================================================
// [#1003 NF06] K-owned decision-receipt records (OBSERVATIONAL_OPTIONAL).
// One durable data-only record per EXACT durable control turn, created
// through the Host true-CAS port (mustBeAbsent — create-or-conflict, never
// an unconditional write). The record NEVER carries admission authority:
// the admitted State, Effect journal and instance CAS remain the only
// authority; a lost/failed/conflicting record is reported as a separate
// typed observation outcome and can never rewrite the business truth.
// ===========================================================================

function decisionReceiptDocKey(turnId) {
  return `v08-kernel:decision-receipt:${turnId}`;
}

// ===========================================================================
// [#1062 HF18/HF32 shared seam] K-owned turn dispositions for durable
// control turns (timer/callback/child-terminal) and — [v0.8.1 R01] restoring
// the v0.2–v0.7 FR04 (target, messageId) dedup that the v0.8 port dropped —
// message turns (the turn id derives from the messageId). One admitted turn
// creates exactly one record at the deterministic turn-id key; a replay of
// the SAME source (redelivery, restart recovery, heal-after-crash) reads it
// inside the occurrence lane and replays the stored receipt with ZERO new
// State/Journal/Effect activity. A record under the same turn id carrying a
// DIFFERENT identity (e.g. the same source re-submitted under another
// intentType) refuses typed before admission — one source is exactly one
// turn. The record is written AFTER the authoritative state CAS as a
// separate best-effort observation (same honest discipline as the NF06
// decision receipt): the v0.8 Host true-CAS store has no cross-document
// atomic batch, so a crash between the state commit and this create leaves
// an honest not_recorded window that the physical negative witnesses —
// atomicity is never claimed.
// ===========================================================================

function turnDispositionDocKey(turnId) {
  return `v08-kernel:turn-disposition:${turnId}`;
}

/**
 * [#1066 R1 P1-B] The bounded same-CAS admission history bound: the last
 * 16 turn admissions (message turns included since v0.8.1 R01) ride inside
 * the instance document. The
 * history is the crash-window backstop for a LOST turn-disposition record
 * (written best-effort after the state CAS). Before evicting the oldest of
 * 16 entries K must verify its independent disposition exists with the
 * exact identity; otherwise new control turns FAIL CLOSED until the old
 * source is recovered and its missing disposition healed. Thus a delayed
 * recovery cannot silently pass beyond the bounded crash backstop.
 */
const MAX_ADMITTED_CONTROL_TURN_HISTORY = 16;

/**
 * [v0.10 K02] The bounded in-document original-receipt ring: 4x the frozen
 * 16-entry history bound, covering the 17+ once-only acceptance with margin.
 * MAX_ADMITTED_CONTROL_TURN_HISTORY stays the kernel's crash-backstop
 * history bound; the ring is the same-CAS once-only truth whose eviction is
 * archive-gated (never admission-blocking).
 */
const K02_DURABLE_RECEIPT_RING_BOUND_DEFAULT = 64;

/**
 * [v0.10 K02 anchor 1] The turn receipt identity is INPUT-COMPLETE and
 * DEPLOYMENT-SCOPED: canonical JSON of {deploymentScope?, target, turn,
 * intentType, inputDigest} where inputDigest = sha256(canonicalJson(input)).
 * An identical retry yields the identical identity (replay); a changed
 * canonical input or a changed intentType yields a different identity (typed
 * conflict). The pinned build identity (kernel module SHA) is deliberately
 * OUTSIDE the identity — it rides the envelope as `buildIdentity` — so the
 * target identity is stable across releases while the build switch stays
 * observable. A runtime wired WITHOUT a deployment scope (the compatibility
 * mode) omits the member entirely; the scope, when wired, is validated
 * bounded-identifier material.
 */
function turnDispositionIdentity(deploymentScope, target, turn, intentType, inputDigest) {
  return canonicalJsonStringify({
    ...(deploymentScope === undefined ? {} : {
      deploymentScope: {
        deployedAppId: deploymentScope.deployedAppId,
        tenantId: deploymentScope.tenantId,
        appId: deploymentScope.appId,
        businessPackageId: deploymentScope.businessPackageId,
      },
    }),
    target: { workflowId: target.workflowId, instanceKey: target.instanceKey },
    turn,
    intentType,
    inputDigest,
  });
}

/**
 * Receipt identity for idempotent-replay adjudication: the kernel module
 * bytes, the turn's occurrence identity and the redacted projected record —
 * everything EXCEPT the volatile recordedAt timestamp, so a crash-restart
 * replay of the same admitted turn recognizes its own record instead of
 * conflicting.
 */
function decisionReceiptIdentity(envelope) {
  const record = isJsonRecord(envelope) && isJsonRecord(envelope.record) ? envelope.record : {};
  const { recordedAt: _recordedAt, ...identity } = record;
  return canonicalJsonStringify({ kernelModuleSha256: envelope.kernelModuleSha256, record: identity });
}

const RECEIPT_DURABILITY_MODES = new Set(['observational-optional', 'durable-mandatory']);

/**
 * [#1003 NF06] Trusted load-boundary wiring of every intent-declared
 * `receiptPolicy`: shape-validated and frozen HERE, before any instance can
 * exist (same discipline as the effect/continuation/semantic wiring). A
 * malformed policy fails the load typed; a valid one is the ONLY receipt
 * authority the submit lane trusts at occurrence time.
 */
function wireDecisionReceiptPolicies(businessEndpoint) {
  const policies = new Map();
  const bindings = businessEndpoint.intentBindings ?? {};
  for (const [intentType, binding] of Object.entries(bindings)) {
    if (!isJsonRecord(binding) || !hasOwn(binding, 'receiptPolicy')) continue;
    const rawPolicy = binding.receiptPolicy;
    if (!isJsonRecord(rawPolicy)) {
      throw new CentralAdmissionError(
        'BUSINESS_RECEIPT_POLICY_INVALID',
        `intent ${intentType} declares a receiptPolicy that is not an object`,
      );
    }
    const durability = rawPolicy.durability;
    if (typeof durability !== 'string' || !RECEIPT_DURABILITY_MODES.has(durability)) {
      throw new CentralAdmissionError(
        'BUSINESS_RECEIPT_POLICY_INVALID',
        `intent ${intentType} declares receiptPolicy.durability ${JSON.stringify(durability)}; exactly 'observational-optional' or 'durable-mandatory' is accepted`,
      );
    }
    let readerRoles;
    if (rawPolicy.readerRoles !== undefined) {
      if (!Array.isArray(rawPolicy.readerRoles)
        || rawPolicy.readerRoles.length === 0
        || rawPolicy.readerRoles.length > 64
        || !rawPolicy.readerRoles.every((role) => typeof role === 'string' && role.length > 0)) {
        throw new CentralAdmissionError(
          'BUSINESS_RECEIPT_POLICY_INVALID',
          `intent ${intentType} declares receiptPolicy.readerRoles that is not a bounded non-empty list of roles`,
        );
      }
      readerRoles = [...new Set(rawPolicy.readerRoles)];
    } else if (durability === 'observational-optional') {
      throw new CentralAdmissionError(
        'BUSINESS_RECEIPT_POLICY_INVALID',
        `intent ${intentType} declares an observational-optional receiptPolicy without readerRoles; a readable observation must declare who may read it`,
      );
    }
    policies.set(intentType, Object.freeze({
      durability,
      ...(readerRoles === undefined ? {} : { readerRoles: Object.freeze(readerRoles) }),
    }));
  }
  return policies;
}

export class KernelGovernancePinStore {
  #docs;
  #sha256;
  #moduleSha256;

  constructor(docs, sha256, moduleSha256) {
    this.#docs = docs;
    this.#sha256 = sha256;
    this.#moduleSha256 = moduleSha256;
  }

  /**
   * [#1006 HF21] The ONE binding-digest material: the exact pre-HF21 tuple,
   * plus the runtime authority class IFF the activation supplied one. A
   * classless activation keeps the byte-identical legacy material; a
   * class-bearing activation can never be re-forged into another class (or
   * stripped to classless) without changing this digest.
   */
  async #computeBindingDigest(workflowInstanceId, governanceBaseline, authorityClass) {
    return computeCanonicalJsonDigest(
      {
        workflowInstanceId,
        governanceBaseline: governanceBaselineKey(governanceBaseline),
        kernelModuleSha256: this.#moduleSha256,
        ...(authorityClass === undefined ? {} : { authorityClass }),
      },
      this.#sha256,
    );
  }

  async bindPin({ workflowInstanceId, governanceBaseline, authorityClass }) {
    assertGovernanceBaselineIdentity(governanceBaseline);
    if (authorityClass !== undefined) {
      requireRuntimeAuthorityClass(authorityClass, 'authorityClass');
    }
    const bindingDigest = await this.#computeBindingDigest(workflowInstanceId, governanceBaseline, authorityClass);
    const pin = {
      workflowInstanceId,
      governanceBaseline,
      bindingDigest,
      kernelModuleSha256: this.#moduleSha256,
      ...(authorityClass === undefined ? {} : { authorityClass }),
    };
    const existing = await this.#docs.get(pinDocKey(workflowInstanceId));
    if (existing !== null) {
      if (canonicalJsonStringify(existing.value) !== canonicalJsonStringify(pin)) {
        throw new GovernanceExecutionBindingError(
          'GOVERNANCE_EXECUTION_PIN_CONFLICT',
          `workflow instance ${workflowInstanceId} is already bound to different execution authority`,
        );
      }
      return pin;
    }
    await this.#docs.put(pinDocKey(workflowInstanceId), pin, { mustBeAbsent: true });
    return this.requirePinnedExecution(workflowInstanceId);
  }

  async requirePinnedExecution(workflowInstanceId) {
    const doc = await this.#docs.get(pinDocKey(workflowInstanceId));
    if (doc === null) {
      throw new GovernanceExecutionBindingError(
        'GOVERNANCE_EXECUTION_PIN_MISSING',
        `workflow instance ${workflowInstanceId} has no durable GovernanceExecutionPin`,
      );
    }
    const pin = doc.value;
    if (pin.kernelModuleSha256 !== this.#moduleSha256) {
      throw new GovernanceExecutionBindingError(
        'GOVERNANCE_EXECUTION_PIN_CONFLICT',
        `workflow instance ${workflowInstanceId} is pinned to kernel module ${pin.kernelModuleSha256} which is unavailable under the loaded kernel module ${this.#moduleSha256}; typed code unavailability — no silent cross-version replay`,
      );
    }
    // [#1006 HF21] Re-prove the stored authority tuple: the bindingDigest is
    // recomputed from the stored fields (class included when present) and any
    // divergence — a re-forged/substituted/stripped authority class above all
    // — refuses typed here, BEFORE any admission that could mint production
    // Effect/Journal. Durable store data is untrusted authority material.
    if (pin.authorityClass !== undefined) {
      requireRuntimeAuthorityClass(pin.authorityClass, 'pin.authorityClass');
    }
    const expectedDigest = await this.#computeBindingDigest(
      pin.workflowInstanceId,
      pin.governanceBaseline,
      pin.authorityClass,
    );
    if (pin.bindingDigest !== expectedDigest) {
      throw new GovernanceExecutionBindingError(
        'AUTHORITY_CLASS_MISMATCH',
        `workflow instance ${workflowInstanceId} carries a GovernanceExecutionPin whose bindingDigest does not match its stored authority tuple; re-forged execution authority refuses typed`,
      );
    }
    return pin;
  }

  /**
   * [#1006 HF21, R2 #1089] The production Effect/Journal authority gate (the
   * selected-K port of the v0.7 T002D `requireProductionEffectAuthority`
   * semantic), FAIL-CLOSED on the exact class: only a durable pin carrying the
   * exact PRODUCTION authority class can mint an authoritative production
   * Effect, Journal record or publication. A SIMULATION-class occurrence can
   * still observe and execute simulation semantics, but refuses production
   * effect authority typed here; a CLASSLESS pin (the pre-HF21 historical
   * compatibility boundary — including a fresh activation registered without
   * a declared class) is NOT production authority either and refuses typed the
   * same way, BEFORE any journal write or effect dispatch, with zero physical
   * Effect. Nothing implicit, historical or absent can ever be substituted for
   * the explicit PRODUCTION declaration; a classless pin also can never be
   * re-bound with a class (bind-once conflict) and remains a reported
   * product-disposition gap, never an authority.
   */
  async requireProductionEffectAuthority(workflowInstanceId) {
    const pin = await this.requirePinnedExecution(workflowInstanceId);
    if (pin.authorityClass !== PRODUCTION_AUTHORITY_CLASS) {
      throw new GovernanceExecutionBindingError(
        'AUTHORITY_CLASS_MISMATCH',
        `workflow instance ${workflowInstanceId} carries the ${JSON.stringify(pin.authorityClass ?? null)} runtime authority class; only an exact PRODUCTION-class pin can mint authoritative production Effect, Journal or publication — a SIMULATION or classless pin can never be substituted`,
      );
    }
    return pin;
  }
}

/** Kernel-owned baseline body registry over the Host doc port (immutable per digest key). */
export class KernelBaselineStore {
  #docs;

  constructor(docs) {
    this.#docs = docs;
  }

  static docKey(identity) {
    return `v08-kernel:baseline:${governanceBaselineKey(identity)}`;
  }

  async putBody(body) {
    const key = KernelBaselineStore.docKey(body.identity);
    const existing = await this.#docs.get(key);
    if (existing !== null) {
      if (canonicalJsonStringify(existing.value) !== canonicalJsonStringify(body)) {
        throw new GovernanceContractError(
          'GOVERNANCE_BODY_CONFLICT',
          'logical store rejected mutation under an existing Governance Baseline digest',
        );
      }
      return;
    }
    await this.#docs.put(key, body, { mustBeAbsent: true });
  }

  async getBody(identity) {
    const doc = await this.#docs.get(KernelBaselineStore.docKey(identity));
    return doc === null ? undefined : doc.value;
  }
}

// ===========================================================================
// [#1003 FR07-KH2 — kernel-owned NEW mechanism code, NOT a v0.7 migration]
// Bounded model continuation, trusted model-call accounting and the
// request-scoped cancellation latch.
//
// Contract: #1003@6122627750 (§4 K owns the loop) + review #1003@6130723310
// B2/B3/B4. The v0.7 harness-machine.ts@86110c6 (blob f2fe5d49) SEMANTICS are
// retained — query allowlist + explicit mutation denial, maxSteps guard,
// query observation + dependency capture/dedupe, ordinary query failure as a
// structured {ok:false,error} observation with bounded recovery, invalid
// query output fail-closed, exact final validation, cooperative cancellation
// — without its XState runtime and WITHOUT any Host/Business `execute()`
// callback: the only query executor is the K-owned read below.
//
//   - A sealed `model-decision` rule carrying a data-only `harness` policy
//     selects the continuation. The policy is validated ONCE at wiring
//     (createOccurrenceRuntime — the trusted load boundary) and deep-frozen
//     into a WeakMap keyed by the exact rule object; live mutation after
//     wiring is ignored and an unwired harness rule refuses typed.
//   - K owns every turn: before each S `invokeStep` call (recovery turns
//     included) the K budget is checked against the sealed `maxSteps`,
//     itself bounded by the immutable K ceiling MAX_FR07_STEPS. A query
//     never resets the budget and there are no hidden retries.
//   - A query envelope is a PROPOSAL: K authorizes the capability against
//     the wired policy (unknown ⇒ UNKNOWN_CAPABILITY, mutation ⇒
//     MUTATION_CAPABILITY_FORBIDDEN, both before any read) and executes the
//     only read kind that exists — a projection of the K-attested instance
//     context re-read through the Host document port at exactly the lane's
//     stateRevision. Nothing on this path writes.
//   - Model-call evidence: K accepts per-step evidence only in the exact
//     trusted shape the Host-bound resolver mints (`measured` count 1 per
//     physical turn, or `unmeasured`) and aggregates it; the legacy numeric
//     `freshModelCallCount` is not read anywhere on the selected path.
//   - Cancellation: a request-scoped signal from the H-authenticated gateway
//     flips a K latch. K checks it before and after every awaited model turn
//     and read and closes it immediately before central admission; once
//     admission has begun a late cancel can no longer split the occurrence.
//   - Only a final envelope (outcome/event allowlisted) reaches
//     admitCentralDecision; every terminal before it leaves zero State,
//     Journal and Effect.
// ===========================================================================

/** Immutable K-owned absolute ceiling on model turns per occurrence (B4). */
export const MAX_FR07_STEPS = 8;

const CONTINUATION_IDENTIFIER = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const CONTINUATION_MAX_CAPABILITIES = 32;
const CONTINUATION_MAX_FIELDS = 32;
const CONTINUATION_MAX_ALLOWED = 64;
const CONTINUATION_HARNESS_KEYS = new Set(['maxSteps', 'capabilities', 'allowedOutcomes', 'allowedEvents']);
const CONTINUATION_READ_KEYS = new Set(['mode', 'source', 'fields', 'outputSchema']);
const CONTINUATION_SCHEMA_TYPES = new Set(['string', 'number', 'boolean', 'object', 'array', 'null']);
const BOUND_PORT_EVIDENCE_SCOPE = 'bound-model-port-invocations';

function invalidContinuation(message) {
  throw new CentralAdmissionError('CONTINUATION_DECLARATION_INVALID', message);
}

function isJsonRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function jsonTypeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function continuationIdentifier(value, label) {
  if (typeof value !== 'string' || !CONTINUATION_IDENTIFIER.test(value)) {
    invalidContinuation(`${label} must be a bounded identifier`);
  }
  return value;
}

function continuationIdentifierList(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > CONTINUATION_MAX_ALLOWED) {
    invalidContinuation(`${label} must be a non-empty bounded identifier list`);
  }
  const seen = new Set();
  for (const item of value) {
    continuationIdentifier(item, label);
    if (seen.has(item)) invalidContinuation(`${label} contains the duplicate ${item}`);
    seen.add(item);
  }
  return [...value];
}

function snapshotReadDescriptor(descriptor, label) {
  for (const key of Object.keys(descriptor)) {
    if (!CONTINUATION_READ_KEYS.has(key)) invalidContinuation(`${label} carries the unsupported key ${key}`);
  }
  if (descriptor.source !== 'instance-context') {
    invalidContinuation(`${label}.source must be 'instance-context' (the only K-owned read kind)`);
  }
  const fieldEntries = isJsonRecord(descriptor.fields) ? Object.entries(descriptor.fields) : [];
  if (fieldEntries.length === 0 || fieldEntries.length > CONTINUATION_MAX_FIELDS) {
    invalidContinuation(`${label}.fields must map 1..${CONTINUATION_MAX_FIELDS} output names to context keys`);
  }
  const fields = {};
  for (const [outputName, contextKey] of fieldEntries) {
    continuationIdentifier(outputName, `${label}.fields output name`);
    fields[outputName] = continuationIdentifier(contextKey, `${label}.fields.${outputName}`);
  }
  const outputSchema = {};
  if (hasOwn(descriptor, 'outputSchema')) {
    if (!isJsonRecord(descriptor.outputSchema)) invalidContinuation(`${label}.outputSchema must be an object`);
    for (const [outputName, type] of Object.entries(descriptor.outputSchema)) {
      if (!hasOwn(fields, outputName)) invalidContinuation(`${label}.outputSchema names the undeclared field ${outputName}`);
      if (!CONTINUATION_SCHEMA_TYPES.has(type)) invalidContinuation(`${label}.outputSchema.${outputName} has the unsupported type ${String(type)}`);
      outputSchema[outputName] = type;
    }
  }
  return { mode: 'read', source: 'instance-context', fields, outputSchema };
}

/**
 * Validate and snapshot ONE harness policy (trusted wiring boundary). The
 * budget is checked against the K ceiling before anything else, so a
 * non-finite/non-integer/out-of-range value fails with its own typed code.
 */
function snapshotContinuationPolicy(rule, ruleId) {
  const harness = rule.harness;
  if (!isPlainObject(harness)) invalidContinuation(`rule ${ruleId}: harness must be a plain data object`);
  const budget = Object.getOwnPropertyDescriptor(harness, 'maxSteps');
  const maxSteps = budget !== undefined && hasOwn(budget, 'value') ? budget.value : undefined;
  if (!Number.isSafeInteger(maxSteps) || maxSteps < 1 || maxSteps > MAX_FR07_STEPS) {
    throw new CentralAdmissionError(
      'CONTINUATION_MAX_STEPS_INVALID',
      `rule ${ruleId}: harness.maxSteps must be an integer in 1..${MAX_FR07_STEPS} (the K-owned absolute ceiling MAX_FR07_STEPS)`,
    );
  }
  let data;
  try {
    data = canonicalizeJson(harness);
  } catch (error) {
    invalidContinuation(`rule ${ruleId}: harness must be canonical JSON data (${error instanceof Error ? error.message : String(error)})`);
  }
  for (const key of Object.keys(data)) {
    if (!CONTINUATION_HARNESS_KEYS.has(key)) invalidContinuation(`rule ${ruleId}: harness carries the unsupported key ${key}`);
  }
  const capabilityEntries = isJsonRecord(data.capabilities) ? Object.entries(data.capabilities) : [];
  if (capabilityEntries.length === 0 || capabilityEntries.length > CONTINUATION_MAX_CAPABILITIES) {
    invalidContinuation(`rule ${ruleId}: harness.capabilities must declare 1..${CONTINUATION_MAX_CAPABILITIES} capability descriptors`);
  }
  const capabilities = {};
  for (const [capabilityId, descriptor] of capabilityEntries) {
    const label = `rule ${ruleId}: capability ${capabilityId}`;
    continuationIdentifier(capabilityId, `rule ${ruleId}: capability id`);
    if (!isJsonRecord(descriptor)) invalidContinuation(`${label} must be a descriptor object`);
    if (descriptor.mode === 'read') {
      capabilities[capabilityId] = snapshotReadDescriptor(descriptor, label);
    } else if (descriptor.mode === 'mutation') {
      // Declared ONLY so K can deny it explicitly: no other field, no callable.
      if (Object.keys(descriptor).length !== 1) invalidContinuation(`${label}: a mutation descriptor carries mode only`);
      capabilities[capabilityId] = { mode: 'mutation' };
    } else {
      invalidContinuation(`${label}.mode must be 'read' or 'mutation'`);
    }
  }
  if (typeof rule.id !== 'string' || typeof rule.modelOperation !== 'string') {
    invalidContinuation(`rule ${ruleId}: a harness model-decision rule requires string id and modelOperation`);
  }
  const policy = {
    // The ONLY declaration S ever receives for this rule (wiring snapshot).
    declaration: { kind: 'model-decision', id: rule.id, modelOperation: rule.modelOperation },
    maxSteps,
    capabilities,
    advertisedCapabilities: Object.keys(capabilities).filter((id) => capabilities[id].mode === 'read'),
    allowedOutcomes: continuationIdentifierList(data.allowedOutcomes, `rule ${ruleId}: harness.allowedOutcomes`),
    allowedEvents: continuationIdentifierList(data.allowedEvents, `rule ${ruleId}: harness.allowedEvents`),
  };
  deepFreezePreparedData(policy);
  return policy;
}

/** Wire every harness rule of the Business policy (createOccurrenceRuntime only). */
function wireContinuationPolicies(businessEndpoint) {
  const registry = new WeakMap();
  for (const [ruleId, rule] of Object.entries(businessEndpoint.rules ?? {})) {
    if (!isJsonRecord(rule) || rule.kind !== 'model-decision' || !hasOwn(rule, 'harness')) continue;
    registry.set(rule, snapshotContinuationPolicy(rule, ruleId));
  }
  return registry;
}

// ===========================================================================
// [#1003 FR08 SD1/SD2 + NF05] Trusted-boundary validation of every
// semantic-decision rule of the Business policy — the SELECTED-Kernel half
// of the BUILD→Standard declaration approval binding. BUILD compiles the
// SemanticDecision descriptor and pins its canonical content identity
// (declarationDigest); this wiring verifies that digest through the Host
// sha256 port (SYNCHRONOUSLY — the physical bootstrap port returns the hex
// digest directly) so ONLY the exact compiled declaration can run: a stale
// or substituted descriptor fails the load typed before any instance can
// exist. The shape is validated once here, the validated declaration is
// deep-frozen, and a semantic-decision rule that was never wired is refused
// at submit (no silent unbound fallback). The Kernel gains no new
// authority: Guard/Admission/Effect/Journal stay exactly where they were;
// the Standard SDK interpreter remains the only declaration semantics.
// ===========================================================================
const SEMANTIC_RULE_KEYS = new Set([
  'kind', 'id', 'decisionId', 'declarationDigest', 'inputSelection', 'resultSchema',
  'allowedOutcomes', 'allowedEventTypes', 'queryCapabilityIds', 'dependencyMaterial',
  'cachePolicy', 'promotedReference', 'policy', 'disposition', 'unavailable',
]);
const SEMANTIC_DISPOSITION_KEYS = new Set(['mode', 'outcome', 'eventType', 'outcomeFrom', 'eventTypeFrom', 'payloadFromInput']);
const SEMANTIC_SCHEMA_TYPES = new Set(['string', 'number', 'boolean', 'object', 'array', 'null']);
const SEMANTIC_MAX_LIST = 64;
const SEMANTIC_MAX_FIELDS = 32;
const SEMANTIC_IDENTIFIER = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;

function invalidSemanticRule(message) {
  throw new CentralAdmissionError('SEMANTIC_DECISION_INVALID', message);
}

function semanticIdentifier(value, label) {
  if (typeof value !== 'string' || !SEMANTIC_IDENTIFIER.test(value)) {
    invalidSemanticRule(`${label} must be a bounded identifier`);
  }
  return value;
}

function semanticIdentifierList(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > SEMANTIC_MAX_LIST) {
    invalidSemanticRule(`${label} must be a non-empty bounded identifier list`);
  }
  const seen = new Set();
  for (const item of value) {
    semanticIdentifier(item, label);
    if (seen.has(item)) invalidSemanticRule(`${label} contains the duplicate ${item}`);
    seen.add(item);
  }
  return [...value];
}

/** Validate ONE compiled semantic-decision rule and freeze its snapshot. */
function snapshotSemanticDecisionRule(rule, ruleId, sha256) {
  let data;
  try {
    data = canonicalizeJson(rule);
  } catch (error) {
    invalidSemanticRule(`rule ${ruleId}: the declaration must be canonical JSON data (${error instanceof Error ? error.message : String(error)})`);
  }
  for (const key of Object.keys(data)) {
    if (!SEMANTIC_RULE_KEYS.has(key)) invalidSemanticRule(`rule ${ruleId}: the declaration carries the unsupported key ${key}`);
  }
  const id = semanticIdentifier(data.id, `rule ${ruleId}: id`);
  if (data.decisionId !== undefined && data.decisionId !== id) {
    invalidSemanticRule(`rule ${ruleId}: decisionId does not match the declaration id`);
  }
  // BUILD approval binding: the pinned canonical content identity must
  // verify against the declaration actually present in this policy.
  const digest = data.declarationDigest;
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
    invalidSemanticRule(`rule ${ruleId}: a compiled semantic-decision rule must carry its 64-hex declarationDigest`);
  }
  const { declarationDigest: _pinned, ...body } = data;
  let computed;
  try {
    computed = sha256.digestUtf8(canonicalJsonStringify(body));
  } catch (error) {
    invalidSemanticRule(`rule ${ruleId}: the Host sha256 port refused the declaration digest material (${error instanceof Error ? error.message : String(error)})`);
  }
  if (typeof computed !== 'string' || computed.length === 0) {
    invalidSemanticRule(`rule ${ruleId}: the Host sha256 port must return the declarationDigest synchronously (an async digest cannot gate the synchronous trusted load boundary)`);
  }
  if (computed !== digest) {
    invalidSemanticRule(`rule ${ruleId}: declarationDigest does not match the declaration body (stale or substituted descriptor)`);
  }
  const allowedOutcomes = semanticIdentifierList(data.allowedOutcomes, `rule ${ruleId}: allowedOutcomes`);
  const allowedEventTypes = semanticIdentifierList(data.allowedEventTypes, `rule ${ruleId}: allowedEventTypes`);
  if (data.queryCapabilityIds !== undefined) {
    // A decision with no query capabilities is legal; the read-only
    // VERIFICATION of each listed capability belongs to BUILD.
    if (!Array.isArray(data.queryCapabilityIds) || data.queryCapabilityIds.length > SEMANTIC_MAX_LIST) {
      invalidSemanticRule(`rule ${ruleId}: queryCapabilityIds must be a bounded identifier list`);
    }
    const seenCapabilities = new Set();
    for (const capabilityId of data.queryCapabilityIds) {
      semanticIdentifier(capabilityId, `rule ${ruleId}: queryCapabilityIds`);
      if (seenCapabilities.has(capabilityId)) invalidSemanticRule(`rule ${ruleId}: queryCapabilityIds contains the duplicate ${capabilityId}`);
      seenCapabilities.add(capabilityId);
    }
  }
  // Exact input selection: 1..N declared projection fields.
  const selectionEntries = isJsonRecord(data.inputSelection) ? Object.entries(data.inputSelection) : [];
  if (selectionEntries.length === 0 || selectionEntries.length > SEMANTIC_MAX_FIELDS) {
    invalidSemanticRule(`rule ${ruleId}: inputSelection must map 1..${SEMANTIC_MAX_FIELDS} output names to input keys`);
  }
  const selectedKeys = new Set();
  for (const [outputName, sourceKey] of selectionEntries) {
    semanticIdentifier(outputName, `rule ${ruleId}: inputSelection output name`);
    semanticIdentifier(sourceKey, `rule ${ruleId}: inputSelection.${outputName}`);
    selectedKeys.add(outputName);
  }
  if (data.resultSchema !== undefined) {
    if (!isJsonRecord(data.resultSchema)) invalidSemanticRule(`rule ${ruleId}: resultSchema must be an object`);
    const required = data.resultSchema.required ?? [];
    if (!Array.isArray(required) || required.length > 1024) {
      invalidSemanticRule(`rule ${ruleId}: resultSchema.required must be a bounded string list`);
    }
    for (const name of required) semanticIdentifier(name, `rule ${ruleId}: resultSchema.required`);
    const properties = isJsonRecord(data.resultSchema.properties) ? data.resultSchema.properties : {};
    for (const [name, type] of Object.entries(properties)) {
      semanticIdentifier(name, `rule ${ruleId}: resultSchema.properties key`);
      if (!SEMANTIC_SCHEMA_TYPES.has(type)) {
        invalidSemanticRule(`rule ${ruleId}: resultSchema.properties.${name} has the unsupported type ${String(type)}`);
      }
    }
  }
  if (!isJsonRecord(data.policy) || !Number.isSafeInteger(data.policy.maxSteps) || data.policy.maxSteps < 1) {
    invalidSemanticRule(`rule ${ruleId}: policy.maxSteps must be a positive integer`);
  }
  if (data.promotedReference !== undefined) {
    if (!isJsonRecord(data.promotedReference)) invalidSemanticRule(`rule ${ruleId}: promotedReference must be an object`);
    semanticIdentifier(data.promotedReference.artifactId, `rule ${ruleId}: promotedReference.artifactId`);
    semanticIdentifier(data.promotedReference.contentDigest, `rule ${ruleId}: promotedReference.contentDigest`);
    if (data.promotedReference.required !== undefined && typeof data.promotedReference.required !== 'boolean') {
      invalidSemanticRule(`rule ${ruleId}: promotedReference.required must be a boolean`);
    }
  }
  if (data.unavailable !== undefined) {
    if (!isJsonRecord(data.unavailable) || data.unavailable.disposition !== 'semantic-unavailable'
      || typeof data.unavailable.reason !== 'string' || data.unavailable.reason.length === 0
      || data.unavailable.reason.length > 256) {
      invalidSemanticRule(`rule ${ruleId}: unavailable must declare disposition 'semantic-unavailable' with a bounded non-empty reason`);
    }
  } else {
    if (!isJsonRecord(data.disposition)) invalidSemanticRule(`rule ${ruleId}: disposition must be an object`);
    for (const key of Object.keys(data.disposition)) {
      if (!SEMANTIC_DISPOSITION_KEYS.has(key)) invalidSemanticRule(`rule ${ruleId}: disposition carries the unsupported key ${key}`);
    }
    const projection = isJsonRecord(data.disposition.payloadFromInput) ? data.disposition.payloadFromInput : {};
    if (Object.keys(projection).length > SEMANTIC_MAX_FIELDS) {
      invalidSemanticRule(`rule ${ruleId}: disposition.payloadFromInput is unbounded`);
    }
    for (const [field, sourceKey] of Object.entries(projection)) {
      semanticIdentifier(field, `rule ${ruleId}: disposition.payloadFromInput field`);
      semanticIdentifier(sourceKey, `rule ${ruleId}: disposition.payloadFromInput.${field}`);
      if (!selectedKeys.has(sourceKey)) {
        invalidSemanticRule(`rule ${ruleId}: disposition.payloadFromInput.${field} addresses ${String(sourceKey)} outside the declared inputSelection`);
      }
    }
    if (data.disposition.mode === 'deterministic') {
      if (!allowedOutcomes.includes(semanticIdentifier(data.disposition.outcome, `rule ${ruleId}: disposition.outcome`))) {
        invalidSemanticRule(`rule ${ruleId}: disposition.outcome is not a declared allowed outcome`);
      }
      if (!allowedEventTypes.includes(semanticIdentifier(data.disposition.eventType, `rule ${ruleId}: disposition.eventType`))) {
        invalidSemanticRule(`rule ${ruleId}: disposition.eventType is not a declared allowed event type`);
      }
    } else if (data.disposition.mode === 'route') {
      semanticIdentifier(data.disposition.outcomeFrom, `rule ${ruleId}: disposition.outcomeFrom`);
      semanticIdentifier(data.disposition.eventTypeFrom, `rule ${ruleId}: disposition.eventTypeFrom`);
    } else {
      invalidSemanticRule(`rule ${ruleId}: disposition.mode must be 'deterministic' or 'route'`);
    }
  }
  const snapshot = { declaration: data };
  deepFreezePreparedData(snapshot);
  return snapshot;
}

/** Wire every compiled semantic-decision rule (createOccurrenceRuntime only). */
function wireSemanticDecisionRules(businessEndpoint, sha256) {
  const registry = new WeakMap();
  for (const [ruleId, rule] of Object.entries(businessEndpoint.rules ?? {})) {
    if (!isJsonRecord(rule) || rule.kind !== 'semantic-decision') continue;
    registry.set(rule, snapshotSemanticDecisionRule(rule, ruleId, sha256));
  }
  return registry;
}

// ===========================================================================
// [#1003 FR08 general + FR09 + FR12] Trusted-boundary validation of
// decision-source rules — the Kernel half of the retained resolver
// composition, lawfully reduced to the frozen v0.8 S contract
// (standard-sdk-v1.mjs resolveRetainedDecision / selectRetainedPromotedChild
// / checkRetainedEvidenceApplicability): "K passes current qualified
// observations; the Standard SDK emits only a selected candidate".
//
// The Business package compiles a decision-source declaration whose legs
// mirror the retained v0.7 ordering Rule -> Exact Cache -> Promoted ->
// Harness; this wiring verifies the pinned canonical declarationDigest and
// freezes the validated legs EXACTLY like the semantic-decision wiring, so
// only the exact compiled declaration can run. The Kernel gains NO new
// admission authority: the S selection is the only ordering/currentness/
// eligibility authority, the selected candidate flows through the UNCHANGED
// central admission (schema → hard invariant → guard → transition →
// journal → effect), and every durable record (exact-cache entry,
// promoted-child pin) lives in the generic Host document store through the
// same ports the journal/pins/baselines already use. No second runtime, no
// v0.7 resolver port, no caller-injected store.
// ===========================================================================
const DECISION_SOURCE_RULE_KEYS = new Set([
  'kind', 'id', 'decisionId', 'declarationDigest', 'payloadFromInput', 'rule', 'cache', 'promoted', 'harness',
]);
const DECISION_SOURCE_IDENTIFIER = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const DECISION_SOURCE_DIGEST = /^[0-9a-f]{64}$/;
const DECISION_SOURCE_MAX_DEPS = 8;
const DECISION_SOURCE_MAX_PROJECTION = 16;
const DECISION_CACHE_PREFIX = 'v08-kernel:decision-cache:';
const PROMOTED_PIN_PREFIX = 'v08-kernel:promoted-pin:';

function invalidDecisionSource(message) {
  throw new CentralAdmissionError('DECISION_SOURCE_INVALID', message);
}

function decisionSourceIdentifier(value, label) {
  if (typeof value !== 'string' || !DECISION_SOURCE_IDENTIFIER.test(value)) {
    invalidDecisionSource(`${label} must be a bounded identifier`);
  }
  return value;
}

function snapshotDecisionSourcePredicate(value, label) {
  if (!isJsonRecord(value)) invalidDecisionSource(`${label} must be a DomainPredicate object`);
  try {
    assertDomainPredicateShape(value, label, invalidDecisionSource);
    return prepareDomainPredicate(value);
  } catch (error) {
    if (error instanceof CentralAdmissionError) throw error;
    invalidDecisionSource(`${label} is not a preparable DomainPredicate: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Validate ONE compiled decision-source rule and freeze its snapshot.
 * Shape follows the semantic-decision discipline: exact key set, pinned
 * canonical declarationDigest, deep-frozen legs. The promoted leg's
 * requested identity must match the sealed approved artifact EXACTLY at
 * this boundary (a BUILD inconsistency fails the load); eligibility
 * (revoked / applicable / compatible) is deliberately NOT decided here —
 * that is the retained S runtime authority.
 */
function snapshotDecisionSourceRule(rule, ruleId, businessEndpoint, sha256) {
  const data = rule;
  for (const key of Object.keys(data)) {
    if (!DECISION_SOURCE_RULE_KEYS.has(key)) {
      invalidDecisionSource(`rule ${ruleId}: unknown decision-source field ${JSON.stringify(key)}`);
    }
  }
  if (data.id !== ruleId) invalidDecisionSource(`rule ${ruleId}: decision-source id must equal the policy rule key`);
  decisionSourceIdentifier(data.id, `rule ${ruleId}: id`);
  const decisionId = decisionSourceIdentifier(data.decisionId, `rule ${ruleId}: decisionId`);
  if (typeof data.declarationDigest !== 'string' || !DECISION_SOURCE_DIGEST.test(data.declarationDigest)) {
    invalidDecisionSource(`rule ${ruleId}: a compiled decision-source rule must carry its 64-hex declarationDigest`);
  }
  const { declarationDigest: _pinned, ...body } = data;
  let digest;
  try {
    digest = sha256.digestUtf8(canonicalJsonStringify(body));
  } catch (error) {
    invalidDecisionSource(`rule ${ruleId}: the Host sha256 port must return the declarationDigest synchronously (${error instanceof Error ? error.message : String(error)})`);
  }
  if (digest !== data.declarationDigest) {
    invalidDecisionSource(`rule ${ruleId}: declarationDigest does not match the declaration body (stale or substituted descriptor)`);
  }

  // The bounded input-projection authorization (the exact context-projection
  // discipline: rule-level payloadFromInput). Doubles as the rule leg's
  // candidate payload source when a rule leg is declared.
  let payloadFromInput;
  if (data.payloadFromInput !== undefined) {
    if (!isJsonRecord(data.payloadFromInput) || Object.keys(data.payloadFromInput).length === 0
      || Object.keys(data.payloadFromInput).length > DECISION_SOURCE_MAX_PROJECTION) {
      invalidDecisionSource(`rule ${ruleId}: payloadFromInput must be a non-empty bounded key map`);
    }
    payloadFromInput = {};
    for (const [payloadKey, inputKey] of Object.entries(data.payloadFromInput)) {
      decisionSourceIdentifier(payloadKey, `rule ${ruleId}: payloadFromInput key`);
      decisionSourceIdentifier(inputKey, `rule ${ruleId}: payloadFromInput.${payloadKey}`);
      payloadFromInput[payloadKey] = inputKey;
    }
  }

  // Deterministic rule leg: predicate gate + declared outcome/eventType; the
  // candidate payload is projected from the occurrence input through the
  // authorized map. A mapped input key that is absent makes the leg MISS
  // (the deterministic rule declines to decide this input) — never a
  // half-projected candidate.
  let ruleLeg;
  if (data.rule !== undefined) {
    if (!isJsonRecord(data.rule)) invalidDecisionSource(`rule ${ruleId}: rule leg must be an object`);
    for (const key of Object.keys(data.rule)) {
      if (key !== 'when' && key !== 'outcome' && key !== 'eventType') {
        invalidDecisionSource(`rule ${ruleId}: rule leg may only declare when, outcome and eventType`);
      }
    }
    if (payloadFromInput === undefined) {
      invalidDecisionSource(`rule ${ruleId}: a rule leg requires the rule-level payloadFromInput projection`);
    }
    const when = snapshotDecisionSourcePredicate(data.rule.when, `rule ${ruleId}: rule.when`);
    const outcome = decisionSourceIdentifier(data.rule.outcome, `rule ${ruleId}: rule.outcome`);
    const eventType = decisionSourceIdentifier(data.rule.eventType, `rule ${ruleId}: rule.eventType`);
    ruleLeg = { when, outcome, eventType };
  }

  // Exact-cache leg: the declared dependency fields whose CURRENT context
  // values pin the cache key; a lookup under changed dependency material is
  // a miss by construction and the stale entry is never served.
  let cacheDeps;
  if (data.cache !== undefined) {
    if (!isJsonRecord(data.cache)) invalidDecisionSource(`rule ${ruleId}: cache leg must be an object`);
    for (const key of Object.keys(data.cache)) {
      if (key !== 'dependencies') invalidDecisionSource(`rule ${ruleId}: cache leg may only declare dependencies`);
    }
    const dependencies = data.cache.dependencies;
    if (!Array.isArray(dependencies) || dependencies.length === 0 || dependencies.length > DECISION_SOURCE_MAX_DEPS) {
      invalidDecisionSource(`rule ${ruleId}: cache.dependencies must be a non-empty bounded list of context fields`);
    }
    const seen = new Set();
    cacheDeps = [];
    for (const field of dependencies) {
      decisionSourceIdentifier(field, `rule ${ruleId}: cache dependency field`);
      if (seen.has(field)) invalidDecisionSource(`rule ${ruleId}: duplicate cache dependency field ${field}`);
      seen.add(field);
      cacheDeps.push(field);
    }
  }

  // Governed promoted-child leg (FR09): requested identity must match the
  // sealed approved artifact exactly; durable pin-before-execution is
  // established at turn time by THIS kernel; eligibility stays with S.
  let promoted;
  if (data.promoted !== undefined) {
    if (!isJsonRecord(data.promoted)) invalidDecisionSource(`rule ${ruleId}: promoted leg must be an object`);
    for (const key of Object.keys(data.promoted)) {
      if (key !== 'artifactId' && key !== 'contentDigest' && key !== 'when') {
        invalidDecisionSource(`rule ${ruleId}: promoted leg may only declare artifactId, contentDigest and when`);
      }
    }
    const artifactId = decisionSourceIdentifier(data.promoted.artifactId, `rule ${ruleId}: promoted.artifactId`);
    const contentDigest = decisionSourceIdentifier(data.promoted.contentDigest, `rule ${ruleId}: promoted.contentDigest`);
    const approved = isJsonRecord(businessEndpoint.promotedArtifacts)
      ? businessEndpoint.promotedArtifacts[artifactId]
      : undefined;
    if (!isJsonRecord(approved) || approved.artifactId !== artifactId || approved.contentDigest !== contentDigest) {
      invalidDecisionSource(
        `rule ${ruleId}: the promoted reference does not match the sealed approved artifact ${artifactId} (BUILD identity inconsistency)`,
      );
    }
    const candidate = approved.candidate;
    if (!isJsonRecord(candidate) || !isJsonRecord(candidate.decision) || !isJsonRecord(candidate.event)
      || typeof candidate.decision.outcome !== 'string' || typeof candidate.event.type !== 'string') {
      invalidDecisionSource(`rule ${ruleId}: approved artifact ${artifactId} carries no structured decision candidate`);
    }
    try {
      canonicalizeJson(candidate);
    } catch (error) {
      invalidDecisionSource(`rule ${ruleId}: approved artifact ${artifactId} candidate is not canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    const when = snapshotDecisionSourcePredicate(data.promoted.when, `rule ${ruleId}: promoted.when`);
    promoted = { artifactId, contentDigest, when, candidate: snapshotJson(candidate) };
  }

  // Bounded harness fallback leg: ONE trusted ModelPort turn through the
  // sealed composite model-decision surface, reached only when every
  // earlier leg missed.
  let harness;
  if (data.harness !== undefined) {
    if (!isJsonRecord(data.harness)) invalidDecisionSource(`rule ${ruleId}: harness leg must be an object`);
    for (const key of Object.keys(data.harness)) {
      if (key !== 'modelOperation') invalidDecisionSource(`rule ${ruleId}: harness leg may only declare modelOperation`);
    }
    const modelOperation = decisionSourceIdentifier(data.harness.modelOperation, `rule ${ruleId}: harness.modelOperation`);
    harness = { modelOperation };
  }

  if (ruleLeg === undefined && promoted === undefined && harness === undefined) {
    invalidDecisionSource(`rule ${ruleId}: a decision-source rule must declare at least one resolver leg (rule/promoted/harness)`);
  }

  const snapshot = {
    id: data.id,
    decisionId,
    payloadFromInput,
    ruleLeg,
    cacheDeps,
    promoted,
    harness,
    declaration: snapshotJson(body),
  };
  deepFreezePreparedData(snapshot);
  return snapshot;
}

/** Wire every decision-source rule of the Business policy (createOccurrenceRuntime only). */
function wireDecisionSourceRules(businessEndpoint, sha256) {
  const registry = new WeakMap();
  let count = 0;
  for (const [ruleId, rule] of Object.entries(businessEndpoint.rules ?? {})) {
    if (!isJsonRecord(rule) || rule.kind !== 'decision-source') continue;
    registry.set(rule, snapshotDecisionSourceRule(rule, ruleId, businessEndpoint, sha256));
    count += 1;
  }
  // WeakMap has no .size: carry a bounded explicit count for fail-fast load gates.
  return { registry, count };
}

/**
 * Trusted per-step evidence: exactly the shape the Host-bound resolver
 * mints for ONE physically observed bound-port invocation. Anything else —
 * a different count, extra fields, a model-free source — fails closed.
 */
function trustedStepEvidence(envelope) {
  const evidence = envelope.modelCallEvidence;
  if (envelope.source === 'host-model-port' && envelope.llmAvoided === false && isJsonRecord(evidence)) {
    const keys = Object.keys(evidence).sort().join(',');
    if (evidence.status === 'measured' && evidence.count === 1 && evidence.scope === BOUND_PORT_EVIDENCE_SCOPE && keys === 'count,scope,status') {
      return 'measured';
    }
    if (evidence.status === 'unmeasured' && keys === 'status') {
      return 'unmeasured';
    }
  }
  throw new CentralAdmissionError(
    'CONTINUATION_MODEL_EVIDENCE_INVALID',
    'a continuation step did not carry the trusted single-invocation evidence of the Host-bound resolver; no decision is admitted',
  );
}

/**
 * K aggregate over completed turns. A discarded in-flight turn may have
 * reached the physical port without returning evidence, so the aggregate
 * can then no longer be an exact count: it degrades to `unmeasured`.
 */
function aggregateModelCallEvidence(stepEvidence, inFlightTurnDiscarded) {
  if (inFlightTurnDiscarded || stepEvidence.length === 0 || stepEvidence.some((status) => status !== 'measured')) {
    return { status: 'unmeasured' };
  }
  return { status: 'measured', count: stepEvidence.length, scope: BOUND_PORT_EVIDENCE_SCOPE };
}

/**
 * Admission-side normalization of resolver model-call evidence (B2). Only a
 * structured trusted shape is carried; absence is `unsupported`; a
 * malformed structured claim fails closed.
 */
function admissionModelCallEvidence(evidence) {
  if (evidence === undefined) return { status: 'unsupported' };
  if (isJsonRecord(evidence)) {
    const keys = Object.keys(evidence).sort().join(',');
    if (evidence.status === 'measured' && Number.isSafeInteger(evidence.count) && evidence.count >= 0
      && typeof evidence.scope === 'string' && keys === 'count,scope,status') {
      return { status: 'measured', count: evidence.count, scope: evidence.scope };
    }
    if ((evidence.status === 'unmeasured' || evidence.status === 'unsupported') && keys === 'status') {
      return { status: evidence.status };
    }
  }
  throw new CentralAdmissionError(
    'ADMISSION_MODEL_EVIDENCE_INVALID',
    'resolver model-call evidence must be a structured measured/unmeasured/unsupported record; no decision is admitted',
  );
}

/**
 * Request-scoped cancellation latch (B3). The signal is H-owned (the
 * authenticated gateway's AbortController); the latch state is K-owned:
 * open → cancelled, or open → admitting (closed for good once admission
 * starts). Without a control the latch never cancels.
 */
function createCancellationLatch(control) {
  if (control === undefined) {
    return { signal: undefined, get cancelled() { return false; }, closeForAdmission() { return true; }, dispose() {} };
  }
  const signal = isJsonRecord(control) ? control.signal : undefined;
  if (
    signal === null
    || typeof signal !== 'object'
    || typeof signal.aborted !== 'boolean'
    || typeof signal.addEventListener !== 'function'
    || typeof signal.removeEventListener !== 'function'
  ) {
    throw new CentralAdmissionError(
      'OCCURRENCE_CONTROL_INVALID',
      'an occurrence control must carry a request-scoped cancellation signal {aborted, addEventListener, removeEventListener}',
    );
  }
  let state = signal.aborted ? 'cancelled' : 'open';
  const onAbort = () => {
    if (state === 'open') state = 'cancelled';
  };
  signal.addEventListener('abort', onAbort, { once: true });
  return {
    signal,
    get cancelled() {
      if (state === 'open' && signal.aborted === true) state = 'cancelled';
      return state === 'cancelled';
    },
    closeForAdmission() {
      if (this.cancelled) return false;
      state = 'admitting';
      return true;
    },
    dispose() {
      signal.removeEventListener('abort', onAbort);
    },
  };
}

/**
 * The ONLY continuation query executor: a K-owned, read-only projection of
 * the instance context, re-read through the Host document port and attested
 * at exactly the lane's stateRevision. Ordinary failures (input not allowed
 * by the descriptor, absent context key) become observations; read material
 * that is not canonical, carries no version, or violates the sealed output
 * contract is a terminal query-output failure.
 */
async function executeContinuationRead(descriptor, callInput, read) {
  let selected = Object.keys(descriptor.fields);
  let input;
  try {
    input = canonicalizeJson(callInput);
  } catch {
    return { ok: false, code: 'QUERY_INPUT_INVALID' };
  }
  if (!isJsonRecord(input) || Object.keys(input).some((key) => key !== 'fields')) {
    return { ok: false, code: 'QUERY_INPUT_INVALID' };
  }
  if (hasOwn(input, 'fields')) {
    const fields = input.fields;
    if (!Array.isArray(fields) || fields.length === 0 || new Set(fields).size !== fields.length
      || !fields.every((name) => typeof name === 'string' && hasOwn(descriptor.fields, name))) {
      return { ok: false, code: 'QUERY_INPUT_INVALID' };
    }
    selected = [...fields];
  }

  const doc = await read.docs.get((read.docKeys ?? legacyKernelDocKeys()).instance(read.target));
  let material;
  try {
    material = canonicalizeJson(doc);
  } catch {
    return { invalid: 'read material is not canonical JSON (accessor, cycle or non-JSON value)' };
  }
  if (!isJsonRecord(material) || !isJsonRecord(material.value)) {
    return { invalid: 'read material carries no instance document' };
  }
  const value = material.value;
  if (!Number.isSafeInteger(material.revision) || !Number.isSafeInteger(value.stateRevision)) {
    return { invalid: 'read material carries no instance version' };
  }
  if (!isJsonRecord(value.address) || !workflowAddressesEqual(value.address, read.target)) {
    return { invalid: 'read material addresses a different workflow instance' };
  }
  if (material.revision !== value.stateRevision || value.stateRevision !== read.stateRevision) {
    return { stale: true };
  }
  const context = isJsonRecord(value.state) ? value.state.context : undefined;
  if (!isJsonRecord(context)) {
    return { invalid: 'read material carries no instance context' };
  }
  const output = {};
  for (const outputName of selected) {
    const contextKey = descriptor.fields[outputName];
    if (!hasOwn(context, contextKey)) return { ok: false, code: 'QUERY_SOURCE_MISSING' };
    const item = context[contextKey];
    if (hasOwn(descriptor.outputSchema, outputName) && jsonTypeOf(item) !== descriptor.outputSchema[outputName]) {
      return { invalid: `read output ${outputName} violates its sealed output type ${descriptor.outputSchema[outputName]}` };
    }
    output[outputName] = item;
  }
  return { ok: true, output, stateRevision: value.stateRevision };
}

/**
 * The K-owned bounded continuation loop (one occurrence, inside its lane).
 * Returns either {resolved} for central admission or {terminal} — never
 * writes State, Journal or Effect itself.
 */
async function runModelContinuation(run) {
  const { policy, sdkEndpoint, latch, requestInput } = run;
  const observations = [];
  const dependencies = [];
  const dependencyKeys = new Set();
  const stepEvidence = [];
  let steps = 0;
  let queries = 0;
  let inFlightTurnDiscarded = false;

  const evidence = () => ({
    source: 'host-model-port',
    llmAvoided: false,
    modelCallEvidence: aggregateModelCallEvidence(stepEvidence, inFlightTurnDiscarded),
    continuation: {
      maxSteps: policy.maxSteps,
      steps,
      queries,
      dependencies: dependencies.map((dependency) => ({ ...dependency })),
    },
  });
  const terminal = (code, extras = {}) => ({ terminal: { code, step: steps, ...extras }, evidence: evidence() });
  const control = latch.signal === undefined ? undefined : { signal: latch.signal };

  for (;;) {
    if (latch.cancelled) return terminal('CANCELLED');
    if (steps >= policy.maxSteps) return terminal('MAX_STEPS_EXHAUSTED');
    steps += 1;
    const modelInput = {
      request: requestInput,
      step: steps,
      maxSteps: policy.maxSteps,
      capabilities: [...policy.advertisedCapabilities],
      observations: observations.map((observation) => canonicalizeJson(observation)),
    };

    let envelope;
    try {
      envelope = await sdkEndpoint.invokeStep(policy.declaration, modelInput, {}, control);
    } catch (error) {
      if (latch.cancelled) {
        inFlightTurnDiscarded = true;
        return terminal('CANCELLED', { inFlightTurnDiscarded: true });
      }
      throw error;
    }
    if (!isJsonRecord(envelope) || (envelope.kind !== 'query' && envelope.kind !== 'final')) {
      throw new CentralAdmissionError('CONTINUATION_STEP_INVALID', 'the step surface returned no query/final envelope');
    }
    stepEvidence.push(trustedStepEvidence(envelope));
    // Late result: a turn that completes after cancellation is discarded.
    if (latch.cancelled) return terminal('CANCELLED', { lateResultDiscarded: true });

    if (envelope.kind === 'final') {
      const structuredDecision = envelope.structuredDecision;
      const outcome = isJsonRecord(structuredDecision) && isJsonRecord(structuredDecision.decision) ? structuredDecision.decision.outcome : undefined;
      const eventType = isJsonRecord(structuredDecision) && isJsonRecord(structuredDecision.event) ? structuredDecision.event.type : undefined;
      if (!policy.allowedOutcomes.includes(outcome)) return terminal('FINAL_OUTCOME_NOT_ALLOWED');
      if (!policy.allowedEvents.includes(eventType)) return terminal('FINAL_EVENT_NOT_ALLOWED');
      return {
        resolved: {
          kind: 'model-continuation',
          structuredDecision,
          provenance: envelope.provenance,
          cacheDisposition: { read: 'disabled' },
          telemetry: [],
          ...evidence(),
        },
      };
    }

    const call = envelope.call;
    const capabilityId = isJsonRecord(call) ? call.capabilityId : undefined;
    if (typeof capabilityId !== 'string') {
      throw new CentralAdmissionError('CONTINUATION_STEP_INVALID', 'a query envelope carries no capabilityId');
    }
    const descriptor = hasOwn(policy.capabilities, capabilityId) ? policy.capabilities[capabilityId] : undefined;
    if (descriptor === undefined) return terminal('UNKNOWN_CAPABILITY', { capabilityId });
    if (descriptor.mode !== 'read') return terminal('MUTATION_CAPABILITY_FORBIDDEN', { capabilityId });

    queries += 1;
    const result = await executeContinuationRead(descriptor, call.input, run.read);
    if (latch.cancelled) return terminal('CANCELLED', { lateReadDiscarded: true });
    if (result.invalid !== undefined) return terminal('QUERY_OUTPUT_INVALID', { capabilityId });
    if (result.stale === true) return terminal('QUERY_SOURCE_STALE', { capabilityId });
    if (result.ok) {
      observations.push({ step: steps, capabilityId, ok: true, output: result.output });
      const dependency = {
        capabilityId,
        source: 'instance-context',
        workflowInstanceId: run.read.workflowInstanceId,
        stateRevision: result.stateRevision,
      };
      const key = canonicalJsonStringify(dependency);
      if (!dependencyKeys.has(key)) {
        dependencyKeys.add(key);
        dependencies.push(dependency);
      }
    } else {
      observations.push({ step: steps, capabilityId, ok: false, error: { code: result.code } });
    }
  }
}

// ===========================================================================
// [KPK-01 experiment, kernel-owned] Occurrence runtime endpoint — the kernel
// composition that the Microkernel wires from the sealed package endpoints.
// The kernel decides WHEN/WHETHER admission, effects, journal commits and
// state commits happen; the SDK endpoint interprets Rules; the Business
// endpoint supplies domain policy (workflow definitions, guards, effect
// handlers); the Host supplies raw storage/crypto/clock/resources.
// ===========================================================================

function stateKindIsTerminal(definition, stateKey) {
  const state = definition.states.find((candidate) => candidate.stateKey === stateKey);
  return state?.kind === 'final' || state?.kind === 'failure';
}

export function createOccurrenceRuntime(options) {
  const {
    moduleIdentity,
    hostPorts,
    sdkEndpoint,
    businessEndpoint,
    observe,
  } = options;

  if (typeof hostPorts?.docs?.get !== 'function' || typeof hostPorts?.docs?.put !== 'function') {
    throw new CentralAdmissionError('ADMISSION_EVALUATION_INPUT_INVALID', 'kernel endpoint requires a Host document-store port');
  }
  if (typeof sdkEndpoint?.interpret !== 'function') {
    throw new CentralAdmissionError('ADMISSION_EVALUATION_INPUT_INVALID', 'kernel endpoint requires an SDK rule-interpreter endpoint');
  }
  if (typeof businessEndpoint?.policyId !== 'string') {
    throw new CentralAdmissionError('ADMISSION_EVALUATION_INPUT_INVALID', 'kernel endpoint requires a Business policy endpoint');
  }

  const counters = {
    admissions: 0,
    guardEvaluations: 0,
    hardInvariantEvaluations: 0,
    journalBegins: 0,
    journalCompletes: 0,
    effectDispatches: 0,
    // [v0.10 C01 #1177] Live K-issued external Effect Permit observability.
    effectPermitsMinted: 0,
    effectPermitsConsumed: 0,
    effectDispatchClaims: 0,
    effectDispatchClaimRefusals: 0,
    engineCommits: 0,
    instanceCreates: 0,
    instanceReads: 0,
    decisionReceiptAppends: 0,
    decisionCacheWrites: 0,
    decisionCacheWriteFailures: 0,
    mutationObservationReads: 0,
    promotedPins: 0,
    turnDispositions: 0,
    turnAdmissionReplays: 0,
    turnDispositionReplays: 0,
    durableOriginalReceiptReplays: 0,
    durableReceiptArchiveWrites: 0,
    durableReceiptArchiveFailures: 0,
    durableRingGrowthEvents: 0,
  };

  const docs = hostPorts.docs;
  const sha256 = hostPorts.sha256;
  const clock = hostPorts.clock ?? (() => new Date().toISOString());

  // [v0.10 K02 anchor 5] The runtime's deployment-identity wiring: a wired
  // deployment scope routes the six durable doc families through the
  // injective scoped grammar (`v010-k02:<app>:<tenant>:<appId>:<pkg>:<kind>:
  // <parts>`) and joins the deployment tuple in every turn identity; the
  // unscoped wiring keeps the historical `v08-kernel:` keys byte-for-byte
  // (compatibility mode). Key builders are chosen ONCE here — never per call.
  const deploymentScope = options.deploymentScope === undefined
    ? undefined
    : deploymentScopeIdentity(options.deploymentScope);
  const docKeys = deploymentScope === undefined ? legacyKernelDocKeys() : scopedKernelDocKeys(deploymentScope);

  // [v0.10 K02] The canonical input digest of ONE occurrence input: sha256
  // over the kernel's own canonical JSON form. An ABSENT input normalizes to
  // null (the same normalization the Host gateway applies), so the omitted
  // and the explicit-null forms are one canonical input; any present
  // non-JSON-representable value refuses typed K02_INPUT_NOT_JSON at the
  // admission boundary.
  const canonicalInputDigestK02 = (input) => {
    try {
      return `sha256:${sha256.digestUtf8(canonicalJsonStringify(input === undefined ? null : input))}`;
    } catch (error) {
      throw new CentralAdmissionError(
        'K02_INPUT_NOT_JSON',
        `the occurrence input is not a canonical JSON value; the durable original-receipt identity requires canonical JSON (${error instanceof Error ? error.message : String(error)})`,
      );
    }
  };

  const engine = new WorkflowInstanceEngine(docs, {
    now: clock,
    counters,
    docKeys,
    ...(options.durableReceiptRingBound === undefined ? {} : { durableReceiptRingBound: options.durableReceiptRingBound }),
  });
  const effectJournal = new KernelDurableEffectJournal(docs, moduleIdentity.moduleSha256, counters, docKeys);
  const pinStore = new KernelGovernancePinStore(docs, sha256, moduleIdentity.moduleSha256);
  const baselines = new KernelBaselineStore(docs);

  // [Controller 090 repair] One-time wiring validation of every dynamic
  // effect-intent binding, at this trusted installation boundary: a
  // malformed/unauthorized/ambiguous declaration fails the load typed
  // BEFORE any instance can exist. The frozen snapshots registered here
  // are the only declaration source trusted at admission time.
  const effectBindings = wireAdmissionEffectBindings(businessEndpoint);
  // [#1005 D3-K] Same trusted boundary: every declared state-context
  // projection is validated and frozen before any instance can exist.
  const contextProjections = wireAdmissionContextProjections(businessEndpoint);
  // [#1003 FR07-KH2] Same trusted boundary, same discipline: every harness
  // rule is validated and frozen here, before any instance can exist.
  const continuationPolicies = wireContinuationPolicies(businessEndpoint);
  // [#1003 FR08 SD1/SD2 + NF05] Same trusted boundary: every compiled
  // semantic-decision rule has its pinned declarationDigest verified and its
  // shape validated ONCE here; a stale/substituted/malformed declaration
  // fails the load typed before any instance can exist.
  const semanticDecisionRules = wireSemanticDecisionRules(businessEndpoint, sha256);
  // [#1003 NF06] Same trusted boundary: every intent-declared receiptPolicy
  // is shape-validated and frozen here, before any instance can exist.
  const decisionReceiptPolicies = wireDecisionReceiptPolicies(businessEndpoint);
  // [#1003 FR08 general + FR09 + FR12] Same trusted boundary: every
  // decision-source rule is digest-verified, shape-validated and frozen
  // here before any instance can exist. The retained S decision-source
  // semantics must be exposed by the selected Standard SDK for any wired
  // rule — no silent degradation to a different engine.
  const { registry: decisionSourceRules, count: decisionSourceRuleCount } = wireDecisionSourceRules(businessEndpoint, sha256);
  if (decisionSourceRuleCount > 0 && (
    typeof sdkEndpoint?.resolveDecisionSource !== 'function'
    || typeof sdkEndpoint?.selectPromotedChild !== 'function'
    || typeof sdkEndpoint?.checkEvidenceApplicability !== 'function'
  )) {
    throw new CentralAdmissionError(
      'DECISION_SOURCE_SDK_ENDPOINT_UNAVAILABLE',
      'the Business policy declares decision-source rules but the selected Standard SDK exposes no retained decision-source endpoints (resolveRetainedDecision / selectRetainedPromotedChild / checkRetainedEvidenceApplicability)',
    );
  }
  // [#1003 FR12] The per-policy decision-scope identity exact-cache records
  // are pinned to: the exact Business package + policy + governance
  // semantics, through the SAME synchronous Host sha256 port as the wiring
  // digests. The retained S evidence-applicability helper validates its
  // package/baseline fields with the bounded-identifier grammar, so the
  // scope is encoded identifier-safely (policyId + a letter-prefixed
  // digest); a policy whose policyId is not identifier-shaped cannot
  // declare cacheable decision-source rules. A cached record from any
  // other scope is never applicable.
  const decisionScopeDigest = `decision-scope-v1:${sha256.digestUtf8(canonicalJsonStringify({
    packageId: businessEndpoint.packageId,
    policyId: businessEndpoint.policyId,
    governanceSemantics: businessEndpoint.governanceSemantics ?? null,
  }))}`;
  const decisionScopePackage = typeof businessEndpoint.policyId === 'string'
    && DECISION_SOURCE_IDENTIFIER.test(businessEndpoint.policyId)
    ? businessEndpoint.policyId
    : undefined;
  if (decisionSourceRuleCount > 0 && decisionScopePackage === undefined) {
    throw new CentralAdmissionError(
      'DECISION_SOURCE_INVALID',
      'a Business policy that declares decision-source rules must carry a bounded-identifier policyId for the retained evidence-applicability scope',
    );
  }

  /**
   * [#1003 FR08 general] Persist ONE exact-cache record through the Host
   * true-CAS port — the physical store has no unconditional writes, so the
   * write is exactly one of create (mustBeAbsent) or CAS
   * (mustMatchRevision at the just-read revision), like every other
   * Kernel-owned durable record. The key is content-addressed by the
   * instance + decision + canonical input + dependency material, so an
   * overwrite can only carry newer admitted truth for the exact same
   * lookup; any lost race is a bounded observation (the cache is an
   * optimization over the durable admission, never an authority).
   */
  async function writeDecisionCacheRecord(key, record) {
    let envelope;
    try {
      envelope = await docs.get(key);
    } catch {
      envelope = undefined;
    }
    const existing = isJsonRecord(envelope) ? envelope : undefined;
    if (
      existing !== undefined
      && isJsonRecord(existing.value)
      && existing.value.writtenAtTurn === record.writtenAtTurn
    ) {
      return; // idempotent same-turn replay of the exact admitted record
    }
    if (existing === undefined) {
      try {
        await docs.put(key, record, { mustBeAbsent: true });
        counters.decisionCacheWrites += 1;
        return;
      } catch {
        // lost the create race — fall through to the CAS re-read
      }
    }
    // Cache maintenance happens after the authoritative business commit.
    // A failed re-read must NEVER reject an already admitted business ACK.
    let current;
    try {
      current = await docs.get(key);
    } catch {
      counters.decisionCacheWriteFailures += 1;
      return;
    }
    if (!isJsonRecord(current)) {
      counters.decisionCacheWriteFailures += 1;
      return;
    }
    try {
      await docs.put(key, record, { mustMatchRevision: current.revision });
      counters.decisionCacheWrites += 1;
    } catch {
      counters.decisionCacheWriteFailures += 1;
    }
  }

  /**
   * [#1003 FR09] Durable pin-before-execution in the generic Host document
   * store (create-if-absent CAS). Re-pinning the EXACT approved artifact is
   * idempotent; a different digest under the same pin slot refuses typed —
   * the approved child can never drift.
   */
  async function commitDecisionSourcePin(pinKey, pinRecord) {
    try {
      await docs.put(pinKey, pinRecord, { mustBeAbsent: true });
      counters.promotedPins += 1;
      return;
    } catch {
      const envelope = await docs.get(pinKey);
      const existing = isJsonRecord(envelope) ? envelope.value : undefined;
      if (isJsonRecord(existing) && existing.artifactId === pinRecord.artifactId
        && existing.contentDigest === pinRecord.contentDigest) {
        return;
      }
      throw new CentralAdmissionError(
        'DECISION_SOURCE_PIN_CONFLICT',
        `the promoted-child pin ${pinKey} is already committed for a different artifact digest; the approved child cannot drift`,
      );
    }
  }

  /**
   * [#1003 FR08 general + FR09 + FR12] The K-owned decision-source
   * composition for ONE turn (inside its lane, before central admission).
   *
   * The legs are assembled lazily in the retained frozen order so an
   * earlier match never consults a later source: the deterministic rule
   * leg first, then the exact-cache leg (FR08 currentness: the lookup key
   * pins the current dependency material; FR12 applicability: the retained
   * S evidence check plus promoted-producer invalidation gate every hit),
   * then the governed promoted leg (FR09: sealed approval identity, S
   * eligibility, durable K pin before the candidate proceeds). S's
   * resolveRetainedDecision is the ONLY ordering authority. Only when every
   * declared cheap leg missed does the bounded harness fallback run —
   * exactly ONE trusted ModelPort turn through the sealed composite
   * model-decision surface with its honest measured(1) evidence.
   *
   * Returns {resolved, pendingWrite} for the UNCHANGED central admission,
   * or {terminal, evidence} for a typed zero-effect stop. The exact-cache
   * write is deferred: it happens only after the authoritative state
   * commit, so a candidate denied by any admission gate is never cached.
   */
  async function resolveDecisionSourceTurn({ wired, request, context, control, target, workflowInstanceId, latch }) {
    const turnId = deriveDurableControlTurnId(target, occurrenceTurnOf(request));
    let canonicalInput;
    try {
      canonicalInput = canonicalizeJson(request.input ?? {});
    } catch (error) {
      throw new CentralAdmissionError(
        'DECISION_SOURCE_INPUT_INVALID',
        `decision-source input must be canonical JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!isJsonRecord(canonicalInput)) {
      throw new CentralAdmissionError('DECISION_SOURCE_INPUT_INVALID', 'decision-source input must be a JSON object');
    }
    const predicateInput = () => prepareDomainPredicateEvaluationInput({
      context,
      event: { type: 'decision-source-input', payload: canonicalInput },
    });

    // ---- current dependency material (exact-cache currentness) ----
    let dependencies;
    let cacheKey;
    if (wired.cacheDeps !== undefined) {
      dependencies = {};
      for (const field of wired.cacheDeps) {
        const value = context[field];
        if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
          throw new CentralAdmissionError(
            'DECISION_SOURCE_DEPENDENCY_INVALID',
            `decision ${wired.decisionId} dependency field ${field} is not a bounded revision string`,
          );
        }
        dependencies[field] = value === undefined ? '' : value;
      }
      cacheKey = `${DECISION_CACHE_PREFIX}${workflowInstanceId}:${wired.decisionId}`
        + `:${sha256.digestUtf8(canonicalJsonStringify(canonicalInput))}`
        + `:${sha256.digestUtf8(canonicalJsonStringify(dependencies))}`;
    }

    const observations = {};
    const legMissed = (name) => observations[name] === undefined || observations[name].status === 'miss';
    let cacheRead = 'disabled';
    let promotedArtifact;
    let harnessEnvelope;

    // ---- deterministic rule leg ----
    if (wired.ruleLeg !== undefined) {
      let projectable = true;
      const payload = {};
      for (const [payloadKey, inputKey] of Object.entries(wired.payloadFromInput)) {
        if (!hasOwn(canonicalInput, inputKey)) {
          projectable = false;
          break;
        }
        payload[payloadKey] = canonicalInput[inputKey];
      }
      if (projectable && evaluateDomainPredicate(wired.ruleLeg.when, predicateInput())) {
        observations.rule = {
          status: 'match',
          candidate: {
            decision: { outcome: wired.ruleLeg.outcome },
            event: { type: wired.ruleLeg.eventType, payload },
          },
        };
      } else {
        observations.rule = { status: 'miss' };
      }
    }

    // ---- exact-cache leg (FR08 currentness + FR12 applicability) ----
    if (wired.cacheDeps !== undefined && legMissed('rule')) {
      cacheRead = 'miss';
      let record;
      try {
        const envelope = await docs.get(cacheKey);
        record = isJsonRecord(envelope) ? envelope.value : undefined;
      } catch {
        record = undefined;
      }
      if (isJsonRecord(record) && isJsonRecord(record.candidate) && isJsonRecord(record.provenance)) {
        let applicable = true;
        try {
          sdkEndpoint.checkEvidenceApplicability(
            { packageId: record.provenance.packageId, baselineDigest: record.provenance.baselineDigest },
            { packageId: decisionScopePackage, baselineDigest: decisionScopeDigest },
          );
        } catch {
          applicable = false;
        }
        // Producer invalidation: a cached decision produced by a promoted
        // artifact is only current while that exact artifact is still the
        // sealed approval and not revoked — a retired producer can never
        // replay its old result through the cache.
        if (applicable && isJsonRecord(record.producedBy) && record.producedBy.kind === 'promoted-artifact') {
          const approved = isJsonRecord(businessEndpoint.promotedArtifacts)
            ? businessEndpoint.promotedArtifacts[record.producedBy.artifactId]
            : undefined;
          if (!isJsonRecord(approved) || approved.contentDigest !== record.producedBy.contentDigest
            || approved.revoked === true) {
            applicable = false;
          }
        }
        if (applicable) {
          observations['exact-cache'] = { status: 'match', exactCurrent: true, candidate: record.candidate };
          cacheRead = 'hit';
        }
      }
    }

    // ---- governed promoted-child leg (FR09) ----
    if (wired.promoted !== undefined && legMissed('rule') && legMissed('exact-cache')) {
      if (evaluateDomainPredicate(wired.promoted.when, predicateInput())) {
        const approved = businessEndpoint.promotedArtifacts[wired.promoted.artifactId];
        const approvedView = {
          artifactId: approved.artifactId,
          contentDigest: approved.contentDigest,
          ...(approved.revoked !== undefined ? { revoked: approved.revoked } : {}),
          ...(approved.applicable !== undefined ? { applicable: approved.applicable } : {}),
          ...(approved.compatible !== undefined ? { compatible: approved.compatible } : {}),
        };
        const requested = { artifactId: wired.promoted.artifactId, contentDigest: wired.promoted.contentDigest };
        let child;
        try {
          child = sdkEndpoint.selectPromotedChild({ requested, approved: approvedView, pinCommitted: false });
        } catch (error) {
          if (!(isJsonRecord(error) && error.code === 'SDK_CHILD_PIN_REQUIRED')) throw error;
        }
        if (child === undefined) {
          const pinKey = `${PROMOTED_PIN_PREFIX}${workflowInstanceId}:${wired.decisionId}`;
          await commitDecisionSourcePin(pinKey, {
            artifactId: requested.artifactId,
            contentDigest: requested.contentDigest,
            pinnedAtTurn: turnId,
            pinnedAt: clock(),
          });
          sdkEndpoint.selectPromotedChild({ requested, approved: approvedView, pinCommitted: true });
        }
        observations['promoted-subworkflow'] = {
          status: 'match',
          artifactCurrent: true,
          candidate: wired.promoted.candidate,
        };
        promotedArtifact = { kind: 'promoted-artifact', artifactId: requested.artifactId, contentDigest: requested.contentDigest };
      } else {
        observations['promoted-subworkflow'] = { status: 'miss' };
      }
    }

    // ---- S selection over the declared frozen ordering ----
    let selected;
    try {
      selected = sdkEndpoint.resolveDecisionSource({ decisionId: wired.decisionId, observations });
    } catch (error) {
      if (!(wired.harness !== undefined && isJsonRecord(error) && error.code === 'SDK_DECISION_HARNESS_UNCONFIGURED')) {
        throw error;
      }
      selected = undefined;
    }

    // ---- bounded harness fallback: exactly ONE trusted ModelPort turn ----
    if (selected === undefined) {
      const declaration = { kind: 'model-decision', id: `${wired.id}:harness`, modelOperation: wired.harness.modelOperation };
      try {
        harnessEnvelope = await sdkEndpoint.interpret(declaration, canonicalInput, context, control);
      } catch (error) {
        if (latch.cancelled) {
          return {
            terminal: { code: 'CANCELLED', step: 1, inFlightTurnDiscarded: true },
            evidence: { modelCallEvidence: { status: 'unmeasured' } },
          };
        }
        throw error;
      }
      if (!isJsonRecord(harnessEnvelope) || !isJsonRecord(harnessEnvelope.structuredDecision)) {
        throw new CentralAdmissionError(
          'DECISION_SOURCE_MODEL_EVIDENCE_INVALID',
          'the harness fallback envelope carries no structured decision; no decision is admitted',
        );
      }
      try {
        trustedStepEvidence(harnessEnvelope);
      } catch (error) {
        throw new CentralAdmissionError(
          'DECISION_SOURCE_MODEL_EVIDENCE_INVALID',
          `the harness fallback did not carry the trusted single-invocation evidence of the Host-bound resolver: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      selected = sdkEndpoint.resolveDecisionSource({
        decisionId: wired.decisionId,
        observations: {
          ...observations,
          'harness-machine': { status: 'match', candidate: harnessEnvelope.structuredDecision },
        },
      });
    }

    const source = selected.selectedSource;
    const resolved = {
      structuredDecision: selected.candidate,
      source,
      llmAvoided: source !== 'harness-machine',
      modelCallEvidence: source === 'harness-machine'
        ? harnessEnvelope.modelCallEvidence
        : { status: 'measured', count: 0, scope: BOUND_PORT_EVIDENCE_SCOPE },
      cacheDisposition: { read: cacheRead },
      telemetry: [],
    };
    // A cache-hit turn writes NOTHING back: the row already carries the
    // original admitted producer record (its source lineage and producedBy
    // identity are the durable ordering truth — relabeling them
    // 'exact-cache' would erase the producer).
    const pendingWrite = wired.cacheDeps === undefined || source === 'exact-cache' ? undefined : {
      key: cacheKey,
      record: {
        version: 1,
        decisionId: wired.decisionId,
        source,
        candidate: selected.candidate,
        provenance: {
          packageId: decisionScopePackage,
          baselineDigest: decisionScopeDigest,
          dependencies,
        },
        ...(promotedArtifact !== undefined && source === 'promoted-subworkflow' ? { producedBy: promotedArtifact } : {}),
        writtenAtTurn: turnId,
      },
    };
    return { resolved, pendingWrite };
  }

  function continuationPolicyFor(rule) {
    const wired = isJsonRecord(rule) ? continuationPolicies.get(rule) : undefined;
    if (wired !== undefined) return wired;
    if (isJsonRecord(rule) && rule.kind === 'model-decision' && hasOwn(rule, 'harness')) {
      throw new CentralAdmissionError(
        'CONTINUATION_DECLARATION_UNVALIDATED',
        'a harness model-decision rule that was never wired at the trusted load boundary cannot run',
      );
    }
    return undefined;
  }

  async function bindGovernance(target, authorityClass) {
    const workflowInstanceId = `${target.workflowId}:${target.instanceKey}`;
    const identity = await computeGovernanceBaselineIdentity({
      domainId: businessEndpoint.domainId,
      governanceId: `governance:${businessEndpoint.policyId}`,
      schemaVersion: '1',
      semantics: businessEndpoint.governanceSemantics,
    }, sha256);
    const body = { identity, semantics: businessEndpoint.governanceSemantics };
    await baselines.putBody(body);
    // [#1006 HF21] The activation-plane runtime authority class rides the ONE
    // existing pin (woven into bindingDigest; validated exact by the store).
    await pinStore.bindPin({ workflowInstanceId, governanceBaseline: identity, ...(authorityClass === undefined ? {} : { authorityClass }) });
    return body;
  }

  /**
   * [#1003 NF06 OBSERVATIONAL_OPTIONAL] The K-owned authoritative append of
   * ONE data-only decision receipt at the exact durable control turn key,
   * invoked strictly AFTER the admitted business commit. K alone decides
   * when/why a record may exist; S supplies only the redacted data-only
   * projection of the verified outcome; the generic Host CAS create is the
   * only persistence. Every failure is a SEPARATE typed observation outcome:
   * nothing here may throw out of the occurrence, rewrite the admitted
   * truth, or claim 'recorded' without a physically accepted create. A
   * create that loses to an existing record re-reads it INSIDE this
   * boundary: the re-read and the identity comparison are themselves
   * bounded — a Host read failure during the replay check is a typed
   * not_recorded observation, never a business failure [#1055 R1 P1-02];
   * the SAME turn's own identity (turn + declaration + projected record,
   * minus the volatile recordedAt) is an idempotent replay; anything else is
   * a typed conflict that never overwrites the stored record. The envelope
   * freezes the recording intent's reader scope, so every read authorizes
   * against THIS record's own scope — never the union of all policies'
   * roles [#1055 R1 P1-01].
   */
  async function appendObservationalDecisionReceipt({ request, target, workflowInstanceId, binding, declaration, resolved }) {
    const receiptPolicy = decisionReceiptPolicies.get(request.intentType);
    if (receiptPolicy === undefined || receiptPolicy.durability !== 'observational-optional') {
      return undefined;
    }
    if (typeof sdkEndpoint?.projectDecisionReceipt !== 'function') {
      return {
        status: 'not_recorded',
        error: { code: 'SDK_DECISION_RECEIPT_PROJECTION_UNAVAILABLE', message: 'the selected Standard SDK exposes no decision-receipt projection endpoint' },
      };
    }
    const turnId = deriveDurableControlTurnId(target, occurrenceTurnOf(request));
    const declarationIdentity = isJsonRecord(declaration)
      ? {
        ruleId: typeof declaration.id === 'string' ? declaration.id : binding.ruleId,
        ...(typeof declaration.declarationDigest === 'string' ? { declarationDigest: declaration.declarationDigest } : {}),
      }
      : { ruleId: binding.ruleId };
    let projected;
    try {
      projected = await sdkEndpoint.projectDecisionReceipt({
        turnId,
        workflowInstanceId,
        declaration: declarationIdentity,
        resolved,
        durability: 'observational-optional',
      });
    } catch (error) {
      return {
        status: 'not_recorded',
        error: {
          code: typeof error?.code === 'string' ? error.code : 'DECISION_RECEIPT_PROJECTION_FAILED',
          message: error instanceof Error ? error.message : String(error),
        },
      };
    }
    const envelope = {
      kernelModuleSha256: moduleIdentity.moduleSha256,
      // [#1055 R1 P1-01] The per-record frozen read scope: the readerRoles of
      // THE intent that records THIS receipt, snapshotted at append time.
      // getDecisionReceipt authorizes against this scope alone — a reader
      // declared by a different intent's policy never gains authority over
      // this record, and the key alone confers no read authority.
      readerRoles: snapshotJson(receiptPolicy.readerRoles ?? []),
      record: snapshotJson({
        projected,
        occurrence: { messageId: request.messageId, workflowInstanceId },
        attribution: attribution(),
        recordedAt: clock(),
      }),
    };
    counters.decisionReceiptAppends += 1;
    const key = docKeys.decisionReceipt(turnId);
    try {
      await docs.put(key, envelope, { mustBeAbsent: true });
      return { status: 'recorded', receiptKey: key, durability: 'observational-optional' };
    } catch (error) {
      if (typeof error === 'object' && error !== null && error.code === 'HOST_KEY_EXISTS') {
        // [#1055 R1 P1-02] The re-read and the identity comparison live
        // INSIDE the optional observation boundary: a Host read failure,
        // an unreadable winner or a canonicalization exception during the
        // replay check is a separate typed not_recorded outcome — it can
        // never fail the already-committed business ACK.
        try {
          const winner = await docs.get(key);
          if (winner !== null && isJsonRecord(winner.value) && decisionReceiptIdentity(winner.value) === decisionReceiptIdentity(envelope)) {
            return { status: 'recorded', receiptKey: key, durability: 'observational-optional', idempotentReplay: true };
          }
          return {
            status: 'not_recorded',
            error: { code: 'DECISION_RECEIPT_CONFLICT', message: `a different record already occupies the decision-receipt key ${key}; the conflicting record is never overwritten` },
          };
        } catch (replayError) {
          return {
            status: 'not_recorded',
            error: {
              code: typeof replayError?.code === 'string' ? replayError.code : 'DECISION_RECEIPT_REPLAY_CHECK_FAILED',
              message: replayError instanceof Error ? replayError.message : String(replayError),
            },
          };
        }
      }
      return {
        status: 'not_recorded',
        error: {
          code: typeof error?.code === 'string' ? error.code : 'DECISION_RECEIPT_APPEND_FAILED',
          message: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }

  /**
   * [v0.10 K02 anchor 3] The same-CAS original-receipt ladder of ONE
   * occurrence, consulted INSIDE the occurrence lane BEFORE the
   * history/disposition ladder: ring (THIS snapshot's durableOriginalReceipts
   * — single-snapshot discipline: adjudication and the later commit CAS share
   * one snapshot) → independent durable archive → undefined (not admitted;
   * the caller may admit). An identity match is an idempotent replay of the
   * EXACT ORIGINAL receipt; a different identity under the same turn id
   * refuses typed BEFORE any admission activity. A legacy/unreadable envelope
   * fails closed typed; an archive READ fault fails closed typed for THIS
   * turn (a faulting store is not a policy wedge).
   */
  async function readDurableOriginalReceiptOrReplay(snapshot, turnId, identity, request, target, workflowInstanceId, inputDigest) {
    const ring = isJsonRecord(snapshot.durableOriginalReceipts) ? snapshot.durableOriginalReceipts : {};
    const storedRing = ring[turnId];
    if (storedRing !== undefined) {
      return adjudicateDurableOriginalReceipt(storedRing, turnId, identity, request, target, workflowInstanceId, inputDigest);
    }
    let archive;
    try {
      archive = await docs.get(docKeys.receiptArchive(turnId));
    } catch (error) {
      throw new CentralAdmissionError(
        'K02_TURN_RECEIPT_STORE_FAULT',
        `the archived original receipt of turn ${turnId} is unreadable; fail closed for this turn (${error instanceof Error ? error.message : String(error)})`,
      );
    }
    if (archive !== null) {
      return adjudicateDurableOriginalReceipt(archive.value, turnId, identity, request, target, workflowInstanceId, inputDigest);
    }
    return undefined;
  }

  /**
   * [v0.10 K02] Adjudicate ONE stored original-receipt envelope against this
   * occurrence's identity: legacy shape → typed fail-closed (no pre-1.0
   * migration); identity match → idempotent replay of the EXACT ORIGINAL
   * acknowledged receipt (never a pseudo-receipt re-derived from the newest
   * snapshot); identity mismatch → typed input/intent conflict. The replay
   * best-effort HEALS the observational turn-disposition record (the
   * archive-only role since the splice); the heal never falsifies the
   * original and never fails the replay ACK.
   */
  async function adjudicateDurableOriginalReceipt(envelope, turnId, identity, request, target, workflowInstanceId, inputDigest) {
    if (!isJsonRecord(envelope)
      || envelope.carrierVersion !== K02_CARRIER_VERSION
      || typeof envelope.identity !== 'string'
      || !isJsonRecord(envelope.receipt)) {
      throw new CentralAdmissionError(
        'K02_TURN_RECEIPT_LEGACY_UNREADABLE',
        `the durable original receipt of turn ${turnId} carries no readable v1 envelope; fail closed, no pre-1.0 migration`,
      );
    }
    if (envelope.identity !== identity) {
      const changedIntent = typeof envelope.intentType === 'string' && envelope.intentType !== request.intentType;
      throw new CentralAdmissionError(
        changedIntent ? 'K02_TURN_RECEIPT_INTENT_CONFLICT' : 'K02_TURN_RECEIPT_INPUT_CONFLICT',
        `turn ${turnId} is already durably admitted with a different ${changedIntent ? 'intentType' : 'canonical input'}; one source is exactly one turn — the original receipt stands`,
      );
    }
    counters.durableOriginalReceiptReplays += 1;
    const replayed = { ...envelope.receipt, idempotentReplay: true };
    const healTurn = isJsonRecord(envelope.turn) ? envelope.turn : undefined;
    const receipt = { ...replayed };
    if (healTurn !== undefined) {
      try {
        const healedDisposition = await writeTurnDisposition(turnId, healTurn, request, target, replayed, inputDigest);
        if (healedDisposition !== undefined) receipt.turnDisposition = healedDisposition;
      } catch {
        // the observational heal never fails the replay
      }
    }
    safeObserve(receipt);
    return receipt;
  }

  /**
   * [#1062 shared seam] Read the turn disposition of ONE non-message turn
   * inside the occurrence lane. An identity-matching record is an
   * idempotent replay of the already-admitted turn (zero new activity); a
   * record with a different identity under the same turn id refuses typed
   * BEFORE any admission — one source is exactly one turn, whatever intent
   * a later submission claims for it.
   */
  async function readTurnDispositionOrReplay(turnId, turn, request, target, inputDigest) {
    let envelope;
    try {
      envelope = await docs.get(docKeys.turnDisposition(turnId));
    } catch {
      return undefined; // an unreadable disposition cannot veto the turn
    }
    if (envelope === null || !isJsonRecord(envelope.value)) return undefined;
    const stored = envelope.value;
    if (!isJsonRecord(stored.receipt) || typeof stored.identity !== 'string') return undefined;
    // [v0.10 K02] Identity is input-complete and deployment-scoped; the
    // disposition record is the ARCHIVE-ONLY observational ladder since the
    // splice (the same-CAS receipt answers first).
    const identity = turnDispositionIdentity(deploymentScope, target, turn, request.intentType, inputDigest);
    if (stored.identity !== identity) {
      throw new CentralAdmissionError(
        'ADMISSION_TURN_DISPOSITION_CONFLICT',
        `turn ${turnId} already has a durably admitted disposition with a different identity; one source is exactly one turn`,
      );
    }
    counters.turnDispositionReplays += 1;
    const replayed = { ...stored.receipt, idempotentReplay: true };
    safeObserve(replayed);
    return replayed;
  }

  /**
   * [#1062 shared seam] Best-effort create of the turn disposition AFTER the
   * authoritative state CAS — a typed observation that never fails the
   * already-committed business ACK and never claims cross-document
   * atomicity. A create that loses to an existing record re-reads it
   * INSIDE this boundary (identical identity → idempotent; different →
   * typed conflict observation, the stored record is never overwritten).
   */
  async function writeTurnDisposition(turnId, turn, request, target, receipt, inputDigest) {
    // [v0.10 K02] The pinned module SHA rides the envelope as buildIdentity
    // (identity stable across releases); the disposition record itself is
    // the ARCHIVE-ONLY observation of the admission (the same-CAS receipt
    // owns the once-only truth).
    const identity = turnDispositionIdentity(deploymentScope, target, turn, request.intentType, inputDigest);
    const envelope = {
      pinVersion: 1,
      identity,
      ...(deploymentScope === undefined ? {} : { buildIdentity: { kernelModuleSha256: moduleIdentity.moduleSha256 } }),
      turn: snapshotJson(turn),
      intentType: request.intentType,
      receipt: snapshotJson(receipt),
    };
    try {
      await docs.put(docKeys.turnDisposition(turnId), envelope, { mustBeAbsent: true });
      counters.turnDispositions += 1;
      return { status: 'recorded' };
    } catch (error) {
      if (typeof error === 'object' && error !== null && error.code === 'HOST_KEY_EXISTS') {
        try {
          const winner = await docs.get(docKeys.turnDisposition(turnId));
          const winnerIdentity = winner !== null && isJsonRecord(winner.value)
            && typeof winner.value.identity === 'string' ? winner.value.identity : undefined;
          if (winnerIdentity === identity) {
            return { status: 'recorded', idempotentReplay: true };
          }
          return {
            status: 'conflict',
            error: { code: 'ADMISSION_TURN_DISPOSITION_CONFLICT', message: `a different admitted disposition already occupies the turn key ${String(turnId)}` },
          };
        } catch {
          // fall through to the honest not_recorded report below
        }
      }
      return {
        status: 'not_recorded',
        error: {
          code: typeof error?.code === 'string' ? error.code : 'TURN_DISPOSITION_APPEND_FAILED',
          message: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }

  /**
   * [#1066 R1 P1-B] The same-CAS admission-history replay of ONE non-message
   * turn, consulted when the independent turn-disposition record is absent
   * (the crash window between the authoritative state CAS and the
   * best-effort disposition create). The instance document committed by
   * that very state CAS carries the turn's admission identity, so the
   * re-submitted turn is recognized as already admitted HERE — with zero
   * new State/Journal/Effect activity — even where the business state
   * machine would legally re-admit it (self-loop). A different identity
   * under the same turn id refuses typed before any admission, exactly
   * like the disposition record itself does. The replay also best-effort
   * heals the lost disposition observation; the stored receipt is this
   * reconstructed replay truth, never invented business detail.
   */
  async function admittedControlTurnHistoryReplay(snapshot, turnId, turn, request, target, workflowInstanceId, inputDigest) {
    const history = Array.isArray(snapshot.admittedControlTurns) ? snapshot.admittedControlTurns : [];
    const admission = history.find((entry) => isJsonRecord(entry) && entry.turnId === turnId);
    if (admission === undefined) return undefined;
    const identity = turnDispositionIdentity(deploymentScope, target, turn, request.intentType, inputDigest);
    if (admission.identity !== identity) {
      throw new CentralAdmissionError(
        'ADMISSION_TURN_DISPOSITION_CONFLICT',
        `turn ${turnId} is already admitted in this instance's committed admission history with a different identity; one source is exactly one turn`,
      );
    }
    counters.turnAdmissionReplays += 1;
    const replay = {
      status: 'admitted',
      idempotentReplay: true,
      turnAdmission: { turnId, admittedAtStateRevision: admission.stateRevision },
      instance: outwardInstanceSnapshot(snapshot),
      occurrence: { messageId: request.messageId, workflowInstanceId },
      attribution: attribution(),
    };
    // Heal the lost disposition observation (best-effort; the outcome rides
    // the replay receipt as an independent field and never fails it).
    const healedDisposition = await writeTurnDisposition(turnId, turn, request, target, replay, inputDigest);
    const receipt = { ...replay, ...(healedDisposition === undefined ? {} : { turnDisposition: healedDisposition }) };
    safeObserve(receipt);
    return receipt;
  }

  /**
   * [#1003 NF06] Authorized read of ONE persisted decision receipt through
   * the same K authority that appended it. THE authorization decision is the
   * record's OWN frozen reader scope — the readerRoles of the intent that
   * recorded THIS receipt, snapshotted into the envelope at append time
   * [#1055 R1 P1-01]: a role declared by a DIFFERENT intent's receiptPolicy
   * (even one wired in the same closure) confers no authority over this
   * record, so a reader of an unprivileged intent can never read a more
   * sensitive intent's committed receipt. A coarse pre-filter (the caller
   * must hold a role declared by SOME wired receiptPolicy) refuses obvious
   * non-readers before the store is touched, but it is only a NECESSARY
   * condition — never sufficient. A record pinned to different Kernel
   * module bytes refuses typed (no silent cross-version replay), and an
   * absent record stays an honest null — it is never an error and never a
   * claim.
   */
  async function getDecisionReceipt(request) {
    if (!isJsonRecord(request)) {
      throw new CentralAdmissionError('DECISION_RECEIPT_READ_INVALID', 'a decision-receipt read must be a record {target, messageId, caller}');
    }
    const target = request.target;
    const messageId = request.messageId;
    if (!isJsonRecord(target) || typeof target.workflowId !== 'string' || typeof target.instanceKey !== 'string') {
      throw new CentralAdmissionError('DECISION_RECEIPT_READ_INVALID', 'a decision-receipt read requires a workflow target {workflowId, instanceKey}');
    }
    if (typeof messageId !== 'string' || messageId.length === 0) {
      throw new CentralAdmissionError('DECISION_RECEIPT_READ_INVALID', 'a decision-receipt read requires a non-empty messageId');
    }
    const caller = isJsonRecord(request.caller) ? request.caller : { role: 'anonymous' };
    const callerRoles = Array.isArray(caller.roles) && caller.roles.every((role) => typeof role === 'string')
      ? caller.roles
      : typeof caller.role === 'string' ? [caller.role] : [];
    // Coarse pre-filter only (necessary, never sufficient): refuse callers
    // holding no declared receipt-reader role at all before the store is
    // touched. The AUTHORITATIVE gate is the per-record frozen scope below.
    const declaredAnywhere = new Set();
    for (const policy of decisionReceiptPolicies.values()) {
      for (const role of policy.readerRoles ?? []) declaredAnywhere.add(role);
    }
    if (declaredAnywhere.size === 0 || !callerRoles.some((role) => declaredAnywhere.has(role))) {
      throw new CentralAdmissionError(
        'DECISION_RECEIPT_READ_UNAUTHORIZED',
        'the authenticated caller holds none of the Business-declared decision-receipt reader roles; the record is not readable',
      );
    }
    const turnId = deriveDurableControlTurnId(target, { kind: 'message', sourceMessageId: messageId });
    const doc = await docs.get(docKeys.decisionReceipt(turnId));
    if (doc === null) return null;
    const envelope = doc.value;
    if (!isJsonRecord(envelope) || envelope.kernelModuleSha256 !== moduleIdentity.moduleSha256) {
      throw new CentralAdmissionError(
        'DECISION_RECEIPT_KERNEL_MISMATCH',
        `the decision receipt of turn ${turnId} is pinned to different kernel module bytes; typed code unavailability — no silent cross-version replay`,
      );
    }
    // [#1055 R1 P1-01] The authoritative per-record gate, checked BEFORE any
    // record byte is released: the caller must hold one of the readerRoles
    // frozen into THIS envelope by the intent that recorded it. A record
    // carrying no valid frozen scope is not readable by anyone (fail closed).
    const recordScope = envelope.readerRoles;
    if (!Array.isArray(recordScope) || recordScope.length === 0 || !recordScope.every((role) => typeof role === 'string' && role.length > 0)) {
      throw new CentralAdmissionError(
        'DECISION_RECEIPT_READ_UNAUTHORIZED',
        `the decision receipt of turn ${turnId} carries no frozen reader scope; it is not readable by any caller`,
      );
    }
    if (!callerRoles.some((role) => recordScope.includes(role))) {
      throw new CentralAdmissionError(
        'DECISION_RECEIPT_READ_UNAUTHORIZED',
        `the authenticated caller holds none of the reader roles the recording intent froze for the decision receipt of turn ${turnId}; the record is not readable`,
      );
    }
    return snapshotJson(envelope.record);
  }

  const effectTools = {
    resolve(effectType) {
      const binding = businessEndpoint.effectBindings?.[effectType];
      if (binding === undefined) return undefined;
      return {
        effectType,
        effectSemantics: binding.semantics,
        // [v0.10 C01 #1177] The binding's external routing config, validated
        // here so a malformed declaration refuses at resolve time — before
        // any journal begin. `resource` rides along so the minted permit is
        // scoped to the declared capability key and operation set.
        external: normalizeExternalEffectConfig(binding.external),
        resource: isJsonRecord(binding.resource) ? binding.resource : null,
      };
    },
    async execute(request) {
      counters.effectDispatches += 1;
      const binding = businessEndpoint.effectBindings[request.binding.effectType];
      const externalConfig = normalizeExternalEffectConfig(binding?.external);
      // [v0.10 C01 #1177 R1 P1-1] The exact per-effect dispatch attempt this
      // executor call represents (the kernel passes its journaled attempt).
      const attempt = Number.isSafeInteger(request.attempt) ? request.attempt : 1;
      // The K-issued ADDRESS CONTEXT of this effect's authority documents: the
      // gate re-reads exactly these keys - never a hardcoded legacy family -
      // so a scoped deployment is addressed under its own injective grammar.
      const authorityContext = externalConfig === null ? null : {
        effectId: request.effectId,
        durableControlTurnId: request.durableControlTurnId,
        businessPackageId: businessEndpoint.packageId,
        keys: {
          permit: docKeys.effectPermit(request.effectId),
          journal: docKeys.journal(request.effectId),
          fence: docKeys.admissionFence(request.target),
          dispatchClaim: docKeys.effectDispatchClaim(request.effectId, attempt),
        },
        attempt,
      };
      // Atomic per-(effectId,attempt) claim: ONE effect grounds at most ONE
      // adapter invocation, enforced by a physical mustBeAbsent CAS before
      // any raw resources call. A refusal is fail-closed typed and carries NO
      // zero-external-effect proof (an earlier invocation may have landed).
      // Generic read calls preceding the external effect cannot consume its
      // one durable claim. Only operations in this effect's K-minted permit
      // scope may claim; a foreign external adapter still fails at the Host gate.
      const isPermittedExternalCall = (resourceKey, operation) =>
        authorityContext !== null
        && isJsonRecord(binding?.resource)
        && resourceKey === binding.resource.key
        && (operation === binding.resource.operation || externalConfig.operations.includes(operation));
      const claimExternalDispatch = async () => {
        if (authorityContext === null) return;
        try {
          await docs.put(
            authorityContext.keys.dispatchClaim,
            {
              pinVersion: 1,
              effectId: authorityContext.effectId,
              durableControlTurnId: authorityContext.durableControlTurnId,
              businessPackageId: authorityContext.businessPackageId,
              attempt: authorityContext.attempt,
              claimedAt: clock(),
            },
            { mustBeAbsent: true },
          );
          counters.effectDispatchClaims += 1;
        } catch (error) {
          counters.effectDispatchClaimRefusals += 1;
          // The attest stays UNMARKED (preHandlerRefusal remains null): an
          // ambiguous or repeated dispatch claim proves nothing about the
          // external world, so the #1108 zero-effect policy must not act on it.
          if (isHostWriteConflict(error)) {
            throw new CentralAdmissionError(
              'ADMISSION_EFFECT_DISPATCH_CLAIM_CONFLICT',
              `[ADMISSION_EFFECT_DISPATCH_CLAIM_CONFLICT] effect ${request.effectId} already grounded an external dispatch attempt ${authorityContext.attempt}; one effect never dispatches twice`,
            );
          }
          throw new CentralAdmissionError(
            'ADMISSION_EFFECT_DISPATCH_CLAIM_CONFLICT',
            `[ADMISSION_EFFECT_DISPATCH_CLAIM_CONFLICT] the external dispatch claim for ${request.effectId} is ambiguous: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      };
      // [#1108 K01 R1 P1 / R2 P1] The Business handler's ONLY external-mutation
      // authority is the physical resources port (v0.8 Host contract). The
      // dispatch probe records whether the handler ever invoked it, and every
      // invocation carries a fresh kernel-minted ATTESTATION object (an extra
      // dedicated argument, never part of the payload or the handler
      // context): the trusted host dispatcher marks it synchronously BEFORE
      // throwing one of its OWN pre-handler refusals. A thrown error's code
      // string proves nothing (a post-mutation throw can carry any code), so
      // the attestation channel is the ONLY dispatcher-side proof. The probe
      // object itself is created by this kernel's executeEffectIntents —
      // marking `supported` here is what makes the proof kernel-owned rather
      // than caller-asserted.
      const probe = request.externalDispatchProbe;
      const rawResources = hostPorts.resources;
      // A missing/non-object resources port passes through VERBATIM: the
      // Business handler's own port guard (and its typed failure) keeps its
      // exact pre-existing shape; nothing is wrapped, nothing is invented.
      const handlerResources = (probe === undefined || probe === null || typeof probe !== 'object'
        || rawResources === null || typeof rawResources !== 'object')
        ? rawResources
          : {
            call: async (resourceKey, operation, payload) => {
              // Mint and register the attest BEFORE the call: a synchronous
              // throw below still leaves the (unmarked) attestation in the
              // probe, which fails the all-attested proof — fail-closed.
              const attest = { preHandlerRefusal: null };
              if (authorityContext !== null) {
                // [v0.10 C01 #1177] The kernel-issued live permit CLAIM rides
                // the attest channel — the only channel a trusted host
                // dispatcher reads. The durable permit document remains the
                // authority the host gate re-reads; a claim alone proves
                // nothing and a Business handler can neither mint nor strip
                // this channel.
                attest.effectPermit = { ...authorityContext };
              }
              probe.dispatchAttests.push(attest);
              probe.invoked = true;
              if (isPermittedExternalCall(resourceKey, operation)) await claimExternalDispatch();
              return rawResources.call(resourceKey, operation, payload, attest);
            },
            ...(typeof rawResources.callScoped === 'function'
              ? {
                  callScoped: async (scopeId, resourceKey, operation, payload) => {
                    const attest = { preHandlerRefusal: null };
                    if (authorityContext !== null) {
                      attest.effectPermit = { ...authorityContext };
                    }
                    probe.dispatchAttests.push(attest);
                    probe.invoked = true;
                    if (isPermittedExternalCall(resourceKey, operation)) await claimExternalDispatch();
                    return rawResources.callScoped(scopeId, resourceKey, operation, payload, attest);
                  },
                }
              : {}),
          };
      if (probe !== undefined && probe !== null && typeof probe === 'object') {
        probe.supported = true;
      }
      return binding.handler({
        input: request.input,
        effectId: request.effectId,
        durableControlTurnId: request.durableControlTurnId,
        operationOrdinal: request.operationOrdinal,
        idempotencyKey: request.idempotencyKey,
        logicalTime: request.logicalTime,
        target: request.target,
        resources: handlerResources,
      });
    },
  };

  // [v0.10 C01 #1177] The K-issued live external Effect Permit — the durable
  // authority half of the selected K→C external Effect Operation. The kernel
  // mints ONE permit document per external effect dispatch (mustBeAbsent
  // create, same-turn identical replay reuses the live original), scoped to
  // the exact effectId/turn/target/business/capability/operation set with a
  // bounded logical expiry, and consumes it (exact-revision CAS) as soon as
  // the dispatch settles. The trusted Host gate re-reads THIS document —
  // plus the journal `started` record and the held admission fence — before
  // any adapter invocation: a permit is never a bearer token, and only the
  // kernel's own attest channel can even CLAIM one.
  const effectPermitAdmin = {
    async mint(spec) {
      const key = docKeys.effectPermit(spec.effectId);
      const value = {
        pinVersion: 1,
        state: 'live',
        effectId: spec.effectId,
        durableControlTurnId: spec.turnId,
        effectType: spec.effectType,
        effectSemantics: spec.effectSemantics,
        businessPackageId: businessEndpoint.packageId,
        target: { workflowId: spec.target.workflowId, instanceKey: spec.target.instanceKey },
        capabilityKey: spec.resource !== null && typeof spec.resource.key === 'string' ? spec.resource.key : null,
        operations: [
          ...(spec.resource !== null && typeof spec.resource.operation === 'string' ? [spec.resource.operation] : []),
          ...spec.external.operations,
        ],
        awaitPolicy: spec.external.awaitPolicy,
        attempt: spec.attempt,
        nonce: sha256.digestUtf8(`${spec.effectId}#${spec.attempt}#${spec.issuedAt}`),
        issuedAt: spec.issuedAt,
        expiresAt: new Date(Date.parse(spec.issuedAt) + spec.external.permitTtlMs).toISOString(),
      };
      let written;
      try {
        written = await docs.put(key, value, { mustBeAbsent: true });
      } catch (error) {
        if (isHostWriteConflict(error)) {
          // The same-turn crash-recovery replay of THIS live permit: an
          // identical live original is reused (its exact revision returned);
          // anything else (consumed, drifted, foreign) refuses typed.
          const existing = await docs.get(key);
          const candidate = existing !== null && isJsonRecord(existing.value) ? existing.value : null;
          const identical = candidate !== null
            && candidate.state === 'live'
            && candidate.durableControlTurnId === spec.turnId
            && candidate.effectType === spec.effectType
            && candidate.attempt === spec.attempt;
          if (!identical) {
            throw new CentralAdmissionError(
              'ADMISSION_EFFECT_PERMIT_CONFLICT',
              `effect permit ${spec.effectId} already exists and is not this dispatch's live original`,
            );
          }
          return { revision: existing.revision };
        }
        throw error;
      }
      counters.effectPermitsMinted += 1;
      return { revision: written.revision };
    },
    async consume(effectId, revision) {
      const doc = await docs.get(docKeys.effectPermit(effectId));
      if (doc === null || !isJsonRecord(doc.value) || doc.value.state !== 'live') {
        throw new CentralAdmissionError(
          'ADMISSION_EFFECT_PERMIT_CONFLICT',
          `effect permit ${effectId} is not live for consumption`,
        );
      }
      await docs.put(
        docKeys.effectPermit(effectId),
        { ...doc.value, state: 'consumed' },
        { mustMatchRevision: revision },
      );
      counters.effectPermitsConsumed += 1;
    },
  };

  // [T-C, V08-ABI-C01-N7b] Observation is OPTIONAL and best-effort: a
  // failing observer never mutates the authoritative occurrence (the
  // receipt side-channel is not an authority path).
  function safeObserve(receipt) {
    if (observe === undefined) return;
    try {
      observe(receipt);
    } catch {
      // Observer failures are deliberately swallowed: the occurrence's
      // admission/journal/state/terminal facts are already durable.
    }
  }

  async function openInstance(request) {
    const target = request.target;
    // [#1006 HF21] The authority class reaches the activation boundary ONLY
    // through the trusted Host genesis seam (provisionGenesis); it is exact-
    // validated by the pin store before any durable write.
    const authorityClass = request?.authorityClass;
    const snapshot = await engine.createInstance({
      address: target,
      correlationId: request.correlationId ?? `corr:${target.instanceKey}`,
      packageId: businessEndpoint.packageId,
      initialState: {
        stateKey: businessEndpoint.initialStateKey,
        context: { ...businessEndpoint.initialContext, ...(request.initialContext ?? {}) },
      },
    });
    await bindGovernance(target, authorityClass);
    // [#1063 HF20] Genesis answers with the OUTWARD snapshot: the seeded
    // observation window is internal carrier truth, readable only through
    // the protected mutation-observation read.
    return outwardInstanceSnapshot(snapshot);
  }

  /**
   * [#1003 FR07-KH2, B3] A continuation/cancellation terminal: the occurrence
   * stopped BEFORE central admission, so no State, Journal or Effect exists.
   */
  function terminatedReceipt(request, workflowInstanceId, terminal, resolver) {
    const receipt = {
      status: 'terminated',
      terminal,
      ...(resolver === undefined ? {} : { resolver }),
      occurrence: { messageId: request.messageId, workflowInstanceId },
      attribution: attribution(),
    };
    safeObserve(receipt);
    return receipt;
  }

  /**
   * `control` is the optional protected, request-scoped occurrence control
   * the H-authenticated gateway supplies (never intent data): currently its
   * cancellation `signal` only. K owns the latch it drives.
   */
  async function submitOccurrence(request, control) {
    const latch = createCancellationLatch(control);
    try {
      return await submitOccurrenceLatched(request, latch);
    } finally {
      latch.dispose();
    }
  }

  async function submitOccurrenceLatched(request, latch) {
    counters.admissions += 1;
    const target = request.target;
    // [#1006 HF21] The runtime authority class is activation-plane material
    // (Genesis pin); a caller-presented class on ANY submit plane — message,
    // OperationCall or control — is an injected authority claim and refuses
    // typed here, before any read, admission, Journal or Effect activity.
    if (hasOwn(request, 'authorityClass')) {
      throw new CentralAdmissionError(
        'AUTHORITY_CLASS_FORBIDDEN',
        'a caller may never present or override the runtime authority class; it is activation-plane material bound once at instance Genesis and woven into the durable GovernanceExecutionPin',
      );
    }
    const binding = businessEndpoint.intentBindings[request.intentType];
    if (binding === undefined) {
      throw new CentralAdmissionError(
        'ADMISSION_EVALUATION_INPUT_INVALID',
        `intent type ${request.intentType} has no binding in business policy ${businessEndpoint.policyId}`,
      );
    }

    // Business-owned domain authorization (caller roles). The kernel routes
    // this gate; the Business package owns the policy. No admission, journal
    // or resource activity happens before it passes.
    const caller = request.caller ?? { role: 'anonymous' };
    if (Array.isArray(binding.roles) && !binding.roles.includes(caller.role)) {
      const denial = {
        reason: 'business-caller-role',
        deniedBy: businessEndpoint.packageId,
        intentType: request.intentType,
        callerRole: caller.role,
      };
      const receipt = {
        status: 'denied',
        denial,
        occurrence: { messageId: request.messageId, workflowInstanceId: `${target.workflowId}:${target.instanceKey}` },
        attribution: attribution(),
      };
      safeObserve(receipt);
      return receipt;
    }

    // [#1003 NF06 DURABLE_MANDATORY] Feasibility gate: the frozen v0.8 Host
    // storage contract is a true-CAS SINGLE-document store with NO
    // cross-document atomic batch or coordinated recovery protocol, so the
    // state-CAS + receipt-append of one occurrence CANNOT be proven atomic
    // or crash-recoverable (the physical negative of this slice witnesses
    // the receipt append failing after the admitted business commit). A
    // separately declared mandatory receipt policy is therefore refused
    // typed BEFORE admission — zero Guard/Journal/Effect/State mutation, no
    // silent fallback to the optional best-effort mode — and reported for
    // product adjudication instead of faking a durability the Host does not
    // supply.
    const wiredReceiptPolicy = decisionReceiptPolicies.get(request.intentType);
    if (wiredReceiptPolicy !== undefined && wiredReceiptPolicy.durability === 'durable-mandatory') {
      const receipt = {
        status: 'denied',
        denial: {
          reason: 'decision-receipt-mandatory-unsupported',
          deniedBy: businessEndpoint.packageId,
          intentType: request.intentType,
          decisionReceipt: {
            policy: 'durable-mandatory',
            supported: false,
            productDecision: 'PRODUCT_DECISION_REQUIRED',
            detail: 'the v0.8 Host true-CAS document store cannot coordinate an atomic or crash-recoverable state+receipt commit; the mandatory receipt mode is refused before admission rather than silently degraded',
          },
        },
        occurrence: { messageId: request.messageId, workflowInstanceId: `${target.workflowId}:${target.instanceKey}` },
        attribution: attribution(),
      };
      safeObserve(receipt);
      return receipt;
    }

    return engine.lane.run(target, async () => {
      const workflowInstanceId = `${target.workflowId}:${target.instanceKey}`;
      // [#1003 FR07-KH2, B3] Cancelled while queued on the lane: nothing read.
      if (latch.cancelled) {
        return terminatedReceipt(request, workflowInstanceId, { code: 'CANCELLED', step: 0 });
      }
      const snapshot = await engine.getInstance(target);
      if (snapshot === null) {
        throw new WorkflowInstanceNotFoundError(target);
      }
      // [v0.8.1 R02] The admission fence revision observed WITH this
      // snapshot: the CAS precondition of the pre-effect claim below.
      const snapshotFenceRevision = await engine.readAdmissionFenceRevision(target);
      // Cancelled during the lane-start read: no model turn may start.
      if (latch.cancelled) {
        return terminatedReceipt(request, workflowInstanceId, { code: 'CANCELLED', step: 0 });
      }
      // [#1062 shared seam] The turn identity of this occurrence, and the
      // disposition gate for non-message durable control turns: a replay of
      // an already-admitted source returns its stored receipt here with zero
      // new State/Journal/Effect activity, and a colliding identity refuses
      // typed before any admission activity. [#1066 R1 P1-B] When the
      // disposition record itself was lost to the crash window, the
      // same-CAS admission history INSIDE the committed instance document
      // answers the same replay guarantee — the authoritative state CAS,
      // not the best-effort observation, owns the once-only truth.
      // [v0.8.1 R01] MESSAGE turns pass the same gate: the v0.2–v0.7 FR04
      // durable (target, messageId) dedup. A re-send of an admitted
      // messageId (lost ACK, client retry, a later retry after further
      // transitions) replays the stored receipt with zero new
      // State/Journal/Effect activity even where a self-loop would legally
      // re-admit it; the same messageId under a different intentType
      // refuses typed. Denials are not dispositions (no state moved), so a
      // re-sent denied message is evaluated afresh, exactly as before.
      const turn = occurrenceTurnOf(request);
      const controlTurnId = deriveDurableControlTurnId(target, turn);
      // [v0.10 K02 anchor 1] The input-complete, deployment-scoped identity
      // material of THIS occurrence: the canonical input digest is computed
      // ONCE here (non-JSON input refuses typed BEFORE any admission
      // activity) and threads every ladder and the commit descriptor.
      const inputDigest = canonicalInputDigestK02(request.input);
      const turnIdentity = turnDispositionIdentity(deploymentScope, target, turn, request.intentType, inputDigest);
      // [v0.10 K02 anchor 3] The same-CAS original-receipt ladder FIRST:
      // ring (this snapshot) → durable archive → undefined.
      const receiptReplayed = await readDurableOriginalReceiptOrReplay(
        snapshot,
        controlTurnId,
        turnIdentity,
        request,
        target,
        workflowInstanceId,
        inputDigest,
      );
      if (receiptReplayed !== undefined) {
        return receiptReplayed;
      }
      // The observation ladders follow (archive-only since the splice): the
      // independent disposition record, then the bounded same-CAS admission
      // history.
      const replayed = await readTurnDispositionOrReplay(
        controlTurnId,
        turn,
        request,
        target,
        inputDigest,
      );
      if (replayed !== undefined) {
        return replayed;
      }
      const historyReplayed = await admittedControlTurnHistoryReplay(
        snapshot,
        controlTurnId,
        turn,
        request,
        target,
        workflowInstanceId,
        inputDigest,
      );
      if (historyReplayed !== undefined) {
        return historyReplayed;
      }
      // [v0.10 K02 anchor 4] The former missing-disposition fail-closed
      // eviction block is REPLACED by the same-CAS original-receipt ring:
      // the once-only truth is atomic with the state (the ring rides the
      // instance document) and its eviction is archive-gated inside the
      // commit, so a LOST derived disposition can no longer wedge all new
      // turns (the 17+ liveness repair). MAX_ADMITTED_CONTROL_TURN_HISTORY
      // stays the bounded crash-backstop history bound; the disposition
      // records remain observational archive depth.
      const context = {
        ...snapshot.state.context,
        callerRole: caller.role,
      };
      const rule = businessEndpoint.rules[binding.ruleId];
      // [#1003 FR08 SD1/SD2 + NF05] A compiled semantic-decision rule that
      // was never digest-verified/frozen at this trusted load boundary can
      // never run — no silent unbound fallback for post-wiring injected or
      // swapped declarations. The registry is keyed by object identity, so
      // `get` (not a re-read of the mutable `kind`) is what binds a rule
      // wired as semantic even if its shape was mutated after wiring.
      const wiredSemanticDecision = isJsonRecord(rule) ? semanticDecisionRules.get(rule) : undefined;
      if (wiredSemanticDecision === undefined && isJsonRecord(rule) && rule.kind === 'semantic-decision') {
        throw new CentralAdmissionError(
          'SEMANTIC_DECISION_UNVALIDATED',
          `semantic-decision rule ${String(binding.ruleId)} was never validated at the trusted load boundary; post-wiring injected declarations are refused`,
        );
      }
      // [#1003 FR08 general + FR09 + FR12] A decision-source rule that was
      // never digest-verified/frozen at this trusted load boundary can
      // never run — same discipline as the semantic-decision wiring.
      const wiredDecisionSource = isJsonRecord(rule) ? decisionSourceRules.get(rule) : undefined;
      if (wiredDecisionSource === undefined && isJsonRecord(rule) && rule.kind === 'decision-source') {
        throw new CentralAdmissionError(
          'DECISION_SOURCE_UNVALIDATED',
          `decision-source rule ${String(binding.ruleId)} was never validated at the trusted load boundary; post-wiring injected declarations are refused`,
        );
      }
      // [#1051 R1 P1] S interprets ONLY the load-time verified frozen
      // declaration. The original rule object stays ordinary mutable policy
      // surface; an in-place mutation after wiring must not change what
      // executes — the approved meaning at load time is the meaning that
      // runs.
      const declaration = wiredSemanticDecision === undefined ? rule : wiredSemanticDecision.declaration;
      const continuation = continuationPolicyFor(declaration);
      const control = latch.signal === undefined ? undefined : { signal: latch.signal };
      let resolved;
      let decisionSourcePendingWrite;
      if (wiredDecisionSource !== undefined) {
        // [#1003 FR08 general + FR09 + FR12] The K-owned retained resolver
        // composition: S selects, K supplies the qualified observations, and
        // the selected candidate proceeds through the UNCHANGED central
        // admission below — there is no separate admission path.
        const decisionSource = await resolveDecisionSourceTurn({
          wired: wiredDecisionSource,
          request,
          context,
          control,
          target,
          workflowInstanceId,
          latch,
        });
        if (decisionSource.terminal !== undefined) {
          return terminatedReceipt(request, workflowInstanceId, decisionSource.terminal, decisionSource.evidence);
        }
        resolved = decisionSource.resolved;
        decisionSourcePendingWrite = decisionSource.pendingWrite;
      } else if (continuation !== undefined) {
        // [#1003 FR07-KH2] K-owned bounded model→query→observation→model
        // continuation over the S single-step surface; only a final
        // envelope proceeds to central admission below.
        if (typeof sdkEndpoint.invokeStep !== 'function') {
          throw new CentralAdmissionError(
            'CONTINUATION_STEP_ENDPOINT_UNAVAILABLE',
            'a harness model-decision rule requires the Host-bound Standard SDK step surface (invokeStep); none is wired',
          );
        }
        const run = await runModelContinuation({
          policy: continuation,
          sdkEndpoint,
          latch,
          requestInput: request.input,
          read: { docs, docKeys, target, workflowInstanceId, stateRevision: snapshot.stateRevision },
        });
        if (run.terminal !== undefined) {
          return terminatedReceipt(request, workflowInstanceId, run.terminal, run.evidence);
        }
        resolved = run.resolved;
      } else {
        // [ABI ruling #1013@6118426531, R1 F-03] The endpoint contract is
        // "synchronous value OR Promise thereof": `await` is transparent for
        // every synchronous model-free Standard SDK endpoint (a non-Promise
        // resolves to itself), and it is what lets a Host-bound model resolver
        // route model-decision rules through its real async port-invoking
        // endpoint. [#1003 FR07-KH2] The protected control rides along so a
        // model-decision turn observes cancellation too.
        try {
          resolved = await sdkEndpoint.interpret(declaration, request.input, context, control);
        } catch (error) {
          if (latch.cancelled) {
            return terminatedReceipt(request, workflowInstanceId, { code: 'CANCELLED', step: 1, inFlightTurnDiscarded: true }, { modelCallEvidence: { status: 'unmeasured' } });
          }
          throw error;
        }
      }

      // [#1003 FR08 SD1] Declared semantic-unavailability: a typed
      // zero-effect terminal BEFORE central admission — no Guard/Admission
      // runs, no Journal record and no Effect dispatch exist, and the
      // ModelPort was never invoked (the declaration route is model-free).
      if (isJsonRecord(resolved) && resolved.semanticStatus === 'unavailable') {
        const declarationId = isJsonRecord(resolved.provenance) && typeof resolved.provenance.declarationId === 'string'
          ? { declarationId: resolved.provenance.declarationId }
          : {};
        return terminatedReceipt(request, workflowInstanceId, { code: 'SEMANTIC_UNAVAILABLE', ...declarationId }, admissionResolverEvidence(resolved));
      }

      // [#1003 FR07-KH2, B3] The final-result → admission race: the latch is
      // checked and CLOSED here, immediately before central admission. A
      // cancel observed now discards the ready result; one arriving after
      // this point can no longer split the authoritative occurrence.
      if (!latch.closeForAdmission()) {
        return terminatedReceipt(request, workflowInstanceId, { code: 'CANCELLED', lateResultDiscarded: true }, {
          modelCallEvidence: admissionModelCallEvidence(resolved?.modelCallEvidence),
          ...(resolved?.continuation === undefined ? {} : { continuation: JSON.parse(canonicalJsonStringify(resolved.continuation)) }),
        });
      }

      const definition = binding.definition ?? businessEndpoint.workflowDefinition;
      const request_shape = {
        target,
        turn,
        trigger: binding.trigger,
        workflowInstanceId,
        definition,
        currentStateKey: snapshot.state.stateKey,
        context,
        event: resolved.structuredDecision.event,
        resolved,
        decisionSchema: businessEndpoint.decisionSchema,
        now: clock(),
      };

      let admissionFence;
      const outcome = await admitCentralDecision(request_shape, {
        governance: pinStore,
        baselines,
        sha256,
        effectJournal,
        effectTools,
        effectBindings,
        contextProjections,
        trace: counters,
        // [v0.10 C01 #1177] The K-issued live external Effect Permit admin —
        // the only component that can mint or consume a permit document.
        effectPermitAdmin,
        // [v0.8.1 R02] Claimed after every denial gate, before any journal
        // begin/effect dispatch; the commit below requires it still held.
        // [#1108 K01] The claim result is RETURNED so admitCentralDecision
        // can apply its zero-ambiguity failure policy to the held fence.
        admissionFence: async (turnId) => {
          admissionFence = await engine.claimAdmissionFence({
            target,
            turnId,
            turnIdentity,
            expectedTargetSequence: snapshot.stateRevision,
            snapshotFenceRevision,
            // [#1108 K01 R1] A trusted-seam recovery turn (operator-authorized
            // poison reconciliation) may supersede a durably all-failed fence
            // holder at this stateRevision; message turns never carry this.
            ...(turn.kind === 'recovery' ? { reconcilesHeldFence: true } : {}),
          });
          return admissionFence;
        },
        // [#1108 K01] Zero-ambiguity failure release (all-failed journal);
        // see admitCentralDecision. Unconditional fence writes do not exist.
        admissionFenceRelease: async (fence) => {
          await engine.releaseAdmissionFence(target, fence);
        },
      });

      if (outcome.status === 'denied') {
        const receipt = {
          status: 'denied',
          denial: outcome.denial,
          occurrence: { messageId: request.messageId, workflowInstanceId },
          attribution: attribution(),
        };
        safeObserve(receipt);
        return receipt;
      }

      const nextLifecycle = stateKindIsTerminal(definition, outcome.admitted.targetState)
        ? 'completed'
        : 'active';
      let committed;
      try {
        committed = await engine.commitAcceptedTransitionInLane({
        target,
        messageId: request.messageId,
        expectedTargetSequence: snapshot.stateRevision,
        ...(admissionFence === undefined ? {} : { admissionFence }),
        // [#1066 R1 P1-B] The non-message turn's admission identity rides
        // INSIDE the authoritative state CAS (bounded same-CAS history), so
        // a lost disposition record can never turn a crash-recovery
        // re-submission into a second State revision. [v0.8.1 R01] Message
        // turns ride the same history.
        admittedControlTurn: {
          turnId: controlTurnId,
          identity: turnIdentity,
        },
        // [v0.10 K02 anchor 2] The immutable ORIGINAL RECEIPT of this turn
        // rides the SAME authoritative state CAS: the engine composes the
        // receipt against the NEXT projection BEFORE the put and commits
        // state + revision + receipt in ONE document write. buildIdentity
        // (the pinned kernel module SHA) rides the envelope — the identity
        // itself is build-stable.
        durableOriginalReceipt: {
          turnId: controlTurnId,
          identity: turnIdentity,
          intentType: request.intentType,
          inputDigest,
          turn: snapshotJson(turn),
          messageId: request.messageId,
          admitted: outcome.admitted,
          buildIdentity: { kernelModuleSha256: moduleIdentity.moduleSha256 },
        },
        transition: (current) => ({
          nextState: {
            stateKey: outcome.admitted.targetState,
            // [#1005 D3-K] The admitted lineage projection is committed by
            // THIS state CAS write, atomically with the target state.
            context: outcome.admitted.contextProjection === undefined
              ? current.state.context
              : { ...current.state.context, ...outcome.admitted.contextProjection },
          },
          nextLifecycle,
          output: {
            transitionKey: outcome.admitted.transitionKey,
            effects: outcome.admitted.effects,
          },
        }),
        });
      } catch (error) {
        // [#1108 K01] Commit-phase failure fence policy: while ANY journal
        // record of this turn exists, the fence stays held (effects may have
        // dispatched; the same-turn replay reconciles through the journal).
        // A turn with ZERO begun journal records (effect-free, or failed
        // before any begin) has nothing durable to protect — the fence is
        // released so a transient store fault cannot wedge the instance at
        // this stateRevision. A failed release keeps the fence held.
        if (admissionFence !== undefined) {
          try {
            const effectCount = Array.isArray(outcome.admitted?.effects) ? outcome.admitted.effects.length : 0;
            let anyRecord = false;
            for (let ordinal = 1; ordinal <= effectCount; ordinal += 1) {
              if (await effectJournal.getEffect(`${controlTurnId}/effect/${String(ordinal)}`) !== null) {
                anyRecord = true;
                break;
              }
            }
            if (!anyRecord) {
              await engine.releaseAdmissionFence(target, admissionFence);
            }
          } catch {
            // keep held — fail-closed
          }
        }
        throw error;
      }

      // [#1003 FR08 general] The exact-cache write happens only AFTER the
      // authoritative state commit: a candidate denied by any admission
      // gate is never cached, and a write failure after the committed
      // truth is a bounded observation that never fails the ACK.
      if (decisionSourcePendingWrite !== undefined) {
        await writeDecisionCacheRecord(decisionSourcePendingWrite.key, {
          ...decisionSourcePendingWrite.record,
          writtenAt: clock(),
        });
      }

      // [#1003 NF06 OBSERVATIONAL_OPTIONAL] AFTER the admitted business
      // commit (the authoritative state CAS is already durable), the
      // K-owned decision receipt is appended as a SEPARATE best-effort
      // observation. Its typed outcome rides the occurrence receipt as an
      // independent field: the admitted business truth above is never
      // rewritten, rolled back or failed by this append.
      const decisionReceipt = await appendObservationalDecisionReceipt({
        request,
        target,
        workflowInstanceId,
        binding,
        declaration,
        resolved,
      });

      // [#1063 HF20] The committed instance projection that leaves the
      // Kernel is the OUTWARD snapshot: the observation window and the
      // control-turn admission history stay internal carrier/replay truth.
      const outwardCommitted = outwardInstanceSnapshot(committed);
      // [v0.10 K02] The disposition record is the post-commit OBSERVATIONAL
      // archive of the admission (the same-CAS original receipt, committed
      // above, owns the once-only truth); a failure here stays a typed
      // observation that never fails the committed ACK.
      const turnDisposition = await writeTurnDisposition(
        controlTurnId,
        turn,
        request,
        target,
        {
          status: 'admitted',
          admitted: outcome.admitted,
          instance: outwardCommitted,
          occurrence: { messageId: request.messageId, workflowInstanceId },
          attribution: attribution(),
        },
        inputDigest,
      );

      const receipt = {
        status: 'admitted',
        admitted: outcome.admitted,
        instance: outwardCommitted,
        occurrence: { messageId: request.messageId, workflowInstanceId },
        attribution: attribution(),
        ...(decisionReceipt === undefined ? {} : { decisionReceipt }),
        turnDisposition,
      };
      safeObserve(receipt);
      return receipt;
    });
  }

  function attribution() {
    return {
      kernel: {
        packageId: moduleIdentity.packageId,
        moduleSha256: moduleIdentity.moduleSha256,
        generation: KERNEL_GENERATION,
      },
      business: { packageId: businessEndpoint.packageId, policyId: businessEndpoint.policyId },
      sdk: { packageId: sdkEndpoint.packageId ?? 'standard-sdk' },
    };
  }

  async function getSnapshot(target) {
    counters.instanceReads += 1;
    // [#1063 HF20] The outward snapshot redacts the K-only carrier fields;
    // the raw document stays the internal next-CAS/replay truth.
    return outwardInstanceSnapshot(await engine.getInstance(target));
  }

  /**
   * [#1063 HF20] Authorized read of the ordered durable mutation-observation
   * window riding the instance document. The Kernel alone validates the
   * opaque cursor against the CURRENT committed window (malformed /
   * substituted stream / beyond-watermark all fail closed typed) and owns
   * the page bytes; an absent instance answers null exactly like
   * getSnapshot — the read is neither an existence oracle nor a leak.
   */
  async function readMutationObservations(request) {
    counters.mutationObservationReads += 1;
    if (!isJsonRecord(request)) {
      throw new CentralAdmissionError('MUTATION_OBSERVATION_READ_INVALID', 'a mutation-observation read must be a record {target, afterCursor?, limit?}');
    }
    const target = request.target;
    if (!isJsonRecord(target) || typeof target.workflowId !== 'string' || target.workflowId.length === 0
      || typeof target.instanceKey !== 'string' || target.instanceKey.length === 0) {
      throw new CentralAdmissionError('MUTATION_OBSERVATION_READ_INVALID', 'a mutation-observation read requires a workflow target {workflowId, instanceKey}');
    }
    if (request.afterCursor !== undefined && (typeof request.afterCursor !== 'string' || request.afterCursor.length === 0)) {
      throw new CentralAdmissionError('MUTATION_OBSERVATION_READ_INVALID', 'afterCursor, when present, must be a non-empty string');
    }
    const raw = await engine.getInstance(target);
    if (raw === null) return null;
    if (!isHf20MutationObservationWindow(raw.mutationObservations)) {
      throw new CentralAdmissionError('WINDOW_INVALID', 'the instance carries no valid mutation-observation window; the read fails closed');
    }
    const stream = `${target.workflowId}:${target.instanceKey}`;
    return projectHf20ObservationPage(raw.mutationObservations, {
      stream,
      ...(request.afterCursor === undefined ? {} : { afterCursor: request.afterCursor }),
      ...(request.limit === undefined ? {} : { limit: request.limit }),
    });
  }

  function getMechanismIdentity() {
    return {
      moduleId: MODULE_ID,
      abiVersion: ABI_VERSION,
      kernelGeneration: KERNEL_GENERATION,
      moduleSha256: moduleIdentity.moduleSha256,
      mechanismFunctions: {
        admitCentralDecision: admitCentralDecision.toString(),
        executeEffectIntents: executeEffectIntents.toString(),
        resolveAdmissionEffectIntents: resolveAdmissionEffectIntents.toString(),
        wireAdmissionEffectBindings: wireAdmissionEffectBindings.toString(),
        VolatileAdmissionEffectJournal: VolatileAdmissionEffectJournal.toString(),
        WorkflowInstanceEngine: WorkflowInstanceEngine.toString(),
        deriveDurableControlTurnId: deriveDurableControlTurnId.toString(),
        readMutationObservations: readMutationObservations.toString(),
      },
    };
  }

  return {
    moduleId: MODULE_ID,
    moduleSha256: moduleIdentity.moduleSha256,
    kernelGeneration: KERNEL_GENERATION,
    counters,
    openInstance,
    submitOccurrence,
    getSnapshot,
    readMutationObservations,
    getDecisionReceipt,
    getJournalRecords: () => effectJournal.getRecords(),
    getMechanismIdentity,
    businessPackageId: businessEndpoint.packageId,
  };
}
// T01K_ADDITIVE_PROTOCOL_EXPORTS_BEGIN (v0.10.2 T01k #1321, L2 section 2)
// ===========================================================================
// [v0.10.2 T01k] The K-owned additive READ-ONLY protocol exports (L2-A, O3).
// Everything from this marker down to T01K_ADDITIVE_PROTOCOL_EXPORTS_END is
// a pure append on top of the T01 kernel blob
// 72a886ffca85fc90caea954ee9fb5b3df7b4fcfa (acceptance: git diff --numstat
// against it shows 0 removed lines; every byte ABOVE this marker is the
// exact T01 payload, sha256
// 66f19f8968cb58cc59808c9c15cfbb193618a150a61ac00a5b5797bec1250630).
//
// The three exports are consumed from the SELECTED, LOADED K module
// instance by the trusted Host Effect gate and the activation seam (L2
// section 2): they mint nothing, mutate nothing and interpret only the K
// document grammar and document shapes this module itself defined above.
// Wire literals and every pre-existing statement are untouched; the
// structural activation contract still requires only createOccurrenceRuntime
// and permits extra exports, so adding these changes no Kernel behavior.
// ===========================================================================

/**
 * [v0.10.2 T01k] The K doc-key builder family of ONE wiring, exactly as the
 * runtime itself chose it at its wiring boundary (`createOccurrenceRuntime`):
 * `scope === undefined` answers the legacy `v08-kernel:` builders; a wired
 * deployment scope answers the injective `v010-k02:` scoped builders (the
 * object with instance, admissionFence, journal, journalPrefix,
 * turnDisposition, decisionReceipt, receiptArchive, effectPermit and
 * effectDispatchClaim). Pure: reads nothing, writes nothing. The Host never
 * reconstructs K key grammar on its own again.
 */
export function kernelDocKeys(scope) {
  return scope === undefined ? legacyKernelDocKeys() : scopedKernelDocKeys(scope);
}

/**
 * [v0.10.2 T01k] The exact K02 scoped key prefix of ONE deployment tuple:
 * `K02_SCOPED_KEY_ROOT` plus the four escaped `deploymentScopeIdentity`
 * fields joined by `:` with a trailing `:` — byte-for-byte the prefix the
 * Host docs composition applies today (activation.ts:379-388 at the v0.10.2
 * pin). Pure; an invalid scope refuses exactly like the scoped grammar
 * itself (`K02_SCOPE_INVALID`).
 */
export function k02ScopePrefix(scope) {
  const frozen = deploymentScopeIdentity(scope);
  return [
    K02_SCOPED_KEY_ROOT,
    encodeK02KeyComponent(frozen.deployedAppId),
    encodeK02KeyComponent(frozen.tenantId),
    encodeK02KeyComponent(frozen.appId),
    encodeK02KeyComponent(frozen.businessPackageId),
  ].join(':') + ':';
}

/**
 * [v0.10.2 T01k] The K-owned read-only Effect authority view: today's
 * trusted-gate steps 2-5 re-read as a pure function of the durable docs.
 * Its ONLY port is `get(key)` — the exact K document address the
 * kernel-minted attest carries; the view never dispatches an adapter, never
 * mutates a document and never marks an attest (the Host gate keeps the
 * pre-handler-refusal authority and the external dispatch itself).
 *
 * Answers `{ ok: true, effectId, durableControlTurnId, attempt,
 * awaitPolicy }` when the full durable authority chain holds (live and
 * unexpired permit of this very turn/business/capability/operation; journal
 * record `started`; admission fence held by this turn; matching dispatch
 * claim), else `{ ok: false, code, message }` with today's code strings and
 * message texts (V10_EFFECT_PERMIT_UNKNOWN / CONSUMED / SCOPE / EXPIRED /
 * JOURNAL / FENCE, V10_EFFECT_DISPATCH_CLAIM_INVALID; a claim that carries
 * no permit at all answers V10_EFFECT_PERMIT_REQUIRED like the gate's own
 * first check).
 */
export async function readEffectAuthorityView(options) {
  const refuse = (code, message) => ({ ok: false, code, message });
  if (!isJsonRecord(options)) {
    return refuse(
      'V10_EFFECT_PERMIT_REQUIRED',
      'readEffectAuthorityView requires { get, attest, capabilityKey, operationId, nowIso }',
    );
  }
  const { get, attest, capabilityKey, operationId, nowIso } = options;
  if (typeof get !== 'function') {
    return refuse(
      'V10_EFFECT_PERMIT_REQUIRED',
      'readEffectAuthorityView reads the durable docs through its only port get(key); this call carries none',
    );
  }
  // The kernel-minted claim shape (the gate's own first check, verbatim):
  // the attest is the only channel that may even CLAIM a K-issued permit.
  if (!isJsonRecord(attest) || !isJsonRecord(attest.effectPermit)
    || typeof attest.effectPermit.effectId !== 'string' || attest.effectPermit.effectId.length === 0
    || typeof attest.effectPermit.durableControlTurnId !== 'string' || attest.effectPermit.durableControlTurnId.length === 0
    || typeof attest.effectPermit.businessPackageId !== 'string' || attest.effectPermit.businessPackageId.length === 0
    || !isJsonRecord(attest.effectPermit.keys)) {
    return refuse(
      'V10_EFFECT_PERMIT_REQUIRED',
      `external effect capability ${String(capabilityKey)} dispatches only under a live K-issued effect permit; this call carries none`,
    );
  }
  const claim = attest.effectPermit;
  const keys = { permit: '', journal: '', fence: '', dispatchClaim: '' };
  for (const name of ['permit', 'journal', 'fence', 'dispatchClaim']) {
    const value = claim.keys[name];
    if (typeof value !== 'string' || value.length === 0) {
      return refuse(
        'V10_EFFECT_PERMIT_REQUIRED',
        `the K-issued permit claim for ${claim.effectId} carries no ${name} document address; the gate refuses an address-less dispatch`,
      );
    }
    keys[name] = value;
  }

  // (2) The durable permit document is the authority (a claim alone proves
  // nothing): live, unexpired, this very turn/business, this capability+operation.
  const permitDoc = await get(keys.permit);
  if (permitDoc === null) {
    return refuse(
      'V10_EFFECT_PERMIT_UNKNOWN',
      `no K-issued effect permit ${claim.effectId} exists at its kernel-issued address (business ${claim.businessPackageId})`,
    );
  }
  const permit = isJsonRecord(permitDoc.value) ? permitDoc.value : null;
  if (permit === null || permit.state !== 'live') {
    return refuse(
      'V10_EFFECT_PERMIT_CONSUMED',
      `K-issued effect permit ${claim.effectId} is not live (state ${JSON.stringify(String(permit?.state))}); a settled or foreign permit never dispatches again`,
    );
  }
  if (permit.durableControlTurnId !== claim.durableControlTurnId) {
    return refuse(
      'V10_EFFECT_PERMIT_SCOPE',
      `K-issued effect permit ${claim.effectId} belongs to turn ${JSON.stringify(String(permit.durableControlTurnId))}, not ${claim.durableControlTurnId}`,
    );
  }
  if (permit.businessPackageId !== claim.businessPackageId) {
    return refuse(
      'V10_EFFECT_PERMIT_SCOPE',
      `K-issued effect permit ${claim.effectId} belongs to business ${JSON.stringify(String(permit.businessPackageId))}, not the dispatching ${claim.businessPackageId}`,
    );
  }
  if (permit.capabilityKey !== capabilityKey) {
    return refuse(
      'V10_EFFECT_PERMIT_SCOPE',
      `K-issued effect permit ${claim.effectId} authorizes capability ${JSON.stringify(String(permit.capabilityKey))}, not ${String(capabilityKey)}`,
    );
  }
  const operations = Array.isArray(permit.operations) ? permit.operations : [];
  if (!operations.includes(operationId)) {
    return refuse(
      'V10_EFFECT_PERMIT_SCOPE',
      `K-issued effect permit ${claim.effectId} does not authorize operation ${String(operationId)}`,
    );
  }
  if (typeof permit.expiresAt !== 'string' || nowIso > permit.expiresAt) {
    return refuse(
      'V10_EFFECT_PERMIT_EXPIRED',
      `K-issued effect permit ${claim.effectId} expired at ${JSON.stringify(String(permit.expiresAt))} (now ${String(nowIso)}); expired live authority dispatches nothing`,
    );
  }

  // (3) The journal cross-check: the effect this permit opens must be durably
  // `started` right now — completed/failed/missing records never dispatch.
  const journalDoc = await get(keys.journal);
  const journalRecord = journalDoc !== null && isJsonRecord(journalDoc.value) && isJsonRecord(journalDoc.value.record)
    ? journalDoc.value.record
    : null;
  if (journalRecord === null || journalRecord.effectId !== claim.effectId || journalRecord.status !== 'started') {
    return refuse(
      'V10_EFFECT_PERMIT_JOURNAL',
      `effect journal record for ${claim.effectId} is not an in-flight started record (status ${JSON.stringify(String(journalRecord?.status))}); a replayed or foreign effect never dispatches`,
    );
  }

  // (4) The admission-fence cross-check: the turn must still hold the
  // instance's admission fence — the LIVE K admission authority itself.
  const target = isJsonRecord(permit.target) ? permit.target : null;
  if (target === null || typeof target.workflowId !== 'string' || typeof target.instanceKey !== 'string') {
    return refuse(
      'V10_EFFECT_PERMIT_SCOPE',
      `K-issued effect permit ${claim.effectId} carries no scoped target identity`,
    );
  }
  const fenceDoc = await get(keys.fence);
  const fence = fenceDoc !== null && isJsonRecord(fenceDoc.value) ? fenceDoc.value : null;
  if (fence === null || fence.turnId !== claim.durableControlTurnId) {
    return refuse(
      'V10_EFFECT_PERMIT_FENCE',
      `the admission fence of ${target.workflowId}/${target.instanceKey} is not held by turn ${claim.durableControlTurnId}; no live admission authority, zero dispatch`,
    );
  }

  // (5) The physical dispatch claim is the final durable link: a key riding
  // the attest is only an address, not proof that K wrote a claim for THIS
  // effect/turn/attempt.
  const attempt = typeof permit.attempt === 'number' ? permit.attempt : 1;
  const claimDoc = await get(keys.dispatchClaim);
  const dispatchClaim = claimDoc !== null && isJsonRecord(claimDoc.value) ? claimDoc.value : null;
  if (dispatchClaim === null
    || dispatchClaim.effectId !== claim.effectId
    || dispatchClaim.durableControlTurnId !== claim.durableControlTurnId
    || dispatchClaim.businessPackageId !== claim.businessPackageId
    || dispatchClaim.attempt !== attempt) {
    return refuse(
      'V10_EFFECT_DISPATCH_CLAIM_INVALID',
      `no matching K dispatch claim exists for effect ${claim.effectId} attempt ${attempt}; zero external dispatch`,
    );
  }

  // Every durable authority check held. The Host gate dispatches, normalizes
  // the phase envelope and enforces this awaitPolicy; the view itself stops
  // here and answers the read-only authority projection.
  return {
    ok: true,
    effectId: claim.effectId,
    durableControlTurnId: claim.durableControlTurnId,
    attempt,
    awaitPolicy: permit.awaitPolicy,
  };
}
// T01K_ADDITIVE_PROTOCOL_EXPORTS_END
