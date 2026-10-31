/**
 * DomainHarness v0.8 — physically loadable Standard SDK Domain Package.
 *
 * A sealed, self-contained source module suitable for the v8 Qualified BUILD
 * closure. Adapted by file/contract from #994@b9ea4d1 sdk-standard.mjs; unlike
 * the experiment it never fabricates freshModelCallCount=1 for a model-free
 * evaluation. K owns admission, state, effect, journal, authorization and replay.
 * This package only interprets five data-only Standard Kind declarations,
 * including the FR02 bounded portable Rule payloadExpression.
 *
 * The host-bound resolver additionally exposes the FR07-S1 single-step
 * query/final envelope surface (#1003 slice 1): an additive, currently
 * UNSELECTED method — the Kernel does not call it until the FR07 K/H
 * successor owns the bounded continuation loop, query authorization,
 * maxSteps and cancellation.
 *
 * No imports / eval / Function constructors / external side effects.
 */
export const MODULE_ID = 'standard-sdk@v08.1.0.0';
export const PACKAGE_KIND = 'standard-sdk';
export const ABI_VERSION = 'v08-standard-sdk-abi/1';
export const ENDPOINTS = Object.freeze([
  Object.freeze({ endpointId: 'sdk:rule-interpreter', kind: 'rule-interpreter' }),
]);

export const STANDARD_KINDS = Object.freeze(['schema', 'rule', 'decision', 'workflow', 'operation']);
const MAX_DEPTH = 32;
const MAX_ITEMS = 1024;
const MAX_CASES = 64;
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const INVALID_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

// FR02 portable-expression budgets. A declared timeoutMs converts to a
// deterministic fixed-rate step budget, so evaluation never reads an ambient
// clock and replay stays byte-identical.
const EXPRESSION_SOURCE_MAX_CHARS = 65_536;
const EXPRESSION_NODE_BUDGET = 4_096;
const EXPRESSION_PARSE_DEPTH_MAX = 256;
const EXPRESSION_EVALUATE_DEPTH_MAX = 1_024;
const EXPRESSION_MAX_BYTES = 4_194_304;
const DEFAULT_EXPRESSION_MAX_BYTES = 1_048_576;
const DEFAULT_EXPRESSION_TIMEOUT_MS = 2_000;
const MAX_EXPRESSION_TIMEOUT_MS = 60_000;
const EXPRESSION_STEPS_PER_MS = 512;
const EXPRESSION_FORBIDDEN_VARIABLES = new Set(['eval', 'random']);
const EXPRESSION_CLOCK_FUNCTIONS = new Set(['now', 'millis']);
const EXPRESSION_TYPES = new Set(['string', 'number', 'boolean', 'object', 'array', 'null']);
const MISSING = Symbol('missing');

export class StandardSdkError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'StandardSdkError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new StandardSdkError(code, message);
}

/**
 * Snapshot declarative inputs before interpretation. No accessors, inherited
 * data, non-enumerable keys or non-JSON syntax are read/evaluated. The ordinary
 * object/array constraint deliberately excludes arbitrary class instances.
 */
function data(value, path = '$', depth = 0) {
  if (depth > MAX_DEPTH) fail('SDK_DATA_BOUNDS', `${path} exceeds nesting bound`);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('SDK_DATA_UNSAFE', `${path} is not finite`);
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > MAX_ITEMS) {
      fail('SDK_DATA_UNSAFE', `${path} is not a bounded plain array`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1) {
      fail('SDK_DATA_UNSAFE', `${path} contains non-index properties or holes`);
    }
    const items = [];
    for (let i = 0; i < value.length; i += 1) {
      const property = descriptors[String(i)];
      if (!property || !Object.hasOwn(property, 'value') || !property.enumerable) {
        fail('SDK_DATA_UNSAFE', `${path} contains an accessor or hole`);
      }
      items.push(data(property.value, `${path}[${i}]`, depth + 1));
    }
    return items;
  }
  if (typeof value !== 'object' || value === null || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    fail('SDK_DATA_UNSAFE', `${path} is not plain JSON data`);
  }
  const desc = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(desc).length > MAX_ITEMS) fail('SDK_DATA_BOUNDS', `${path} contains too many properties`);
  const result = Object.create(null);
  for (const key of Reflect.ownKeys(desc)) {
    if (typeof key !== 'string' || INVALID_KEYS.has(key)) {
      fail('SDK_DATA_UNSAFE', `${path} contains forbidden key`);
    }
    const property = desc[key];
    if (!property.enumerable || !Object.hasOwn(property, 'value')) {
      fail('SDK_DATA_UNSAFE', `${path} contains accessor/non-enumerable field ${key}`);
    }
    result[key] = data(property.value, `${path}.${key}`, depth + 1);
  }
  return result;
}

function record(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('SDK_DECLARATION_INVALID', `${label} must be an object`);
  }
  return value;
}

function ident(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    fail('SDK_DECLARATION_INVALID', `${label} must be a bounded identifier`);
  }
  return value;
}

/** K-derived opaque addresses (URL-encoded turn/workflow ids): bounded text, not identifier-shaped. */
function boundedText(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    fail('SDK_DECISION_RECEIPT_RECORD_INVALID', `${label} must be bounded non-empty text`);
  }
  return value;
}

function project(fields, input, label) {
  const map = record(fields, `${label} projection`);
  const result = Object.create(null);
  for (const [outKey, inKey] of Object.entries(map)) {
    ident(outKey, `${label} output key`);
    if (typeof inKey !== 'string' || !Object.hasOwn(input, inKey)) {
      fail('SDK_PROJECTION_MISSING', `${label} cannot project missing input ${String(inKey)}`);
    }
    result[outKey] = input[inKey];
  }
  return result;
}

function evidence(id) {
  return {
    provenance: { sdkModule: MODULE_ID, declarationId: id },
    source: 'harness-machine',
    llmAvoided: true,
    // No trusted ModelPort attached at the SDK interpreter boundary. An
    // upstream caller-supplied number can NEVER prove a physical model call.
    modelCallEvidence: { status: 'unsupported' },
    cacheDisposition: { read: 'disabled' },
    telemetry: [],
  };
}

// FR07-S1 single-step envelope grammar, retained from the v0.7
// harness-machine.ts@86110c6 blob f2fe5d49 exact-key parsers
// (parseModelEnvelope / parseQueryCall / parseStructuredResult):
//   {kind:'query', call:{capabilityId, input}}
//   {kind:'final', result:{decision:{outcome,data}, event:{type,payload}}}
// The model output may carry NOTHING else: state/transition/effect/journal/
// governance authority belongs to K, and a model can never pre-claim call
// provenance or measurement. Allowed outcomes/events/capabilities are NOT
// validated here — that allowlist lives in the sealed Business policy and
// is enforced by K in the FR07 K/H successor.
const STEP_AUTHORITY_KEYS = Object.freeze([
  'nextState', 'transition', 'mutation', 'effect', 'journal',
  'promotion', 'activation', 'governanceBaseline', 'privateReasoning',
  'modelCallEvidence', 'freshModelCallCount',
]);
const STEP_QUERY_KEYS = Object.freeze(['kind', 'call']);
const STEP_CALL_KEYS = Object.freeze(['capabilityId', 'input']);
const STEP_FINAL_KEYS = Object.freeze(['kind', 'result']);
const STEP_RESULT_KEYS = Object.freeze(['decision', 'event']);
const STEP_DECISION_KEYS = Object.freeze(['outcome', 'data']);
const STEP_EVENT_KEYS = Object.freeze(['type', 'payload']);

function exactKeys(value, keys, label) {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    fail('SDK_MODEL_OUTPUT_INVALID', `model step ${label} must carry exactly the keys [${keys.join(', ')}]`);
  }
}

/** Bounded identifier check scoped to MODEL OUTPUT (never a declaration code). */
function stepIdent(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    fail('SDK_MODEL_OUTPUT_INVALID', `model step ${label} must be a bounded identifier`);
  }
  return value;
}

/** Object check scoped to MODEL OUTPUT (never a declaration code). */
function stepRecord(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('SDK_MODEL_OUTPUT_INVALID', `model step ${label} must be an object`);
  }
  return value;
}

/**
 * Parse one data()-snapshotted model turn into a strict step envelope
 * candidate. Fail-closed typed on every non-canonical or authority-claiming
 * shape; the caller wraps the candidate with trusted per-step evidence.
 */
function parseStepEnvelope(snapshot) {
  for (const key of STEP_AUTHORITY_KEYS) {
    if (Object.hasOwn(snapshot, key)) {
      fail('SDK_MODEL_AUTHORITY_REFUSED', `model step output may not carry the reserved authority/evidence key ${key}`);
    }
  }
  if (snapshot.kind === 'query') {
    exactKeys(snapshot, STEP_QUERY_KEYS, 'query envelope');
    const call = stepRecord(snapshot.call, 'query call');
    exactKeys(call, STEP_CALL_KEYS, 'query call');
    return { stepKind: 'query', capabilityId: stepIdent(call.capabilityId, 'query call.capabilityId'), input: call.input };
  }
  if (snapshot.kind === 'final') {
    exactKeys(snapshot, STEP_FINAL_KEYS, 'final envelope');
    const result = stepRecord(snapshot.result, 'final result');
    exactKeys(result, STEP_RESULT_KEYS, 'final result');
    const decision = stepRecord(result.decision, 'final decision');
    exactKeys(decision, STEP_DECISION_KEYS, 'final decision');
    stepIdent(decision.outcome, 'final decision.outcome');
    const event = stepRecord(result.event, 'final event');
    exactKeys(event, STEP_EVENT_KEYS, 'final event');
    stepIdent(event.type, 'final event.type');
    return { stepKind: 'final', structuredDecision: { decision, event } };
  }
  fail('SDK_MODEL_OUTPUT_INVALID', `model step output kind must be 'query' or 'final'`);
}

function schema(definition, input) {
  const properties = record(definition.properties ?? {}, 'schema.properties');
  const required = definition.required ?? [];
  if (!Array.isArray(required) || required.length > MAX_ITEMS) {
    fail('SDK_DECLARATION_INVALID', 'schema.required must be a bounded string list');
  }
  const issues = [];
  const types = new Set(['string', 'number', 'boolean', 'object', 'array', 'null']);
  for (const name of required) {
    ident(name, 'schema.required');
    if (!Object.hasOwn(input, name)) issues.push({ path: name, code: 'REQUIRED_MISSING' });
  }
  for (const [name, expected] of Object.entries(properties)) {
    ident(name, 'schema.properties key');
    if (!types.has(expected)) fail('SDK_DECLARATION_INVALID', `unsupported schema type ${String(expected)}`);
    if (!Object.hasOwn(input, name)) continue;
    const value = input[name];
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    if (actual !== expected) issues.push({ path: name, code: 'TYPE_MISMATCH' });
  }
  return { kind: 'schema', valid: issues.length === 0, issues };
}

function rule(definition, input) {
  const eventType = ident(definition.eventType, 'rule.eventType');
  const hasPayloadExpression = Object.hasOwn(definition, 'payloadExpression');
  if (hasPayloadExpression && Object.hasOwn(definition, 'payloadFromInput')) {
    fail('SDK_DECLARATION_INVALID', 'rule must declare exactly one of payloadFromInput or payloadExpression');
  }
  const payload = hasPayloadExpression
    ? evaluateRulePayloadExpression(definition.payloadExpression, input)
    : project(definition.payloadFromInput ?? {}, input, 'rule');
  return {
    kind: 'rule',
    structuredDecision: {
      decision: { outcome: 'decide', data: payload },
      event: { type: eventType, payload },
    },
  };
}

function decision(definition, input) {
  const candidates = definition.cases;
  if (!Array.isArray(candidates) || candidates.length === 0 || candidates.length > MAX_CASES) {
    fail('SDK_DECLARATION_INVALID', 'decision.cases must contain 1..64 data-only cases');
  }
  for (const candidate of candidates) {
    record(candidate, 'decision case');
    record(candidate.when, 'decision.when');
    const field = ident(candidate.when.field, 'decision.when.field');
    if (!Object.hasOwn(candidate.when, 'equals')) fail('SDK_DECLARATION_INVALID', 'decision.when.equals missing');
    if (JSON.stringify(input[field]) !== JSON.stringify(candidate.when.equals)) continue;
    return { kind: 'decision', matched: true, outcome: ident(candidate.outcome, 'decision.outcome') };
  }
  return { kind: 'decision', matched: false, outcome: null };
}

function workflow(definition, input) {
  const from = ident(definition.from, 'workflow.from');
  const trigger = ident(definition.trigger, 'workflow.trigger');
  const to = ident(definition.to, 'workflow.to');
  if (input.state !== from || input.trigger !== trigger) {
    return { kind: 'workflow', matched: false, candidate: null };
  }
  // A proposal only: K still evaluates policy/Guard/Admission and writes state.
  return { kind: 'workflow', matched: true, candidate: { from, to, trigger } };
}

function operation(definition, input) {
  const operationId = ident(definition.operationId, 'operation.operationId');
  const resourceKey = ident(definition.resourceKey, 'operation.resourceKey');
  return {
    kind: 'operation',
    // Data-only effect intent. NO Host calls and NO execution permission.
    proposal: { operationId, resourceKey, input: project(definition.inputFrom ?? {}, input, 'operation') },
  };
}

// FR08 SD1/SD2 + NF05 (#1003): the compiled SemanticDecision declaration
// interpreter. BUILD compiles/validates/pins the descriptor
// (compileSemanticDecisions — declarationDigest over the canonical body);
// the selected Kernel verifies that digest once at its trusted load boundary
// and alone owns Guard/Admission/Effect/Journal; this interpreter only turns
// the data-only declaration into ONE proposed structured decision. It never
// calls a ModelPort (the declaration route is model-free by construction)
// and never executes or authorizes anything.
const SEMANTIC_MAX_LIST = 64;
const SEMANTIC_MAX_FIELDS = 32;
const SEMANTIC_RESULT_TYPES = new Set(['string', 'number', 'boolean', 'object', 'array', 'null']);
const SEMANTIC_REASON_MAX_CHARS = 256;

function identList(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > SEMANTIC_MAX_LIST) {
    fail('SDK_SEMANTIC_DECISION_INVALID', `${label} must be a non-empty bounded identifier list`);
  }
  const seen = new Set();
  for (const item of value) {
    ident(item, label);
    if (seen.has(item)) fail('SDK_SEMANTIC_DECISION_INVALID', `${label} contains the duplicate ${item}`);
    seen.add(item);
  }
  return [...value];
}

/**
 * NF05 declared resultSchema check on the resolver RESULT payload
 * (decision.data — same scoping precedent as the FR02 payloadExpression
 * outputSchema). Violations are typed refusals AFTER resolution and BEFORE
 * any Kernel admission can consume the proposal.
 */
function assertSemanticResultSchema(rawSchema, payload) {
  if (rawSchema === undefined) return;
  const spec = record(rawSchema, 'semantic-decision.resultSchema');
  const required = spec.required ?? [];
  if (!Array.isArray(required) || required.length > MAX_ITEMS) {
    fail('SDK_SEMANTIC_DECISION_INVALID', 'resultSchema.required must be a bounded string list');
  }
  const properties = record(spec.properties ?? {}, 'resultSchema.properties');
  for (const name of required) {
    ident(name, 'resultSchema.required');
    if (!Object.hasOwn(payload, name)) {
      fail('SDK_SEMANTIC_RESULT_INVALID', `semantic decision result violates resultSchema (required ${name} is missing)`);
    }
  }
  for (const [name, expected] of Object.entries(properties)) {
    ident(name, 'resultSchema.properties key');
    if (!SEMANTIC_RESULT_TYPES.has(expected)) {
      fail('SDK_SEMANTIC_DECISION_INVALID', `unsupported resultSchema type ${String(expected)}`);
    }
    if (!Object.hasOwn(payload, name)) continue;
    const actual = expressionValueKind(payload[name]);
    if (actual !== expected) {
      fail('SDK_SEMANTIC_RESULT_INVALID', `semantic decision result violates resultSchema (${name} is ${actual}, expected ${expected})`);
    }
  }
}

function semanticDecision(definition, input, rawContext) {
  const allowedOutcomes = identList(definition.allowedOutcomes, 'semantic-decision.allowedOutcomes');
  const allowedEventTypes = identList(definition.allowedEventTypes, 'semantic-decision.allowedEventTypes');
  if (definition.queryCapabilityIds !== undefined) {
    // Read-only capability VERIFICATION belongs to BUILD (compiled Tools,
    // effect 'none'); here the list is only shape-bounded inert data, and a
    // decision with no query capabilities is legal (bounded, may be empty).
    if (!Array.isArray(definition.queryCapabilityIds) || definition.queryCapabilityIds.length > SEMANTIC_MAX_LIST) {
      fail('SDK_SEMANTIC_DECISION_INVALID', 'semantic-decision.queryCapabilityIds must be a bounded identifier list');
    }
    const seen = new Set();
    for (const capabilityId of definition.queryCapabilityIds) {
      ident(capabilityId, 'semantic-decision.queryCapabilityIds');
      if (seen.has(capabilityId)) fail('SDK_SEMANTIC_DECISION_INVALID', `semantic-decision.queryCapabilityIds contains the duplicate ${capabilityId}`);
      seen.add(capabilityId);
    }
  }
  // SD1: a declared semantic-unavailability is a typed zero-effect state of
  // its own — NOT an error and NOT a decision. The Kernel turns it into a
  // typed terminal before central admission; no ModelPort and no effect can
  // exist on this path.
  if (definition.unavailable !== undefined) {
    const unavailable = record(definition.unavailable, 'semantic-decision.unavailable');
    if (unavailable.disposition !== 'semantic-unavailable') {
      fail('SDK_SEMANTIC_DECISION_INVALID', "unavailable.disposition must be 'semantic-unavailable'");
    }
    if (typeof unavailable.reason !== 'string' || unavailable.reason.length === 0
      || unavailable.reason.length > SEMANTIC_REASON_MAX_CHARS) {
      fail('SDK_SEMANTIC_DECISION_INVALID', 'unavailable.reason must be a bounded non-empty string');
    }
    return {
      kind: 'semantic-decision',
      semanticStatus: 'unavailable',
      unavailable: { disposition: unavailable.disposition, reason: unavailable.reason },
    };
  }
  const context = record(data(rawContext), 'semantic-decision context');
  // NF05: a declared required promoted reference must be SUPPLIED through
  // the trusted Kernel context with the exact pinned content identity.
  if (definition.promotedReference !== undefined) {
    const reference = record(definition.promotedReference, 'semantic-decision.promotedReference');
    const artifactId = ident(reference.artifactId, 'promotedReference.artifactId');
    const contentDigest = ident(reference.contentDigest, 'promotedReference.contentDigest');
    if (reference.required === true) {
      const suppliedMap = context.promotedReferences === undefined ? {} : context.promotedReferences;
      const supplied = record(suppliedMap, 'context.promotedReferences')[artifactId];
      if (!Object.hasOwn(record(suppliedMap, 'context.promotedReferences'), artifactId)
        || supplied?.artifactId !== artifactId || supplied?.contentDigest !== contentDigest) {
        fail('SDK_SEMANTIC_PROMOTION_UNRESOLVED', `the required promoted reference ${artifactId} is not supplied or does not match the pinned content digest`);
      }
    }
  }
  // NF05: exact input selection — the decision may read ONLY the declared
  // projection of the occurrence input.
  const selection = record(definition.inputSelection ?? {}, 'semantic-decision.inputSelection');
  if (Object.keys(selection).length === 0 || Object.keys(selection).length > SEMANTIC_MAX_FIELDS) {
    fail('SDK_SEMANTIC_DECISION_INVALID', `semantic-decision.inputSelection must map 1..${SEMANTIC_MAX_FIELDS} fields`);
  }
  const selectedInput = project(selection, input, 'semantic-decision');
  // SD2: the declared disposition is the ONLY source of the proposed event
  // type/outcome, and both must stay inside the declared allowlists.
  const disposition = record(definition.disposition, 'semantic-decision.disposition');
  let outcome;
  let eventType;
  if (disposition.mode === 'deterministic') {
    outcome = ident(disposition.outcome, 'disposition.outcome');
    eventType = ident(disposition.eventType, 'disposition.eventType');
  } else if (disposition.mode === 'route') {
    outcome = selectedInput[ident(disposition.outcomeFrom, 'disposition.outcomeFrom')];
    eventType = selectedInput[ident(disposition.eventTypeFrom, 'disposition.eventTypeFrom')];
    if (typeof outcome !== 'string' || !IDENTIFIER.test(outcome)) {
      fail('SDK_SEMANTIC_DECISION_INVALID', 'the routed outcome must be a bounded identifier');
    }
    if (typeof eventType !== 'string' || !IDENTIFIER.test(eventType)) {
      fail('SDK_SEMANTIC_DECISION_INVALID', 'the routed event type must be a bounded identifier');
    }
  } else {
    fail('SDK_SEMANTIC_DECISION_INVALID', "disposition.mode must be 'deterministic' or 'route'");
  }
  if (!allowedOutcomes.includes(outcome)) {
    fail('SDK_SEMANTIC_OUTCOME_UNDECLARED', `outcome ${outcome} is not a declared allowed outcome`);
  }
  if (!allowedEventTypes.includes(eventType)) {
    fail('SDK_SEMANTIC_EVENT_UNDECLARED', `event type ${eventType} is not a declared allowed event type`);
  }
  const payload = project(disposition.payloadFromInput ?? {}, selectedInput, 'semantic-decision disposition');
  assertSemanticResultSchema(definition.resultSchema, payload);
  return {
    kind: 'semantic-decision',
    structuredDecision: {
      decision: { outcome, data: payload },
      event: { type: eventType, payload },
    },
    // FR08 SD1 declaration-level truth: this declared route contains ZERO
    // fresh-model steps by construction. It is NOT an operational port
    // attestation — that stays exclusively in modelCallEvidence.
    freshModelCallCount: 0,
  };
}

/**
 * FR02 portable safe expression evaluation, retained from the v0.7
 * expression-runtime.ts@c37cf23d / policy.ts / json-boundary.ts observables
 * (historic pin 86110c6) and adapted to the sealed v0.8 Standard SDK:
 *
 * - JSONata is NOT embedded. A bounded deterministic grammar subset —
 *   literals, field/index paths, object/array construction, arithmetic,
 *   comparison, boolean and string-concat operators plus the deterministic
 *   clock functions — is interpreted here, so the sealed payload keeps zero
 *   imports, no dynamic code evaluation and no second runtime;
 * - `$now()`/`$millis()` are injected from the declaration logicalTime; the
 *   evaluator never reads an ambient clock or network;
 * - the v0.7 wall-clock timeoutMs becomes a deterministic fixed-rate step
 *   budget (EXPRESSION_STEPS_PER_MS steps per declared millisecond): the
 *   same fail-closed denial class with zero ambient time dependence;
 * - parser nesting and AST evaluation recursion each carry an explicit
 *   depth budget checked BEFORE descending, so a legal-length source can
 *   never overflow the JS stack (typed SDK_EXPRESSION_BOUNDS instead);
 * - UTF-8 input/output byte limits and the plain-JSON result round-trip
 *   follow the v0.7 json-boundary semantics.
 */
function utf8ByteLength(value) {
  let bytes = 0;
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) continue;
    if (codePoint <= 0x7f) bytes += 1;
    else if (codePoint <= 0x7ff) bytes += 2;
    else if (codePoint <= 0xffff) bytes += 3;
    else bytes += 4;
  }
  return bytes;
}

function expressionOption(spec, field, fallback, maximum) {
  const value = spec[field];
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > maximum) {
    fail('SDK_DECLARATION_INVALID', `rule.payloadExpression.${field} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

function evaluateRulePayloadExpression(rawDeclaration, input) {
  const spec = record(rawDeclaration, 'rule.payloadExpression');
  const source = spec.source;
  if (typeof source !== 'string') {
    fail('SDK_DECLARATION_INVALID', 'rule.payloadExpression.source must be an expression string');
  }
  if (source.length > EXPRESSION_SOURCE_MAX_CHARS) {
    fail('SDK_EXPRESSION_BOUNDS', `rule.payloadExpression source length exceeds ${EXPRESSION_SOURCE_MAX_CHARS} characters`);
  }
  const logicalTime = spec.logicalTime;
  if (typeof logicalTime !== 'string' || !Number.isFinite(Date.parse(logicalTime))) {
    fail('SDK_DECLARATION_INVALID', 'rule.payloadExpression.logicalTime must be a valid ISO timestamp');
  }
  const timeoutMs = expressionOption(spec, 'timeoutMs', DEFAULT_EXPRESSION_TIMEOUT_MS, MAX_EXPRESSION_TIMEOUT_MS);
  const maxInputBytes = expressionOption(spec, 'maxInputBytes', DEFAULT_EXPRESSION_MAX_BYTES, EXPRESSION_MAX_BYTES);
  const maxOutputBytes = expressionOption(spec, 'maxOutputBytes', DEFAULT_EXPRESSION_MAX_BYTES, EXPRESSION_MAX_BYTES);
  if (utf8ByteLength(JSON.stringify(input)) > maxInputBytes) {
    fail('SDK_EXPRESSION_BOUNDS', `rule.payloadExpression input exceeds maxInputBytes (${maxInputBytes})`);
  }
  const evaluated = evaluateExpressionSource(source, input, logicalTime, timeoutMs);
  const serialized = JSON.stringify(evaluated);
  if (utf8ByteLength(serialized) > maxOutputBytes) {
    fail('SDK_EXPRESSION_BOUNDS', `rule.payloadExpression result exceeds maxOutputBytes (${maxOutputBytes})`);
  }
  // v0.7 boundary: hand callers plain JSON (JSON round-trip), never the
  // evaluator's internal null-prototype constructions.
  const result = JSON.parse(serialized);
  assertExpressionOutputSchema(spec.outputSchema, result);
  return result;
}

function expressionValueKind(value) {
  return value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
}

function assertExpressionOutputSchema(rawSchema, result) {
  if (rawSchema === undefined) return;
  const schema = record(rawSchema, 'rule.payloadExpression.outputSchema');
  const required = schema.required ?? [];
  if (!Array.isArray(required) || required.length > MAX_ITEMS) {
    fail('SDK_DECLARATION_INVALID', 'outputSchema.required must be a bounded string list');
  }
  const properties = record(schema.properties ?? {}, 'outputSchema.properties');
  // The schema describes object fields; primitive or null results must be
  // refused typed before Object.hasOwn below can raise a bare TypeError.
  const resultKind = expressionValueKind(result);
  if (resultKind !== 'object' && resultKind !== 'array') {
    fail('SDK_EXPRESSION_OUTPUT_INVALID', `expression result does not satisfy outputSchema (result is ${resultKind}, expected object)`);
  }
  for (const name of required) {
    ident(name, 'outputSchema.required');
    if (!Object.hasOwn(result, name)) {
      fail('SDK_EXPRESSION_OUTPUT_INVALID', `expression result does not satisfy outputSchema (required ${name} is missing)`);
    }
  }
  for (const [name, expected] of Object.entries(properties)) {
    ident(name, 'outputSchema.properties key');
    if (!EXPRESSION_TYPES.has(expected)) {
      fail('SDK_DECLARATION_INVALID', `unsupported outputSchema type ${String(expected)}`);
    }
    if (!Object.hasOwn(result, name)) continue;
    const value = result[name];
    const actual = expressionValueKind(value);
    if (actual !== expected) {
      fail('SDK_EXPRESSION_OUTPUT_INVALID', `expression result does not satisfy outputSchema (${name} is ${actual}, expected ${expected})`);
    }
  }
}

function evaluateExpressionSource(source, scope, logicalTime, timeoutMs) {
  const ast = createExpressionParser(source).parse();
  const state = { steps: 0, budget: timeoutMs * EXPRESSION_STEPS_PER_MS, timeoutMs, depth: 0 };
  const clock = { now: logicalTime, millis: Date.parse(logicalTime) };
  const result = evaluateExpressionNode(ast, scope, clock, state);
  if (result === MISSING) {
    fail('SDK_EXPRESSION_UNSAFE', 'rule.payloadExpression result is not portable JSON (unresolved path)');
  }
  return result;
}

function expressionTick(state) {
  state.steps += 1;
  if (state.steps > state.budget) {
    fail('SDK_EXPRESSION_TIMEOUT', `rule.payloadExpression evaluation exceeded its deterministic timeout budget (timeoutMs=${state.timeoutMs})`);
  }
}

function createExpressionParser(source) {
  let pos = 0;
  let nodes = 0;
  let depth = 0;

  function unsafe(message) {
    fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression ${message}`);
  }
  function node(fields) {
    nodes += 1;
    if (nodes > EXPRESSION_NODE_BUDGET) {
      fail('SDK_EXPRESSION_BOUNDS', `rule.payloadExpression exceeds bounded expression node budget (${EXPRESSION_NODE_BUDGET})`);
    }
    return fields;
  }
  // Every recursive-descent cycle passes through enterNesting() BEFORE
  // descending, so a legal-length source can never exhaust the JS stack
  // before the node/step budgets run. The counter is not restored on the
  // failure path: fail() abandons this parser instance entirely.
  function enterNesting() {
    depth += 1;
    if (depth > EXPRESSION_PARSE_DEPTH_MAX) {
      fail('SDK_EXPRESSION_BOUNDS', `rule.payloadExpression exceeds bounded expression nesting depth (${EXPRESSION_PARSE_DEPTH_MAX})`);
    }
  }
  function skip() {
    while (
      pos < source.length
      && (source[pos] === ' ' || source[pos] === '\t' || source[pos] === '\n' || source[pos] === '\r')
    ) pos += 1;
  }
  function peek() {
    skip();
    return pos < source.length ? source[pos] : '';
  }
  function eat(character) {
    if (peek() === character) {
      pos += 1;
      return true;
    }
    return false;
  }
  function expect(character) {
    if (!eat(character)) unsafe(`syntax error: expected '${character}' at offset ${pos}`);
  }
  function identifierStart(character) {
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character === '_';
  }
  function identifierPart(character) {
    return identifierStart(character) || (character >= '0' && character <= '9');
  }
  function readIdentifier() {
    const start = pos;
    while (pos < source.length && identifierPart(source[pos])) pos += 1;
    return source.slice(start, pos);
  }
  function readKeyword(word) {
    skip();
    if (source.slice(pos, pos + word.length) !== word) return false;
    const after = pos + word.length;
    if (after < source.length && identifierPart(source[after])) return false;
    pos = after;
    return true;
  }
  function readString() {
    const quote = source[pos];
    pos += 1;
    let value = '';
    while (pos < source.length) {
      const character = source[pos];
      if (character === quote) {
        pos += 1;
        return value;
      }
      if (character === '\\') {
        pos += 1;
        if (pos >= source.length) unsafe('syntax error: unterminated escape');
        const escape = source[pos];
        if (escape === 'n') value += '\n';
        else if (escape === 't') value += '\t';
        else if (escape === 'r') value += '\r';
        else if (escape === '"' || escape === "'" || escape === '\\' || escape === '/') value += escape;
        else if (escape === 'u') {
          const hex = source.slice(pos + 1, pos + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) unsafe('syntax error: invalid unicode escape');
          value += String.fromCharCode(Number.parseInt(hex, 16));
          pos += 4;
        } else unsafe(`syntax error: invalid escape \\${escape}`);
        pos += 1;
        continue;
      }
      value += character;
      pos += 1;
    }
    unsafe('syntax error: unterminated string');
  }
  function readNumber() {
    const start = pos;
    while (pos < source.length && source[pos] >= '0' && source[pos] <= '9') pos += 1;
    if (pos < source.length && source[pos] === '.') {
      pos += 1;
      while (pos < source.length && source[pos] >= '0' && source[pos] <= '9') pos += 1;
    }
    if (pos < source.length && (source[pos] === 'e' || source[pos] === 'E')) {
      pos += 1;
      if (pos < source.length && (source[pos] === '+' || source[pos] === '-')) pos += 1;
      while (pos < source.length && source[pos] >= '0' && source[pos] <= '9') pos += 1;
    }
    const text = source.slice(start, pos);
    const value = Number(text);
    if (text === '' || !Number.isFinite(value)) unsafe(`syntax error: invalid number at offset ${start}`);
    return node({ type: 'literal', value });
  }

  function parseExpression() {
    return parseOr();
  }
  function parseOr() {
    let left = parseAnd();
    while (readKeyword('or')) left = node({ type: 'binary', operator: 'or', left, right: parseAnd() });
    return left;
  }
  function parseAnd() {
    let left = parseComparison();
    while (readKeyword('and')) left = node({ type: 'binary', operator: 'and', left, right: parseComparison() });
    return left;
  }
  function parseComparison() {
    const left = parseAdditive();
    skip();
    for (const operator of ['!=', '<=', '>=', '=', '<', '>']) {
      if (source.slice(pos, pos + operator.length) === operator) {
        pos += operator.length;
        return node({ type: 'binary', operator, left, right: parseAdditive() });
      }
    }
    return left;
  }
  function parseAdditive() {
    let left = parseMultiplicative();
    for (;;) {
      skip();
      const character = pos < source.length ? source[pos] : '';
      if (character === '+' || character === '-' || character === '&') {
        pos += 1;
        left = node({ type: 'binary', operator: character, left, right: parseMultiplicative() });
      } else return left;
    }
  }
  function parseMultiplicative() {
    let left = parseUnary();
    for (;;) {
      skip();
      const character = pos < source.length ? source[pos] : '';
      if (character === '*' || character === '/' || character === '%') {
        pos += 1;
        left = node({ type: 'binary', operator: character, left, right: parseUnary() });
      } else return left;
    }
  }
  function parseUnary() {
    if (eat('-')) {
      enterNesting();
      const operand = parseUnary();
      depth -= 1;
      return node({ type: 'neg', operand });
    }
    return parsePostfix();
  }
  function parsePostfix() {
    let base = parsePrimary();
    for (;;) {
      skip();
      const character = pos < source.length ? source[pos] : '';
      if (character === '.') {
        pos += 1;
        skip();
        if (pos >= source.length || !identifierStart(source[pos])) unsafe(`syntax error: expected field name at offset ${pos}`);
        base = node({ type: 'field', base, name: readIdentifier() });
      } else if (character === '[') {
        pos += 1;
        const start = pos;
        while (pos < source.length && source[pos] >= '0' && source[pos] <= '9') pos += 1;
        const text = source.slice(start, pos);
        if (text === '') unsafe(`syntax error: path index must be a nonnegative integer at offset ${start}`);
        const index = Number(text);
        expect(']');
        base = node({ type: 'index', base, index });
      } else return base;
    }
  }
  function parsePrimary() {
    skip();
    const character = pos < source.length ? source[pos] : '';
    if (character === '' ) unsafe(`syntax error: unexpected end of expression`);
    if (character === '(') {
      pos += 1;
      enterNesting();
      const inner = parseExpression();
      depth -= 1;
      expect(')');
      return inner;
    }
    if (character === '{') {
      pos += 1;
      enterNesting();
      const entries = [];
      if (peek() !== '}') {
        for (;;) {
          skip();
          const keyCharacter = peek();
          let key;
          if (keyCharacter === '"' || keyCharacter === "'") key = readString();
          else if (identifierStart(keyCharacter)) key = readIdentifier();
          else unsafe(`syntax error: invalid object key at offset ${pos}`);
          if (INVALID_KEYS.has(key)) {
            fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression object key ${JSON.stringify(key)} is forbidden`);
          }
          expect(':');
          entries.push([key, parseExpression()]);
          if (!eat(',')) break;
        }
      }
      expect('}');
      depth -= 1;
      return node({ type: 'object', entries });
    }
    if (character === '[') {
      pos += 1;
      enterNesting();
      const items = [];
      if (peek() !== ']') {
        items.push(parseExpression());
        while (eat(',')) items.push(parseExpression());
      }
      expect(']');
      depth -= 1;
      return node({ type: 'array', items });
    }
    if (character === '"' || character === "'") {
      return node({ type: 'literal', value: readString() });
    }
    if (character >= '0' && character <= '9') return readNumber();
    if (character === '$') {
      pos += 1;
      const name = readIdentifier();
      if (name === '') unsafe(`syntax error: expected a function name at offset ${pos}`);
      if (EXPRESSION_FORBIDDEN_VARIABLES.has(name)) {
        fail('SDK_EXPRESSION_FORBIDDEN', `$${name} is forbidden by DomainHarness`);
      }
      skip();
      if (pos < source.length && source[pos] === '(') {
        pos += 1;
        enterNesting();
        const args = [];
        if (peek() !== ')') {
          args.push(parseExpression());
          while (eat(',')) args.push(parseExpression());
        }
        expect(')');
        depth -= 1;
        if (EXPRESSION_CLOCK_FUNCTIONS.has(name)) {
          if (args.length > 0) {
            fail('SDK_EXPRESSION_FORBIDDEN', `$${name}(...) arguments are not supported by the deterministic clock contract`);
          }
          return node({ type: 'clock', name });
        }
      }
      fail('SDK_EXPRESSION_FORBIDDEN', `unknown or forbidden function or variable $${name}`);
    }
    if (identifierStart(character)) {
      const name = readIdentifier();
      if (name === 'true') return node({ type: 'literal', value: true });
      if (name === 'false') return node({ type: 'literal', value: false });
      if (name === 'null') return node({ type: 'literal', value: null });
      return node({ type: 'root', name });
    }
    unsafe(`syntax error: unexpected character '${character}' at offset ${pos}`);
  }

  return {
    parse() {
      skip();
      const ast = parseExpression();
      skip();
      if (pos !== source.length) unsafe(`syntax error: unexpected input at offset ${pos}`);
      return ast;
    },
  };
}

function expressionJsonEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => expressionJsonEqual(item, b[index]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    return aKeys.length === bKeys.length
      && aKeys.every((key) => Object.hasOwn(b, key) && expressionJsonEqual(a[key], b[key]));
  }
  return false;
}

function expressionNumber(value, operator) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression operator ${operator} requires finite number operands`);
  }
  return value;
}

function expressionString(value) {
  if (typeof value !== 'string') {
    fail('SDK_EXPRESSION_UNSAFE', 'rule.payloadExpression operator & requires two string operands');
  }
  return value;
}

function expressionBoolean(value, operator) {
  if (typeof value !== 'boolean') {
    fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression operator ${operator} requires boolean operands`);
  }
  return value;
}

function evaluateExpressionNode(ast, scope, clock, state) {
  expressionTick(state);
  state.depth += 1;
  if (state.depth > EXPRESSION_EVALUATE_DEPTH_MAX) {
    fail('SDK_EXPRESSION_BOUNDS', `rule.payloadExpression exceeds bounded expression evaluation depth (${EXPRESSION_EVALUATE_DEPTH_MAX})`);
  }
  try {
    return evaluateExpressionNodeInner(ast, scope, clock, state);
  } finally {
    state.depth -= 1;
  }
}

function evaluateExpressionNodeInner(ast, scope, clock, state) {
  switch (ast.type) {
    case 'literal':
      return ast.value;
    case 'clock':
      return ast.name === 'now' ? clock.now : clock.millis;
    case 'root':
      return Object.hasOwn(scope, ast.name) ? scope[ast.name] : MISSING;
    case 'field': {
      const base = evaluateExpressionNode(ast.base, scope, clock, state);
      if (base === MISSING) return MISSING;
      if (base === null || typeof base !== 'object') return MISSING;
      expressionTick(state);
      return Object.hasOwn(base, ast.name) ? base[ast.name] : MISSING;
    }
    case 'index': {
      const base = evaluateExpressionNode(ast.base, scope, clock, state);
      if (base === MISSING) return MISSING;
      if (!Array.isArray(base) || ast.index >= base.length) return MISSING;
      expressionTick(state);
      return base[ast.index];
    }
    case 'object': {
      const result = Object.create(null);
      for (const [key, valueAst] of ast.entries) {
        const value = evaluateExpressionNode(valueAst, scope, clock, state);
        if (value === MISSING) {
          fail('SDK_EXPRESSION_UNSAFE', 'rule.payloadExpression result is not portable JSON (unresolved path)');
        }
        result[key] = value;
      }
      return result;
    }
    case 'array': {
      const items = [];
      for (const itemAst of ast.items) {
        const value = evaluateExpressionNode(itemAst, scope, clock, state);
        if (value === MISSING) {
          fail('SDK_EXPRESSION_UNSAFE', 'rule.payloadExpression result is not portable JSON (unresolved path)');
        }
        items.push(value);
      }
      return items;
    }
    case 'neg': {
      const operand = expressionNumber(evaluateExpressionNode(ast.operand, scope, clock, state), '-');
      return -operand;
    }
    case 'binary':
      return evaluateExpressionBinary(ast, scope, clock, state);
    default:
      fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression cannot evaluate node ${String(ast.type)}`);
  }
}

function evaluateExpressionBinary(ast, scope, clock, state) {
  const operator = ast.operator;
  if (operator === '=' || operator === '!=') {
    const left = evaluateExpressionNode(ast.left, scope, clock, state);
    const right = evaluateExpressionNode(ast.right, scope, clock, state);
    if (left === MISSING && right === MISSING) return operator === '=';
    if (left === MISSING || right === MISSING) return operator !== '=';
    const equal = expressionJsonEqual(left, right);
    return operator === '=' ? equal : !equal;
  }
  const left = evaluateExpressionNode(ast.left, scope, clock, state);
  const right = evaluateExpressionNode(ast.right, scope, clock, state);
  switch (operator) {
    case '+':
    case '-':
    case '*':
    case '/':
    case '%': {
      const a = expressionNumber(left, operator);
      const b = expressionNumber(right, operator);
      const result = operator === '+' ? a + b : operator === '-' ? a - b : operator === '*' ? a * b : operator === '/' ? a / b : a % b;
      if (!Number.isFinite(result)) {
        fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression operator ${operator} produced a non-finite number`);
      }
      return result;
    }
    case '&':
      return `${expressionString(left)}${expressionString(right)}`;
    case 'and':
      return expressionBoolean(left, 'and') && expressionBoolean(right, 'and');
    case 'or':
      return expressionBoolean(left, 'or') || expressionBoolean(right, 'or');
    case '<':
    case '<=':
    case '>':
    case '>=': {
      if (typeof left === 'number' && typeof right === 'number') {
        const a = expressionNumber(left, operator);
        const b = expressionNumber(right, operator);
        return operator === '<' ? a < b : operator === '<=' ? a <= b : operator === '>' ? a > b : a >= b;
      }
      if (typeof left === 'string' && typeof right === 'string') {
        return operator === '<' ? left < right : operator === '<=' ? left <= right : operator === '>' ? left > right : left >= right;
      }
      return fail('SDK_EXPRESSION_UNSAFE', 'rule.payloadExpression ordering comparison requires two numbers or two strings');
    }
    default:
      fail('SDK_EXPRESSION_UNSAFE', `rule.payloadExpression unknown operator ${String(operator)}`);
  }
}

/**
 * Interpret one frozen declarative Kind into a data-only proposal, not a
 * committed Runtime decision. SDK never executes a physical effect and
 * cannot authorize state, release or access control.
 */
export function interpret(declaration, rawInput, rawContext = {}) {
  const definition = record(data(declaration), 'declaration');
  const input = record(data(rawInput), 'input');
  data(rawContext); // validated but ignored for all security/measurement claims
  // #994 selected Kernel's rule endpoint supplies {ruleId,eventType,
  // payloadFromInput} with no generic {kind,id} wrapper. This is a
  // current-v0.8 K/S composition contract, not legacy public API support.
  // Do not guess a Kind from business input; the only permitted shorthand
  // is an explicit ruleId on an otherwise data-only Rule declaration.
  const shorthandRule = definition.kind === undefined
    && Object.hasOwn(definition, 'ruleId')
    && typeof definition.ruleId === 'string';
  const kind = shorthandRule ? 'rule' : definition.kind;
  const id = ident(shorthandRule ? definition.ruleId : definition.id, 'declaration.id');
  let result;
  switch (kind) {
    case 'schema': result = schema(definition, input); break;
    case 'rule': result = rule(definition, input); break;
    case 'decision': result = decision(definition, input); break;
    case 'workflow': result = workflow(definition, input); break;
    case 'operation': result = operation(definition, input); break;
    case 'semantic-decision': result = semanticDecision(definition, input, rawContext); break;
    default: fail('SDK_KIND_UNSUPPORTED', `unsupported Standard Kind ${String(kind)}`);
  }
  return { ...result, ...evidence(id) };
}


/**
 * FR08 model measurement capability, scoped to the protected Host bootstrap.
 *
 * Binding authority is NOT established by this ordinary JS factory. Only the
 * trusted Host, holding the module namespace behind qualified load(), may
 * supply an actual ModelPort and expose the returned resolver to K. Neither
 * a Business declaration nor interpret(..., context) can install one.
 *
 * A port invocation count is an observation of CALLS THROUGH THIS BOUND PORT
 * for this resolution, not a derived number from model text, journal entries,
 * user-provided context or historical fast-path assumptions. Without a
 * Host-bound port, plain interpret() emits 'unsupported'.
 *
 * The factory never mutates Domain state or commits a tool/effect/journal.
 */
export function createHostBoundModelResolver(hostModelPort, options = {}) {
  if (typeof hostModelPort !== 'object' || hostModelPort === null) {
    fail('SDK_MODEL_PORT_INVALID', 'a protected Host ModelPort object is required');
  }
  const descriptor = Object.getOwnPropertyDescriptor(hostModelPort, 'invoke');
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
    fail('SDK_MODEL_PORT_INVALID', 'Host ModelPort.invoke must be a direct callable');
  }
  const invoke = descriptor.value.bind(hostModelPort);
  const config = data(options);
  const metered = config.metering === undefined || config.metering === 'measured';
  if (config.metering !== undefined && config.metering !== 'measured' && config.metering !== 'unmeasured') {
    fail('SDK_MODEL_PORT_INVALID', 'Host metering mode must be measured or unmeasured');
  }

  function observation(count) {
    return metered
      ? { status: 'measured', count, scope: 'bound-model-port-invocations' }
      : { status: 'unmeasured' };
  }

  return Object.freeze({
    /**
     * Model-free success: zero actual calls THROUGH THIS PORT. This does
     * not assert a global or cross-component LLM accounting total.
     */
    interpret(declaration, input, callerContext = {}) {
      const resolved = interpret(declaration, input, callerContext);
      return {
        ...resolved,
        modelCallEvidence: observation(0),
      };
    },
    /**
     * Fresh ModelPort invocation, with result captured as JSON. K alone can
     * admit the returned proposed decision, enforce guards and write state.
     */
    async invokeDecision(declaration, input, callerContext = {}) {
      const plan = record(data(declaration), 'model declaration');
      const selectedInput = record(data(input), 'model input');
      data(callerContext); // ignored for accounting; user-supplied meters cannot attest calls
      if (plan.kind !== 'model-decision') {
        fail('SDK_KIND_UNSUPPORTED', 'Host ModelPort invocation requires an explicit model-decision declaration');
      }
      const declarationId = ident(plan.id, 'model-decision.id');
      const modelOperation = ident(plan.modelOperation, 'model-decision.modelOperation');
      let output;
      try {
        output = await invoke({ operation: modelOperation, input: selectedInput });
      } catch (_error) {
        fail('SDK_MODEL_PORT_FAILED', 'trusted Host ModelPort invocation failed; no decision admitted');
      }
      const decision = data(output);
      record(decision, 'model result');
      if (!Object.hasOwn(decision, 'decision') || !Object.hasOwn(decision, 'event')) {
        fail('SDK_MODEL_OUTPUT_INVALID', 'ModelPort output requires structured decision and event');
      }
      return {
        kind: 'model-decision',
        structuredDecision: decision,
        provenance: { sdkModule: MODULE_ID, declarationId },
        source: 'host-model-port',
        llmAvoided: false,
        modelCallEvidence: observation(1),
        cacheDisposition: { read: 'disabled' },
        telemetry: [],
      };
    },
    /**
     * FR07-S1 single-step envelope surface (#1003 slice 1) — additive and
     * currently UNSELECTED: the Kernel keeps calling interpret/invokeDecision
     * only, until the FR07 K/H successor owns the bounded continuation loop.
     *
     * Runs exactly ONE physical ModelPort invocation and parses the model
     * output into a strict data-only step envelope:
     *   {kind:'query', call:{capabilityId,input}, modelCallEvidence,...}
     *   {kind:'final', structuredDecision, modelCallEvidence,...}
     * The query call is an inert PROPOSAL for K-owned authorization: S never
     * executes it, never reads Host storage and never commits state/effect/
     * journal. The evidence is this resolver's own observation of the single
     * bound-port call; a model- or caller-supplied count can never reach it.
     * No continuation, no maxSteps and no cancellation live here — those are
     * K/H-owned in the FR07 successor per the #1003 admission.
     */
    async invokeStep(declaration, input, callerContext = {}) {
      const plan = record(data(declaration), 'model declaration');
      const selectedInput = record(data(input), 'model input');
      data(callerContext); // ignored for accounting; user-supplied meters cannot attest calls
      if (plan.kind !== 'model-decision') {
        fail('SDK_KIND_UNSUPPORTED', 'Host ModelPort invocation requires an explicit model-decision declaration');
      }
      const declarationId = ident(plan.id, 'model-decision.id');
      const modelOperation = ident(plan.modelOperation, 'model-decision.modelOperation');
      let output;
      try {
        output = await invoke({ operation: modelOperation, input: selectedInput });
      } catch (_error) {
        fail('SDK_MODEL_PORT_FAILED', 'trusted Host ModelPort invocation failed; no step envelope admitted');
      }
      const snapshot = data(output);
      stepRecord(snapshot, 'model step output');
      const parsed = parseStepEnvelope(snapshot);
      const evidenceBase = {
        provenance: { sdkModule: MODULE_ID, declarationId },
        source: 'host-model-port',
        llmAvoided: false,
        modelCallEvidence: observation(1),
        cacheDisposition: { read: 'disabled' },
        telemetry: [],
      };
      const envelope = parsed.stepKind === 'query'
        ? { kind: 'query', call: { capabilityId: parsed.capabilityId, input: parsed.input }, ...evidenceBase }
        : { kind: 'final', structuredDecision: parsed.structuredDecision, ...evidenceBase };
      // v0.7 boundary (FR02 precedent): hand callers plain JSON, never the
      // internal null-prototype constructions. The round-trip also proves
      // the envelope is inert serializable data — no callable, no Host handle.
      return JSON.parse(JSON.stringify(envelope));
    },
  });
}

/**
 * Retention: v0.7 ProjectionService @86110c6 blob 52b3127..., reduced to
 * the Standard-package-owned *deterministic projection* boundary.
 *
 * All source reads/currentness and exposure admission belong to K + trusted
 * Host. This method cannot read them or mint a provenance revision. It
 * consumes ONLY snapshots with exact K-attested revision selectors and yields
 * an inert projection candidate. Revision mismatch is fail-closed.
 */
export function projectRetainedRead(rawDeclaration, rawSnapshots) {
  const declaration = record(data(rawDeclaration), 'projection declaration');
  const snapshots = record(data(rawSnapshots), 'projection snapshots');
  const id = ident(declaration.projectionId, 'projectionId');
  const dependencies = declaration.dependencies;
  if (!Array.isArray(dependencies) || dependencies.length === 0 || dependencies.length > MAX_CASES) {
    fail('SDK_PROJECTION_INVALID', 'projection requires a bounded non-empty dependency list');
  }
  const assembled = Object.create(null);
  const revisions = Object.create(null);
  const keys = new Set();
  for (const dependency of dependencies) {
    record(dependency, 'projection dependency');
    const name = ident(dependency.name, 'projection dependency name');
    if (keys.has(name)) fail('SDK_PROJECTION_INVALID', 'ambiguous duplicate projection source');
    keys.add(name);
    const source = snapshots[name];
    if (source === undefined) fail('SDK_PROJECTION_MISSING', 'projection dependency is unavailable');
    record(source, 'projection source');
    const revision = ident(source.revision, 'projection source revision');
    const expected = ident(dependency.expectedRevision, 'projection expected revision');
    if (revision !== expected) fail('SDK_PROJECTION_STALE', 'the supplied source revision differs from the pinned projection');
    if (!Object.hasOwn(source, 'value')) fail('SDK_PROJECTION_MISSING', 'projection source contains no value');
    assembled[name] = source.value;
    revisions[name] = revision;
  }
  const fields = record(declaration.fields, 'projection fields');
  const candidate = Object.create(null);
  for (const [outputName, sourceName] of Object.entries(fields)) {
    ident(outputName, 'projection output');
    if (typeof sourceName !== 'string' || !Object.hasOwn(assembled, sourceName)) {
      fail('SDK_PROJECTION_INVALID', 'a projected field must reference a declared source');
    }
    candidate[outputName] = assembled[sourceName];
  }
  return {
    kind: 'projection',
    projectionId: id,
    candidate,
    sourceRevisions: revisions,
    revisionEvidence: { status: 'unmeasured' }, // only H can attest a revision digest
    authority: 'proposal-only',
  };
}

/**
 * Retention of the v0.7 resolver ordering (resolver.ts@86110c6
 * blob 25e8a621...): Rule -> Exact Cache -> Promoted -> Harness.
 * This does NOT execute any source. K passes current qualified observations;
 * the Standard SDK emits only a selected candidate. An unqualified cache
 * hit, stale promoted artifact, or missing harness is never auto-admitted.
 */
export function resolveRetainedDecision(rawSelection) {
  const selected = record(data(rawSelection), 'decision source selection');
  const id = ident(selected.decisionId, 'decisionId');
  const observations = record(selected.observations ?? {}, 'decision observations');
  const sources = ['rule', 'exact-cache', 'promoted-subworkflow', 'harness-machine'];
  for (const source of sources) {
    const observation = observations[source];
    if (observation === undefined) continue;
    record(observation, 'decision observation');
    switch (observation.status) {
      case 'not-applicable':
      case 'miss':
        continue;
      case 'revoked-deny':
      case 'failed':
        fail('SDK_DECISION_SOURCE_REFUSED', `source ${source} refuses or failed`);
        break;
      case 'match':
        if (!Object.hasOwn(observation, 'candidate')) fail('SDK_DECISION_SOURCE_INVALID', 'matching source has no candidate');
        if (source === 'exact-cache' && observation.exactCurrent !== true) {
          fail('SDK_DECISION_SOURCE_REFUSED', 'cache hit has no exact-currentness evidence');
        }
        if (source === 'promoted-subworkflow' && observation.artifactCurrent !== true) {
          fail('SDK_DECISION_SOURCE_REFUSED', 'promoted child is not verified current');
        }
        return {
          kind: 'decision-source',
          decisionId: id,
          selectedSource: source,
          candidate: observation.candidate,
          provenance: { sdkModule: MODULE_ID, authority: 'proposal-only' },
          modelCallEvidence: { status: 'unsupported' },
        };
      default:
        fail('SDK_DECISION_SOURCE_INVALID', 'unknown resolver source disposition');
    }
  }
  fail('SDK_DECISION_HARNESS_UNCONFIGURED', 'no admitted resolver candidate; no unbounded retries or invented fallback');
}

/**
 * Agent-safe Operation exposure projection ported from the frozen
 * v0.7 agent-tool-projection.ts@86110c6 blob 70932bed...
 * An S projection is never admission. Mutation-capable operations MUST NOT
 * acquire a query route merely because they were listed for an agent.
 */
export function projectRetainedAgentTools(rawOperations) {
  const operations = data(rawOperations);
  if (!Array.isArray(operations) || operations.length > MAX_CASES) {
    fail('SDK_TOOL_SURFACE_INVALID', 'operations must be a bounded list');
  }
  const tools = [];
  const seen = new Set();
  for (const operation of operations) {
    record(operation, 'operation descriptor');
    const id = ident(operation.operationId, 'operationId');
    if (seen.has(id)) fail('SDK_TOOL_SURFACE_INVALID', 'duplicate operation');
    seen.add(id);
    if (operation.agentExposed !== true) continue;
    if (operation.effectClass !== 'none') {
      fail('SDK_AGENT_MUTATION_REFUSED', 'agent read-only projection rejects effectful operation');
    }
    tools.push({ operationId: id, effectClass: 'none', authority: 'projection-only' });
  }
  return { kind: 'agent-tool-surface', tools, authority: 'projection-only' };
}

// #1006 FR11/HF24 retained compiled-package-data read. The SECTION is the
// BUILD-compiled package-data compound sealed inside the Business module
// bytes (compiler domainData/businessSources sections plus the compiled
// projection declarations that bind them); the trusted Host load boundary
// already re-validated it with the production integrity validators before
// this projection ever ran. This endpoint owns ONLY the deterministic,
// fail-closed READ: declared-key projection in the compiled key order and
// business-source observation admission against the compiler-declared
// schema contract. It has no hash port — content digests are the sealed
// descriptors', verified once at the trusted load boundary, never recomputed
// here. No state, no effects, no authority: the result is inert data.
const COMPILED_SCHEMA_TYPES = new Set(['string', 'integer', 'number', 'boolean', 'object', 'array', 'null']);
const COMPILED_SCHEMA_KEYS = new Set(['type', 'required', 'properties', 'additionalProperties', 'minimum']);

function compiledKeyOrder(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * Bounded evaluation of a compiler-declared valueSchema against one
 * observation value. The authoritative DomainHarness JSON Schema v1
 * validation runs at the trusted load boundary over the SECTION; this
 * read-time check fail-closes stale/substituted OBSERVATIONS before they
 * can enter a projection result. A declared schema using keywords outside
 * this bounded subset refuses the read typed rather than under-validate.
 */
function assertCompiledSchema(rawSchema, value, label, violationCode) {
  const schema = record(rawSchema, `${label} schema`);
  for (const key of Object.keys(schema)) {
    if (!COMPILED_SCHEMA_KEYS.has(key)) {
      fail('SDK_COMPILED_DATA_SCHEMA_UNSUPPORTED', `${label} schema uses keyword '${key}' outside the retained read subset`);
    }
  }
  if (schema.type !== undefined) {
    if (typeof schema.type !== 'string' || !COMPILED_SCHEMA_TYPES.has(schema.type)) {
      fail('SDK_COMPILED_DATA_SCHEMA_UNSUPPORTED', `${label} schema declares an unsupported type`);
    }
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    if (schema.type === 'integer') {
      if (typeof value !== 'number' || !Number.isInteger(value)) {
        fail(violationCode, `${label} value is ${actual}, expected integer`);
      }
    } else if (actual !== schema.type) {
      fail(violationCode, `${label} value is ${actual}, expected ${schema.type}`);
    }
  }
  if (schema.minimum !== undefined) {
    if (typeof schema.minimum !== 'number' || !Number.isFinite(schema.minimum)) {
      fail('SDK_COMPILED_DATA_SCHEMA_UNSUPPORTED', `${label} schema minimum must be a finite number`);
    }
    if (typeof value !== 'number' || value < schema.minimum) {
      fail(violationCode, `${label} value is below the declared minimum`);
    }
  }
  if (schema.required !== undefined) {
    if (!Array.isArray(schema.required)) {
      fail('SDK_COMPILED_DATA_SCHEMA_UNSUPPORTED', `${label} schema required must be an array`);
    }
    for (const name of schema.required) {
      if (typeof name !== 'string') {
        fail('SDK_COMPILED_DATA_SCHEMA_UNSUPPORTED', `${label} schema required entries must be strings`);
      }
      if (!Object.hasOwn(value ?? {}, name)) {
        fail(violationCode, `${label} value is missing the required field ${name}`);
      }
    }
  }
  if (schema.properties !== undefined) {
    const properties = record(schema.properties, `${label} schema properties`);
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      for (const [name, subSchema] of Object.entries(properties)) {
        if (Object.hasOwn(value, name)) assertCompiledSchema(subSchema, value[name], `${label}.${name}`, violationCode);
      }
    }
    if (schema.additionalProperties === false) {
      for (const name of Object.keys(value ?? {})) {
        if (!Object.hasOwn(properties, name)) {
          fail(violationCode, `${label} value carries the undeclared field ${name}`);
        }
      }
    }
  } else if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== 'boolean') {
    fail('SDK_COMPILED_DATA_SCHEMA_UNSUPPORTED', `${label} schema additionalProperties must be a boolean when present`);
  }
}

function compiledDescriptorList(section, field, label) {
  const container = record(section[field], `compiled package data ${label}`);
  const descriptors = container.descriptors;
  if (!Array.isArray(descriptors)) {
    fail('SDK_COMPILED_DATA_INVALID', `compiled package data ${label} descriptors must be an array`);
  }
  return { container, descriptors };
}

/**
 * FR11/HF24: project the sealed compiled Domain Data / Business Source
 * section. `keys` selects Domain Data entries (undeclared keys refuse
 * typed); the response ALWAYS carries entries in the compiled deterministic
 * key order regardless of request order. `businessSources` are observation
 * bindings `{source, value}`: each source must be declared by the compiled
 * section and each value must satisfy the compiler-declared valueSchema
 * (substituted/aliased sources and stale schemas fail closed before any
 * observation enters the result). The compiled projection declarations are
 * returned as inert binding evidence; this projection executes none of them.
 */
export function projectRetainedCompiledData(rawSection, rawRequest) {
  const section = record(data(rawSection), 'compiled package data section');
  const request = record(data(rawRequest), 'compiled package data read');
  for (const key of Object.keys(section)) {
    if (key !== 'domainData' && key !== 'businessSources' && key !== 'projections') {
      fail('SDK_COMPILED_DATA_INVALID', `compiled package data section carries the unsupported field '${key}'`);
    }
  }
  const { descriptors: dataDescriptors, container: dataContainer } = compiledDescriptorList(section, 'domainData', 'Domain Data');
  const values = record(dataContainer.values, 'compiled Domain Data values');
  const declaredKeys = [];
  for (const descriptor of dataDescriptors) {
    record(descriptor, 'Domain Data descriptor');
    const key = ident(descriptor.key, 'Domain Data descriptor key');
    if (typeof descriptor.contentDigest !== 'string' || descriptor.contentDigest.length === 0) {
      fail('SDK_COMPILED_DATA_INVALID', `Domain Data descriptor '${key}' carries no content digest`);
    }
    if (descriptor.valueSchema !== undefined) record(descriptor.valueSchema, `Domain Data '${key}' valueSchema`);
    if (!Object.hasOwn(values, key)) {
      fail('SDK_COMPILED_DATA_INVALID', `Domain Data descriptor '${key}' has no bundled value`);
    }
    declaredKeys.push(key);
  }
  const sortedKeys = [...declaredKeys].sort(compiledKeyOrder);
  if (declaredKeys.some((key, index) => key !== sortedKeys[index])) {
    fail('SDK_COMPILED_DATA_ORDER_INVALID', 'Domain Data descriptors are not in the compiled deterministic key order');
  }

  const { container: sourceContainer, descriptors: sourceDescriptors } = compiledDescriptorList(section, 'businessSources', 'Business Sources');
  // The schema contract version is a versioned contract identity (it may
  // carry '/'), not a declaration identifier: bounded text, exact match
  // pinned by the sealed section itself.
  const schemaContractVersion = boundedText(sourceContainer.schemaContractVersion, 'Business Source schemaContractVersion');
  const declaredSources = [];
  for (const descriptor of sourceDescriptors) {
    record(descriptor, 'Business Source descriptor');
    const source = ident(descriptor.source, 'Business Source name');
    record(descriptor.valueSchema, `Business Source '${source}' valueSchema`);
    declaredSources.push(source);
  }
  const sortedSources = [...declaredSources].sort(compiledKeyOrder);
  if (declaredSources.some((source, index) => source !== sortedSources[index])) {
    fail('SDK_COMPILED_DATA_ORDER_INVALID', 'Business Source descriptors are not in the compiled deterministic source order');
  }
  const projections = record(section.projections ?? {}, 'compiled projections');
  for (const [id, projection] of Object.entries(projections)) {
    record(projection, `compiled projection '${id}'`);
    if (projection.projectionId !== id) {
      fail('SDK_COMPILED_DATA_INVALID', `compiled projection '${id}' carries a mismatched projectionId`);
    }
  }

  const requestedKeys = request.keys === undefined ? [...declaredKeys] : request.keys;
  if (!Array.isArray(requestedKeys) || requestedKeys.length > MAX_ITEMS) {
    fail('SDK_COMPILED_DATA_INVALID', 'the read keys must be a bounded list');
  }
  const wanted = new Set();
  for (const key of requestedKeys) {
    ident(key, 'read key');
    if (!Object.hasOwn(values, key)) {
      fail('SDK_DOMAIN_DATA_KEY_UNDECLARED', `Domain Data key '${key}' is not declared by the compiled section`);
    }
    wanted.add(key);
  }
  const observations = request.businessSources === undefined ? [] : request.businessSources;
  if (!Array.isArray(observations) || observations.length > MAX_ITEMS) {
    fail('SDK_COMPILED_DATA_INVALID', 'business source observations must be a bounded list');
  }
  const boundSources = [];
  const seenBindings = new Set();
  for (const observation of observations) {
    record(observation, 'business source observation');
    const source = ident(observation.source, 'business source observation source');
    if (seenBindings.has(source)) {
      fail('SDK_BUSINESS_SOURCE_AMBIGUOUS', `business source '${source}' is bound more than once`);
    }
    seenBindings.add(source);
    const descriptor = sourceDescriptors.find((entry) => entry.source === source);
    if (descriptor === undefined) {
      fail('SDK_BUSINESS_SOURCE_UNDECLARED', `business source '${source}' is not declared by the compiled section`);
    }
    assertCompiledSchema(descriptor.valueSchema, observation.value, `business source '${source}' observation`, 'SDK_BUSINESS_SOURCE_SCHEMA_VIOLATION');
    boundSources.push({ source, schemaContractVersion });
  }

  // Entries are ALWAYS emitted in the compiled deterministic key order —
  // the request order can never reorder the projection result.
  const entries = [];
  for (const key of declaredKeys) {
    if (!wanted.has(key)) continue;
    const descriptor = dataDescriptors.find((entry) => entry.key === key);
    entries.push({
      key,
      value: values[key],
      contentDigest: descriptor.contentDigest,
      ...(descriptor.valueSchema === undefined ? {} : { valueSchema: descriptor.valueSchema }),
    });
  }
  return {
    kind: 'compiled-data-projection',
    entries,
    businessSourceContracts: boundSources,
    compiledProjections: Object.keys(projections).sort(),
    schemaContractVersion,
    authority: 'proposal-only',
  };
}

/**
 * #v0.6 NF05/NF06 retained decision handoff as inert data: exact assembly
 * qualification and durable append are K-owned, not Standard SDK authority.
 */
export function makeRetainedDecisionReceipt(rawResolution) {
  const resolution = record(data(rawResolution), 'decision resolution');
  const decisionId = ident(resolution.decisionId, 'decisionId');
  const turnId = ident(resolution.turnId, 'turnId');
  const source = ident(resolution.source, 'decision source');
  if (!Object.hasOwn(resolution, 'decision')) {
    fail('SDK_DECISION_RECEIPT_INVALID', 'decision receipt has no resolved decision');
  }
  return {
    kind: 'decision-receipt-proposal',
    eventType: 'DECISION_RECEIPT',
    decisionId,
    turnId,
    source,
    decision: resolution.decision,
    authority: 'proposal-only',
    durableAppend: 'required-by-kernel',
  };
}

/**
 * #1003 NF06 OBSERVATIONAL_OPTIONAL — bounded, redacted, DATA-ONLY decision
 * receipt projection. The Kernel hands in ONLY material it has already
 * verified (the derived durable turn identity, the approved declaration
 * identity, the resolved structured decision) plus the declaring receipt
 * policy; this projection reduces it to an allowlist — decision outcome and
 * event TYPE only. Raw input payloads, credentials and any model text can
 * never enter the record: they are not on the allowlist even when present
 * in the verified material. S owns no durable append: the returned record
 * is inert data the Kernel alone may persist through the Host CAS port.
 */
export function projectDecisionReceiptRecord(rawVerified) {
  const verified = record(data(rawVerified), 'verified decision material');
  // The durable turn id / workflow instance id are K-derived opaque
  // addresses (URL-encoded components), not declaration identifiers: they
  // are validated as bounded non-empty text, never identifier-shaped.
  const turnId = boundedText(verified.turnId, 'turnId');
  const workflowInstanceId = boundedText(verified.workflowInstanceId, 'workflowInstanceId');
  const declaration = record(verified.declaration, 'declaration identity');
  const ruleId = ident(declaration.ruleId, 'declaration.ruleId');
  const declarationDigest = declaration.declarationDigest === undefined
    ? undefined
    : boundedText(declaration.declarationDigest, 'declaration.declarationDigest');
  const durability = verified.durability;
  if (durability !== 'observational-optional') {
    fail('SDK_DECISION_RECEIPT_RECORD_INVALID', 'a data-only decision receipt projects the observational-optional durability only; durable-mandatory coordination is Kernel/Host authority, never an S claim');
  }
  const resolved = record(verified.resolved, 'verified resolution');
  const source = ident(resolved.source, 'resolution source');
  const structured = record(resolved.structuredDecision, 'resolved structured decision');
  const decision = record(structured.decision, 'resolved decision');
  const outcome = ident(decision.outcome, 'resolved decision outcome');
  const event = record(structured.event, 'resolved event');
  const eventType = ident(event.type, 'resolved event type');
  if (typeof resolved.llmAvoided !== 'boolean') {
    fail('SDK_DECISION_RECEIPT_RECORD_INVALID', 'the verified resolution must carry a boolean llmAvoided truth');
  }
  let modelCallEvidence;
  if (resolved.modelCallEvidence === undefined) {
    modelCallEvidence = { status: 'unsupported' };
  } else {
    const evidence = record(resolved.modelCallEvidence, 'model call evidence');
    const keys = Object.keys(evidence).sort().join(',');
    if (evidence.status === 'measured' && Number.isSafeInteger(evidence.count) && evidence.count >= 0
      && typeof evidence.scope === 'string' && keys === 'count,scope,status') {
      modelCallEvidence = { status: 'measured', count: evidence.count, scope: evidence.scope };
    } else if ((evidence.status === 'unmeasured' || evidence.status === 'unsupported') && keys === 'status') {
      modelCallEvidence = { status: evidence.status };
    } else {
      fail('SDK_DECISION_RECEIPT_RECORD_INVALID', 'model call evidence must be the structured measured/unmeasured/unsupported record');
    }
  }
  return {
    kind: 'decision-receipt-record',
    eventType: 'DECISION_RECEIPT',
    turnId,
    workflowInstanceId,
    declaration: declarationDigest === undefined ? { ruleId } : { ruleId, declarationDigest },
    decision: { outcome },
    event: { type: eventType },
    source,
    llmAvoided: resolved.llmAvoided,
    modelCallEvidence,
    durability,
    authority: 'data-only',
  };
}

/**
 * FR09 source reuse: promoted-child/selection + runtime@86110c6
 * blob e7e73afc...; qualified selection is a *candidate*, never an
 * executable child or substituted package authority.
 */
export function selectRetainedPromotedChild(rawSelection) {
  const choice = record(data(rawSelection), 'promoted child selection');
  const requested = record(choice.requested, 'requested promoted artifact');
  const approved = record(choice.approved, 'approved promoted artifact');
  const artifactId = ident(requested.artifactId, 'requested.artifactId');
  const contentDigest = ident(requested.contentDigest, 'requested.contentDigest');
  if (approved.artifactId !== artifactId || approved.contentDigest !== contentDigest) {
    fail('SDK_CHILD_IDENTITY_MISMATCH', 'promoted child does not match the approved exact artifact');
  }
  if (approved.revoked === true || approved.applicable !== true || approved.compatible !== true) {
    fail('SDK_CHILD_NOT_ELIGIBLE', 'promoted child is revoked, incompatible or not applicable');
  }
  if (choice.pinCommitted !== true) {
    fail('SDK_CHILD_PIN_REQUIRED', 'durable pin-before-execution must be established by Kernel');
  }
  return {
    kind: 'promoted-child-candidate',
    artifactId, contentDigest, authority: 'proposal-only',
    operation: 'run-in-authoritative-kernel-only',
  };
}

/**
 * HF17: v0.7 SubscriptionRegistry @86110c6 blob 52177373...
 * Deterministic coalescing of delivered revision observations, not Host
 * registration, authorization, resubscription or event dispatch.
 * Subscription currentness and credentials MUST be revalidated by H for
 * every physical delivery.
 */
export function coalesceRetainedObservations(rawObservations) {
  const observations = data(rawObservations);
  if (!Array.isArray(observations) || observations.length > MAX_ITEMS) {
    fail('SDK_SUBSCRIPTION_INVALID', 'observations must be a bounded data list');
  }
  const byId = new Map();
  for (const event of observations) {
    record(event, 'revision observation');
    const subscriptionId = ident(event.subscriptionId, 'subscriptionId');
    const revision = ident(event.revision, 'subscription revision');
    const epoch = event.epoch;
    if (!Number.isSafeInteger(epoch) || epoch < 0) {
      fail('SDK_SUBSCRIPTION_INVALID', 'an observation must have a nonnegative monotonic epoch');
    }
    const previous = byId.get(subscriptionId);
    if (previous && epoch < previous.epoch) {
      fail('SDK_SUBSCRIPTION_STALE', 'a reordered older observation cannot replace a newer revision');
    }
    if (previous && epoch === previous.epoch && revision !== previous.revision) {
      fail('SDK_SUBSCRIPTION_AMBIGUOUS', 'equal monotonic epochs with different revisions');
    }
    if (!previous || epoch > previous.epoch) byId.set(subscriptionId, { subscriptionId, revision, epoch });
  }
  return { kind: 'subscription-projection', observations: [...byId.values()], authority: 'projection-only' };
}

/**
 * FR12 evidence applicability from use-gate.ts@86110c6
 * blob 701ecad...; no credential minting. A claimed record is only a
 * *semantic applicability candidate*, not a signed/durable audit proof.
 */
export function checkRetainedEvidenceApplicability(rawRecord, rawExpected) {
  const receipt = record(data(rawRecord), 'evidence record');
  const expected = record(data(rawExpected), 'evidence required provenance');
  const packageId = ident(expected.packageId, 'expected packageId');
  const baselineDigest = ident(expected.baselineDigest, 'expected baselineDigest');
  if (receipt.packageId !== packageId || receipt.baselineDigest !== baselineDigest) {
    fail('SDK_EVIDENCE_SCOPE_MISMATCH', 'evidence belongs to a different package or governance baseline');
  }
  if (expected.durableAuditRequired === true && receipt.durableAudit !== true) {
    fail('SDK_EVIDENCE_DURABILITY_REQUIRED', 'governed evaluation requires durable audit evidence');
  }
  return { kind: 'evidence-applicability', eligibleForHostVerification: true, authority: 'proposal-only' };
}
