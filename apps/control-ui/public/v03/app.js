// Bounded v03 Control UI (T10, Issue #238).
//
// Same-origin only: every request goes to /api on the loopback origin that
// served this page. The UI renders the current guided step, the selected-root
// scope, progress/history and honest REFUSED/UNKNOWN states; it relays an
// explicit human decision and never constructs a grant or approval itself.
// All display decisions come from the pure view-model; this file only wires
// the DOM to it.
import { t } from './strings.js';
import {
  advisoryView,
  buildStepOutcome,
  consentView,
  currentStepModel,
  historyModel,
  progressModel,
  refusalView,
  replayGuard,
  scopeSummary,
  userDecisionRelay,
} from './view-model.js';

const STATE_ENDPOINT = '/api/v03/guided/state';
const DECISION_ENDPOINT = '/api/v03/guided/decision';

/** Replay ledger for this page session: keys of outcomes already relayed. */
/** @type {string[]} */
const relayedKeys = [];

/** @type {any} */
let currentStep = undefined;
const locale = /** @type {'en'|'zh'} */ (
  (navigator.language ?? 'en').toLowerCase().startsWith('zh') ? 'zh' : 'en'
);

function el(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const node = el(id);
  if (node) node.textContent = text;
}

/**
 * Loud-fail lookup: a missing or unbound key throws instead of rendering the
 * raw key name. Callers catch and show the reason as an UNKNOWN/error state,
 * so a future catalog gap can never silently degrade into machine text.
 */
function text(key) {
  const line = t(locale, key);
  if (!line.ok) throw new Error(`${line.code}: ${line.reason}`);
  return line.text;
}

/**
 * Same-origin API call. Any failure surfaces as an explicit unknown banner —
 * the UI never invents state to cover an unreachable backend.
 * @param {string} path
 * @param {{ method?: string, body?: unknown }} [options]
 */
async function api(path, options) {
  const response = await fetch(path, {
    method: options?.method ?? (options?.body !== undefined ? 'POST' : 'GET'),
    headers: options?.body === undefined ? undefined : { 'content-type': 'application/json' },
    body: options?.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const body = await response.json().catch(() => undefined);
  if (!response.ok) {
    throw new Error(
      typeof body?.error?.detail === 'string' ? body.error.detail : `API responded ${response.status}`,
    );
  }
  return body;
}

function renderScope(scope) {
  const model = scopeSummary(scope, locale);
  const box = el('v03-scope');
  if (!box) return;
  box.innerHTML = '';
  const line = document.createElement('p');
  if (model.status === 'REFUSED') {
    throw new Error(model.reason);
  } else if (model.status === 'NONE') {
    line.className = 'muted';
    line.textContent = model.label;
  } else if (model.status === 'UNKNOWN') {
    line.className = 'unknown';
    line.textContent = `${text('state.unknown')} — ${model.label}`;
  } else {
    line.className = 'ok';
    line.textContent = model.label;
  }
  box.append(line);
}

/**
 * Journey progress / paused panel. Renders only what the guided state
 * actually carries: a real position ("Step x of y") or an explicit UNKNOWN,
 * plus the paused reason when the journey is paused.
 */
function renderProgress(journey) {
  const box = el('v03-progress');
  if (!box) return;
  box.innerHTML = '';
  const model = progressModel(journey, locale);
  if (!model.ok) {
    throw new Error(model.reason);
  }
  const positionLine = document.createElement('p');
  positionLine.textContent = model.position.text;
  positionLine.className = model.position.known ? 'muted' : 'unknown';
  box.append(positionLine);
  if (model.status === 'PAUSED') {
    const pausedLine = document.createElement('p');
    pausedLine.className = 'warn';
    pausedLine.textContent = `${text('state.paused')} — ${model.pausedReason ?? ''}`;
    box.append(pausedLine);
  } else if (model.status === 'UNKNOWN') {
    // The paused flag was not a clean true/false: say Unknown, never coerce.
    const unknownLine = document.createElement('p');
    unknownLine.className = 'unknown';
    unknownLine.textContent = text('state.unknown');
    box.append(unknownLine);
  }
}

function renderStep(step) {
  const box = el('v03-step');
  if (!box) return;
  box.innerHTML = '';
  const model = currentStepModel(step, Date.now());
  const heading = document.createElement('h3');
  const detail = document.createElement('p');
  if (model.status === 'REFUSED') {
    const refusal = refusalView(model.code, locale);
    if (!refusal.ok) throw new Error(refusal.reason);
    heading.className = 'refused';
    heading.textContent = text('state.refused');
    detail.className = 'refused';
    detail.textContent = refusal.text;
  } else if (model.status === 'UNKNOWN') {
    heading.className = 'unknown';
    heading.textContent = text('state.unknown');
    detail.className = 'unknown';
    detail.textContent = model.reason;
  } else {
    heading.textContent = `${text('state.currentStep')} — ${text(model.titleKey)}`;
    detail.className = 'muted';
    detail.textContent =
      `${model.templateId} · ${model.journeyId} · ${model.taskId} · ${model.stepId} · digest ${model.templateDigest.slice(0, 12)}…`;
  }
  box.append(heading, detail);
}

function renderHistory(entries) {
  const box = el('v03-history');
  if (!box) return;
  box.innerHTML = '';
  const model = historyModel(entries, locale);
  if (!model.ok) {
    throw new Error(model.reason);
  }
  if (model.lines.length === 0) {
    const line = document.createElement('p');
    line.className = 'muted';
    line.textContent = text('history.empty');
    box.append(line);
    return;
  }
  for (const entry of model.lines) {
    const item = document.createElement('li');
    item.className = entry.success ? 'ok' : entry.tone === 'unknown' ? 'unknown' : 'refused';
    item.textContent = `${entry.at} — ${entry.text}`;
    box.append(item);
  }
}

function renderAdvisory(advisory) {
  const box = el('v03-advisory');
  if (!box) return;
  box.innerHTML = '';
  const model = advisoryView(advisory);
  const line = document.createElement('p');
  if (model.status === 'REFUSED') {
    line.className = 'refused';
    line.textContent = `${text('state.refused')} — ${model.reason}`;
  } else {
    line.className = 'muted';
    line.textContent = `${text('advisory.title')}: ${model.explanation} (${text('advisory.notAuthority')})`;
  }
  box.append(line);
}

function renderUnknownState(reason) {
  const banner = el('v03-banner');
  if (banner) {
    banner.className = 'unknown';
    banner.textContent = `${text('state.unknown')} — ${reason}`;
  }
  renderStep(undefined);
  renderProgress(undefined);
  renderHistory([]);
}

/**
 * Relay an explicit decision. `confirmed` is true only when this call comes
 * directly from a click on the approve/refuse button — there is no other
 * caller, so nothing can be approved without a human click.
 * @param {'APPROVE'|'REFUSE'} decision
 */
async function decide(decision) {
  const feedback = el('v03-decision-feedback');
  if (!feedback || !currentStep) return;
  try {
    const confirmed = true;
    const built = buildStepOutcome({
      step: currentStep,
      answers: collectAnswers(),
      sourceRef: 'ui:v03-session',
      occurredAtUnixMs: Date.now(),
    });
    if (!built.ok) {
      feedback.className = 'refused';
      feedback.textContent = `${text('state.refused')} — ${built.reason}`;
      return;
    }
    const relay = userDecisionRelay({
      step: currentStep,
      outcome: built.outcome,
      decision,
      confirmed,
      nowUnixMs: Date.now(),
    });
    if (!relay.ok) {
      const refusal = refusalView(relay.code, locale);
      if (!refusal.ok) throw new Error(relay.reason);
      feedback.className = 'refused';
      feedback.textContent = `${text('state.refused')} — ${refusal.text}`;
      return;
    }
    const replay = replayGuard(relayedKeys, built.outcome);
    if (!replay.allowed) {
      const refusal = refusalView(replay.code, locale);
      if (!refusal.ok) throw new Error(refusal.reason);
      feedback.className = 'refused';
      feedback.textContent = refusal.text;
      return;
    }
    feedback.className = 'muted';
    feedback.textContent = text('step.relayPending');
    // userDecisionRelay returns {ok,relay}; only the bounded relay payload is
    // accepted by the server. Do not serialize UI-local status as authority.
    const result = await api(DECISION_ENDPOINT, { body: relay.relay });
    if (result?.status !== 'RECORDED' || result?.humanGrantIssued !== false ||
        result?.effectSent !== false) {
      throw new Error('GUIDED_DECISION_OUTCOME_UNKNOWN');
    }
    // Record the replay key only after the relay succeeded: a network failure
    // must not permanently occupy the identity in this session (the Host's
    // CONSUMED state remains the authoritative replay fence).
    relayedKeys.push(replay.key);
    renderHistory(Array.isArray(result?.history) ? result.history : []);
    feedback.className = 'muted';
    feedback.textContent = `${text('state.ok')} — ${text('consent.notGrant')}`;
    await refresh();
  } catch (error) {
    const unknown = t(locale, 'state.unknown');
    feedback.className = 'unknown';
    feedback.textContent = `${unknown.ok ? unknown.text : 'UNKNOWN'} — ${
      error instanceof Error ? error.message : String(error)
    }`;
  }
}

/** Read the current step's form inputs into view-model answers. */
function collectAnswers() {
  /** @type {{ fieldId: string, value: string | boolean }[]} */
  const answers = [];
  const form = el('v03-step-form');
  if (!form) return answers;
  for (const input of form.querySelectorAll('[data-field-id]')) {
    const fieldId = input.getAttribute('data-field-id');
    if (!fieldId) continue;
    if (input instanceof HTMLInputElement && input.type === 'checkbox') {
      answers.push({ fieldId, value: input.checked });
    } else {
      answers.push({ fieldId, value: input.value });
    }
  }
  return answers;
}

function renderForm(model) {
  const form = el('v03-step-form');
  if (!form) return;
  form.innerHTML = '';
  for (const field of model.fields) {
    const label = document.createElement('label');
    label.textContent = text(field.labelKey);
    label.className = 'muted';
    /** @type {HTMLInputElement | HTMLSelectElement} */
    let input;
    if (field.type === 'CONFIRM') {
      input = document.createElement('input');
      /** @type {HTMLInputElement} */ (input).type = 'checkbox';
    } else if (field.type === 'CHOICE') {
      input = document.createElement('select');
      for (const option of field.options ?? []) {
        const choice = document.createElement('option');
        choice.value = option.id;
        choice.textContent = text(option.labelKey);
        /** @type {HTMLSelectElement} */ (input).append(choice);
      }
    } else {
      input = document.createElement('input');
      /** @type {HTMLInputElement} */ (input).type = 'text';
    }
    input.setAttribute('data-field-id', field.id);
    form.append(label, input);
  }
  const consent = consentView(locale);
  if (!consent.ok) throw new Error(consent.reason);
  const note = document.createElement('p');
  note.className = model.requiresExplicitApproval ? 'warn' : 'muted';
  note.textContent = model.requiresExplicitApproval ? consent.lines.join(' ') : '';
  form.append(note);
}

async function refresh() {
  try {
    const state = await api(STATE_ENDPOINT);
    currentStep = state?.currentStep;
    const banner = el('v03-banner');
    if (banner) banner.textContent = '';
    renderScope(state?.scope);
    renderProgress(state?.journey);
    renderStep(currentStep);
    const model = currentStepModel(currentStep, Date.now());
    if (model.status === 'CURRENT') renderForm(model);
    renderHistory(Array.isArray(state?.history) ? state.history : []);
    renderAdvisory(state?.advisory);
  } catch (error) {
    renderUnknownState(error instanceof Error ? error.message : String(error));
  }
}

const approveButton = el('v03-approve');
if (approveButton) {
  approveButton.textContent = text('step.approve');
  approveButton.addEventListener('click', () => {
    void decide('APPROVE');
  });
}
const refuseButton = el('v03-refuse');
if (refuseButton) {
  refuseButton.textContent = text('step.refuse');
  refuseButton.addEventListener('click', () => {
    void decide('REFUSE');
  });
}

try {
  setText('v03-title', text('app.title'));
  setText('v03-subtitle', text('app.subtitle'));
  setText('v03-scope-title', text('state.selectedScope'));
  setText('v03-progress-title', text('state.progress'));
  setText('v03-history-title', text('state.history'));
} catch (error) {
  renderUnknownState(error instanceof Error ? error.message : String(error));
}

void refresh();
