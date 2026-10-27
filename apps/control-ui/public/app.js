// Shun local control surface (T08 reference UI, L2 §12).
//
// Same-origin only: every request goes to /api on the loopback origin that
// served this page. The UI renders and relays; it never constructs
// authorization and never talks to anything but the local control-api.
import {
  approvalDecisionState,
  decisionGuard,
  failureLines,
  fallbackFor,
  localOnlyBadge,
  previewBlocks,
  progressLines,
  recoveryLines,
  residueLines,
  simulationBanner,
  stateLabel,
  stateTone,
  taskCard,
} from './view-model.js';

const state = {
  tasks: [],
  approvals: [],
  selectedTaskId: undefined,
  preview: undefined,
  residueDetail: false,
  lastError: undefined,
};

async function api(path, options) {
  const response = await fetch(`/api${path}`, {
    headers: options?.body === undefined ? undefined : { 'content-type': 'application/json' },
    method: options?.method ?? (options?.body !== undefined ? 'POST' : 'GET'),
    body: options?.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const body = await response.json().catch(() => undefined);
  if (!response.ok) {
    const code = body?.error?.code ?? 'INTERNAL';
    const error = new Error(body?.error?.detail ?? fallbackFor(code));
    error.code = code;
    throw error;
  }
  return body;
}

function el(id) {
  return document.getElementById(id);
}

function renderError(container, error) {
  container.innerHTML = '';
  const box = document.createElement('p');
  box.className = 'fallback';
  box.textContent = error.code ? fallbackFor(error.code) : (error.message ?? 'Unexpected error.');
  container.append(box);
}

function renderTasks() {
  const list = el('task-list');
  list.innerHTML = '';
  for (const snapshot of state.tasks) {
    const card = taskCard(snapshot);
    const item = document.createElement('li');
    const button = document.createElement('button');
    button.type = 'button';
      button.className = `task-card tone-${card.tone}${snapshot.taskId === state.selectedTaskId ? ' selected' : ''}`;
    button.innerHTML = `<strong></strong><span class="badge"></span><span class="detail"></span>`;
    button.querySelector('strong').textContent = card.title;
    button.querySelector('.badge').textContent = card.stateLabel;
    button.querySelector('.detail').textContent = card.detailLine;
    button.addEventListener('click', () => selectTask(card.taskId));
    item.append(button);
    list.append(item);
  }
}

function renderApprovals() {
  const list = el('approval-list');
  list.innerHTML = '';
  if (state.approvals.length === 0) {
    list.innerHTML = '<li class="muted">No approvals are waiting.</li>';
    return;
  }
  for (const approval of state.approvals) {
    const item = document.createElement('li');
    item.className = 'approval-item';
    const summary = document.createElement('p');
    summary.textContent = approval.summary;
    const meta = document.createElement('p');
    meta.className = 'muted';
    meta.textContent = `Task ${approval.taskId} · risk ${approval.riskClass} · plan ${approval.planHash.slice(0, 12)}…`;
    const open = document.createElement('button');
    open.type = 'button';
    open.textContent = 'Review and decide';
    open.addEventListener('click', () => selectTask(approval.taskId));
    item.append(summary, meta, open);
    list.append(item);
  }
}

function renderDetail() {
  const container = el('task-detail');
  container.innerHTML = '';
  const snapshot = state.tasks.find((task) => task.taskId === state.selectedTaskId);
  if (!snapshot) {
    container.innerHTML = '<p class="muted">Select a task to see its progress.</p>';
    return;
  }

  const header = document.createElement('h3');
  header.textContent = snapshot.title;
  const badge = document.createElement('span');
  badge.className = `badge tone-${stateTone(snapshot.state)}`;
  badge.textContent = stateLabel(snapshot.state);
  const local = document.createElement('span');
  local.className = 'badge tone-neutral';
  local.textContent = localOnlyBadge(snapshot);
  container.append(header, badge, ' ', local);

  if (snapshot.clarification) {
    const question = document.createElement('p');
    question.className = 'callout';
    question.textContent = snapshot.clarification.question;
    const input = document.createElement('input');
    input.id = 'clarification-input';
    input.placeholder = 'Type your answer…';
    const send = document.createElement('button');
    send.type = 'button';
    send.textContent = 'Answer';
    send.addEventListener('click', async () => {
      await act(container, () =>
        api(`/tasks/${snapshot.taskId}/clarification`, { body: { answer: el('clarification-input').value } }),
      );
    });
    container.append(question, input, send);
  }

  const failure = failureLines(snapshot);
  if (failure.length > 0) {
    const box = document.createElement('p');
    box.className = 'callout bad';
    box.textContent = failure.join(' ');
    container.append(box);
  }

  const recovery = recoveryLines(snapshot);
  if (recovery.length > 0) {
    const box = document.createElement('p');
    box.className = 'callout warn';
    box.textContent = recovery.join(' ');
    container.append(box);
    const reconcile = document.createElement('button');
    reconcile.type = 'button';
    reconcile.textContent = 'Reconcile now';
    reconcile.addEventListener('click', () =>
      act(container, () => api(`/tasks/${snapshot.taskId}/recovery`, { body: {} })),
    );
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.textContent = 'Retry (same action identity)';
    retry.addEventListener('click', () =>
      act(container, () => api(`/tasks/${snapshot.taskId}/retry`, { body: {} })),
    );
    container.append(reconcile, ' ', retry);
  }

  const progress = document.createElement('h4');
  progress.textContent = 'Progress';
  const steps = document.createElement('ul');
  steps.className = 'progress';
  for (const line of progressLines(snapshot)) {
    const item = document.createElement('li');
    item.textContent = `${line.at} — ${line.label}${line.note ? `: ${line.note}` : ''}`;
    steps.append(item);
  }
  container.append(progress, steps);

  const plan = snapshot.planSummary;
  if (plan) {
    const planTitle = document.createElement('h4');
    planTitle.textContent = 'Plan';
    const planLine = document.createElement('p');
    planLine.textContent = `${plan.riskStatement} (${plan.actionCount} step(s), plan ${plan.planHash.slice(0, 12)}…, policy ${plan.policySnapshotRevision})`;
    const previewButton = document.createElement('button');
    previewButton.type = 'button';
    previewButton.textContent = 'Show human-readable preview';
    previewButton.addEventListener('click', () => loadPreview(snapshot.taskId));
    const previewBox = document.createElement('div');
    previewBox.id = 'preview-box';
    container.append(planTitle, planLine, previewButton, previewBox);
    if (state.preview && state.preview.taskId === snapshot.taskId) renderPreviewInto(previewBox, state.preview);
  }

  if (snapshot.residueSummary) {
    const residueTitle = document.createElement('h4');
    residueTitle.textContent = 'Leftovers found (residue)';
    const box = document.createElement('p');
    box.innerText = residueLines({
      headline: snapshot.residueSummary.headline,
      groups: snapshot.residueSummary.groups,
      protectedUntouchedCount: 0,
    }).join('\n');
    const detailToggle = document.createElement('button');
    detailToggle.type = 'button';
    detailToggle.textContent = state.residueDetail ? 'Hide itemized evidence' : 'Show itemized evidence';
    detailToggle.addEventListener('click', () => {
      state.residueDetail = !state.residueDetail;
      renderDetail();
    });
    container.append(residueTitle, box, detailToggle);
    if (state.residueDetail) {
      api(`/tasks/${snapshot.taskId}/residue?detail=true`)
        .then((detail) => {
          const list = document.createElement('ul');
          for (const item of detail.items ?? []) {
            const line = document.createElement('li');
            line.textContent = `${item.path} — ${item.classification}`;
            const ref = document.createElement('button');
            ref.type = 'button';
            ref.className = 'link';
            ref.textContent = `evidence ${item.evidenceRef}`;
            ref.addEventListener('click', () => showEvidence(item.evidenceRef));
            line.append(' ', ref);
            list.append(line);
          }
          container.append(list);
        })
        .catch((error) => renderError(container, error));
    }
  }

  const actions = document.createElement('div');
  actions.className = 'actions';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.textContent = 'Cancel task';
  cancel.addEventListener('click', () =>
    act(container, () => api(`/tasks/${snapshot.taskId}/cancel`, { body: {} })),
  );
  actions.append(cancel);
  container.append(actions);
}

function renderPreviewInto(box, preview) {
  box.innerHTML = '';
  const blocks = previewBlocks(preview);
  const risk = document.createElement('p');
  risk.className = `callout ${blocks.requiresExplicitApproval ? 'warn' : 'ok'}`;
  risk.textContent = blocks.riskStatement;
  const headline = document.createElement('p');
  headline.innerHTML = `<strong></strong>`;
  headline.querySelector('strong').textContent = blocks.headline;
  const list = document.createElement('ul');
  for (const bullet of blocks.bullets) {
    const item = document.createElement('li');
    item.textContent = bullet;
    list.append(item);
  }
  const hash = document.createElement('p');
  hash.className = 'muted';
  hash.textContent = `You are approving exactly this plan: ${blocks.planHash}`;
  box.append(headline, risk, list, hash);

  // Decision buttons render only from the approval DTO's actual status
  // (VC-P1-01): PENDING → buttons; decided → explicit already-decided note;
  // missing/unknown status → fail-closed refusal, never silent and never a
  // guessed button state.
  const approval = state.approvals.find((candidate) => candidate.taskId === preview.taskId);
  const decision = approvalDecisionState(approval);
  if (decision.decidable) {
    // UI-side guard: the click is only sent when the displayed plan hash is
    // the one bound to this approval (the server re-checks fail-closed).
    const guard = decisionGuard({
      previewPlanHash: preview.planHash,
      approvalPlanHash: approval.planHash,
      enteredPlanHash: preview.planHash,
    });
    const approve = document.createElement('button');
    approve.type = 'button';
    approve.textContent = 'Approve';
    approve.disabled = !guard.allowed;
    approve.title = guard.allowed ? '' : guard.reason;
    approve.addEventListener('click', () =>
      decide(approval.approvalId, preview.planHash, true),
    );
    const decline = document.createElement('button');
    decline.type = 'button';
    decline.textContent = 'Decline';
    decline.addEventListener('click', () => decide(approval.approvalId, preview.planHash, false));
    box.append(approve, ' ', decline);
  } else if (approval) {
    const note = document.createElement('p');
    note.className = 'muted';
    note.textContent = decision.reason;
    box.append(note);
  }
}

async function decide(approvalId, planHash, approved) {
  const box = el('decision-feedback');
  box.innerHTML = '';
  try {
    await api(`/approvals/${approvalId}/decision`, { body: { approved, planHash } });
    box.textContent = approved ? 'Approved — the task is running.' : 'Declined — nothing was executed.';
    box.className = approved ? 'ok' : 'muted';
    await refresh();
  } catch (error) {
    box.textContent = fallbackFor(error.code ?? 'INTERNAL');
    box.className = 'fallback';
    await refresh();
  }
}

async function showEvidence(ref) {
  const box = el('evidence-box');
  box.innerHTML = '';
  try {
    const record = await api(`/evidence/${ref}`);
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(record, null, 2);
    box.append(pre);
  } catch (error) {
    renderError(box, error);
  }
}

async function loadPreview(taskId) {
  const box = el('preview-box');
  try {
    state.preview = await api(`/tasks/${taskId}/preview`);
    renderPreviewInto(box, state.preview);
  } catch (error) {
    renderError(box, error);
  }
}

async function selectTask(taskId) {
  state.selectedTaskId = taskId;
  state.preview = undefined;
  state.residueDetail = false;
  renderTasks();
  renderDetail();
}

async function act(container, fn) {
  try {
    await fn();
    await refresh();
  } catch (error) {
    renderError(container, error);
  }
}

async function refresh() {
  try {
    const [tasks, approvals] = await Promise.all([api('/tasks'), api('/approvals')]);
    state.tasks = tasks.tasks ?? [];
    state.approvals = approvals.approvals ?? [];
    state.lastError = undefined;
  } catch (error) {
    state.lastError = error;
  }
  renderTasks();
  renderApprovals();
  renderDetail();
  // Simulation banner (VC-P2-06): rendered from the backend's own disclosure;
  // it stays visible while the API is unreachable or silent.
  const banner = el('simulation-banner');
  const sim = simulationBanner(undefined);
  banner.textContent = sim.text;
  banner.hidden = !sim.visible;
  banner.className = 'sim-banner';
  const health = el('health');
  api('/health')
    .then((info) => {
      health.textContent = `${info.cloudMode === 'REMOTE_OPT_IN' && info.localOnly === false ? 'REMOTE DeepSeek opt-in (Windows consent required)' : 'Local-only (cloud disabled)'} · policy ${info.policy?.kind ?? 'UNKNOWN'} · ${info.api ?? ''}`;
      health.className = 'muted';
      const label = simulationBanner(info);
      banner.textContent = label.text;
      banner.hidden = !label.visible;
      banner.className = label.visible ? 'sim-banner' : 'muted';
    })
    .catch(() => {
      health.textContent = 'Control API unreachable.';
      health.className = 'fallback';
    });
}

function wireForm() {
  const form = el('goal-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const feedback = el('submit-feedback');
    feedback.textContent = '';
    const goal = el('goal-input').value.trim();
    if (!goal) return;
    const request = {
      taskId: `ui-${Date.now()}`,
      goal,
      objects: [],
      constraints: {},
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    };
    try {
      const snapshot = await api('/tasks', { body: request });
      feedback.textContent = `Task ${snapshot.taskId} created.`;
      feedback.className = 'ok';
      el('goal-input').value = '';
      await selectTask(snapshot.taskId);
      await refresh();
    } catch (error) {
      feedback.textContent = fallbackFor(error.code ?? 'INTERNAL');
      feedback.className = 'fallback';
    }
  });
}

// First true user-operable T08 J0 slice: this button reads the already
// reviewed T06 OS inventory in the local Windows backend. It does NOT run a
// model, issue an authorization grant, or claim the scripted demo task states
// are real. No automatic polling or external disclosure.
function wireLiveSystem() {
  const button = el('read-system-info');
  button.addEventListener('click', async () => {
    const status = el('system-status');
    const facts = el('system-facts');
    button.disabled = true;
    status.textContent = 'Reading live Windows system information…';
    facts.replaceChildren();
    try {
      const result = await api('/system/inventory');
      if (
        result.ok !== true ||
        result.source !== 'LIVE_WINDOWS_LOCAL_READONLY' ||
        result.snapshot?.schema !== 'shun.system-inventory.v02' ||
        result.snapshot?.platform !== 'win32' ||
        result.snapshot?.localOnly !== true
      ) {
        throw new Error('Unverified inventory response');
      }
      const snapshot = result.snapshot;
      const numbers = [
        ['Logical CPUs', snapshot.cpuLogicalCount],
        ['Memory total (MiB)', snapshot.memoryTotalBytes / (1024 * 1024)],
        ['Memory available (MiB)', snapshot.memoryFreeBytes / (1024 * 1024)],
        ['Disk total (GiB)', snapshot.diskTotalBytes / (1024 * 1024 * 1024)],
        ['Disk available (GiB)', snapshot.diskFreeBytes / (1024 * 1024 * 1024)],
        ['Uptime (hours)', snapshot.uptimeSeconds / 3600],
      ];
      if (numbers.some(([, value]) => !Number.isFinite(value) || value < 0)) {
        throw new Error('Invalid inventory facts');
      }
      for (const [label, value] of numbers) {
        const item = document.createElement('li');
        item.textContent = `${label}: ${value.toFixed(label === 'Logical CPUs' ? 0 : 1)}`;
        facts.append(item);
      }
      status.textContent = 'Live local Windows facts read. No cloud call or file changes.';
    } catch {
      status.textContent = 'Live Windows information unavailable. Nothing was simulated.';
      facts.replaceChildren();
    } finally {
      button.disabled = false;
    }
  });
}

// T08 C01: a local, non-authoritative display of the exact T01 cloud
// disclosure projection. Nothing in this browser can issue a broker assertion,
// approve a model send, or change cloud budget/currentness.
function wireCloudDisclosurePreview(onDisplayed) {
  const button = el('cloud-preview-button');
  const status = el('cloud-preview-status');
  const hash = el('cloud-preview-hash');
  const json = el('cloud-preview-json');
  button.addEventListener('click', async () => {
    onDisplayed(null);
    status.textContent = 'Calculating local disclosure preview…';
    hash.textContent = '';
    json.textContent = '';
    button.disabled = true;
    try {
      const goalText = el('cloud-preview-goal').value;
      const result = await api('/cloud/disclosure-preview', { body: { goalText } });
      if (goalText !== el('cloud-preview-goal').value) throw new Error('Goal changed');
      if (
        result.ok !== true ||
        result.status !== 'LOCAL_PREVIEW_ONLY' ||
        result.consentIssued !== false ||
        result.cloudSendAllowed !== false ||
        result.privateBrokerReady !== false ||
        typeof result.projectionJson !== 'string' ||
        !/^[a-f0-9]{64}$/.test(result.sha256)
      ) {
        throw new Error('The server did not confirm preview-only mode.');
      }
      json.textContent = result.projectionJson;
      hash.textContent = `Disclosure SHA-256: ${result.sha256}`;
      status.textContent = 'Local preview only. No cloud request was made. A separate Windows dialog is required to send.';
      onDisplayed(goalText);
    } catch {
      onDisplayed(null);
      status.textContent = 'Disclosure preview unavailable. No cloud request was made.';
    } finally {
      button.disabled = false;
    }
  });
}

// Only the trusted *real* backend can persist the fixed, immutable T04
// candidate. An HTTP caller cannot choose source text, emit grants, promote
// ACTIVE, or execute even an R0 effect from this UI path.
function wireBuiltinRecipeSave() {
  const button = el('save-inventory-recipe');
  const status = el('recipe-save-status');
  const identity = el('recipe-save-identity');
  button.addEventListener('click', async () => {
    button.disabled = true;
    status.textContent = 'Saving fixed local Recipe candidate…';
    identity.textContent = '';
    try {
      const saved = await api('/recipes/builtin/system-inventory/save', { body: {} });
      if (
        saved.ok !== true ||
        saved.state !== 'PERSISTED_CANDIDATE_ONLY' ||
        saved.executionAuthorized !== false ||
        saved.modelCalls !== 0 ||
        typeof saved.recipeId !== 'string' ||
        !/^[a-f0-9]{64}$/.test(saved.revisionSha256)
      ) {
        throw new Error('Unverified Recipe candidate save');
      }
      identity.textContent = `Recipe: ${saved.recipeId} · SHA-256 revision: ${saved.revisionSha256}`;
      status.textContent = saved.inserted
        ? 'Saved immutable candidate locally. Not active or authorized to execute.'
        : 'Existing identical candidate found. No new model call or execution.';
    } catch {
      status.textContent =
        'Recipe save unavailable (real local backend required). No Recipe was executed.';
    } finally {
      button.disabled = false;
    }
  });
}

// Trusted cloud planning is a DISTINCT real lane, not a promotion of Demo
// task data into authoritative ActionController results. Every send still
// requires an actual Win32 private broker Allow gesture in the local host.
function wireTrustedCloudInterpretation() {
  const button = el('cloud-send-button');
  const status = el('cloud-send-status');
  const resultText = el('cloud-result-text');
  const goal = el('cloud-preview-goal');
  let preflightGoal = null;
  let available = false;

  async function checkAvailability() {
    try {
      const state = await api('/cloud/status');
      available =
        state.enabled === true &&
        state.provider === 'deepseek' &&
        state.model === 'deepseek-flash' &&
        state.osConsentRequired === true;
    } catch {
      available = false;
    }
    button.disabled = !available || preflightGoal !== goal.value;
    if (!available) {
      status.textContent = 'Trusted cloud send unavailable: Windows broker, key or host policy missing.';
    } else {
      status.textContent = 'Local cloud planner ready. Preview the exact goal, then confirm in Windows.';
    }
  }

  goal.addEventListener('input', () => {
    preflightGoal = null;
    button.disabled = true;
    resultText.textContent = '';
    status.textContent = 'Goal changed. Review the disclosure again before sending.';
  });
  // Only the one actual rendered preview can unlock the send button.
  // Never run a second racing preflight request that could complete before
  // the JSON and digest are visible on screen.
  function onDisplayed(displayedGoal) {
    preflightGoal = displayedGoal !== null && displayedGoal === goal.value ? displayedGoal : null;
    button.disabled = !available || preflightGoal === null;
  }

  button.addEventListener('click', async () => {
    if (!available || preflightGoal === null || preflightGoal !== goal.value) {
      status.textContent = 'The displayed goal changed. Preview before requesting consent.';
      button.disabled = true;
      return;
    }
    const goalText = preflightGoal;
    preflightGoal = null;
    button.disabled = true;
    resultText.textContent = '';
    status.textContent = 'Waiting for your separate Windows consent dialog…';
    try {
      const response = await api('/cloud/interpret', { body: { goalText } });
      if (
        response.ok !== true ||
        response.status !== 'UNTRUSTED_REMOTE_PROPOSAL' ||
        response.executed !== false ||
        response.model !== 'deepseek-flash' ||
        response.costState !== 'UNKNOWN_COST' ||
        typeof response.proposalText !== 'string'
      ) {
        throw new Error('Unverified cloud response');
      }
      // Raw model text is UNTRUSTED, never use innerHTML or execute it.
      resultText.textContent = response.proposalText;
      status.textContent =
        'Real DeepSeek response received. No action executed. Charges may be uncertain.';
    } catch {
      status.textContent = 'Cloud request refused or unavailable. No action was executed.';
    } finally {
      await checkAvailability();
      button.disabled = true;
    }
  });
  void checkAvailability();
  return onDisplayed;
}

wireForm();
wireLiveSystem();
wireBuiltinRecipeSave();
const onCloudDisplayed = wireTrustedCloudInterpretation();
wireCloudDisclosurePreview(onCloudDisplayed);
refresh();
setInterval(refresh, 2500);
