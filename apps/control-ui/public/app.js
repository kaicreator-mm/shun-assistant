// Shun local control surface (T08 reference UI, L2 §12).
//
// Same-origin only: every request goes to /api on the loopback origin that
// served this page. The UI renders and relays; it never constructs
// authorization and never talks to anything but the local control-api.
import {
  decisionGuard,
  failureLines,
  fallbackFor,
  localOnlyBadge,
  previewBlocks,
  progressLines,
  recoveryLines,
  residueLines,
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

  const approval = state.approvals.find((candidate) => candidate.taskId === preview.taskId);
  if (approval && approval.status === 'PENDING') {
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
  const health = el('health');
  api('/health')
    .then((info) => {
      health.textContent = `Local only · policy ${info.policy?.kind ?? 'UNKNOWN'} · ${info.api ?? ''}`;
      health.className = 'muted';
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

wireForm();
refresh();
setInterval(refresh, 2500);
