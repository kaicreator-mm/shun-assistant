// @ts-nocheck — bounded DOM infrastructure fixture for the SHIPPED desktop.js.
// This is NOT a real Windows/browser E2E or an authority simulation.
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import * as approvals from '../../../../apps/control-ui/public/v03/desktop-approvals.js';

const raw = readFileSync(new URL('../../../../apps/control-ui/public/v03/desktop.js', import.meta.url), 'utf8');
const script = raw.replace(/^import .* from '\.\/[^']+';\s*$/gm, '');
if (/^import /m.test(script)) throw new Error('Unexpected import in desktop.js');

class StubElement {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.hidden = false; this.value = ''; this.textContent = '';
    this.dataset = {}; this.children = []; this.events = {};
    this.attrs = {}; this.className = ''; this.disabled = false;
    this.checked = false; this.focused = false; this.previousElementSibling = null;
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; this.textContent = ''; }
  setAttribute(key, value) { this.attrs[key] = value; }
  removeAttribute(key) { delete this.attrs[key]; }
  addEventListener(type, fn) { this.events[type] = fn; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  focus() { this.focused = true; }
  blur() {}
  reportValidity() { return true; }
  click() { this.events.click?.(); }
}

function setup(locale, options = {}) {
  const registry = new Map();
  const document = {
    documentElement: new StubElement('html'), body: new StubElement('body'),
    getElementById(id) {
      if (!registry.has(id)) registry.set(id, new StubElement('div'));
      return registry.get(id);
    },
    createElement: (tag) => new StubElement(tag),
    querySelectorAll: () => [], querySelector: () => new StubElement(),
    addEventListener() {},
  };
  document.documentElement.dataset.theme = 'system';
  const requests = [];
  let releaseTaskA;
  const blockedTaskA = options.deferTaskA ? new Promise((resolve) => { releaseTaskA = resolve; }) : null;
  const tasks = [
    { taskId: 'task-a', title: 'Folder question', revision: 1, state: 'CLARIFICATION',
      updatedAt: '2026-11-02T02:00:00Z', clarification: { question: 'Which folder?' } },
    { taskId: 'task-b', title: 'Finished check', revision: 2, state: 'SUCCEEDED',
      updatedAt: '2026-11-01T23:00:00Z',progress:[
       {at:'2026-11-01T22:00:00Z',state:'RECEIVED',note:'private-file'},
       {at:'2026-11-01T23:00:00Z',state:'SUCCEEDED',note:'private-token'}] },
    ...(options.includeApprovalTask ? [{ taskId: 'task-c', title: 'Needs approval', revision: 3,
      state: 'AWAITING_AUTHORIZATION', updatedAt: '2026-11-01T22:00:00Z' }] : []),
  ];
  const fetch = async (url, requestOptions) => {
    requests.push({ url, method: requestOptions?.method || 'GET' });
    let data;
    if (url === '/api/health') data = {
      ok: true, loopbackOnly: true, simulated: false,
      policy: { kind: 'ACTIVE', revision: 'fixture' }, cloudMode: 'DISABLED',
    };
    else if (url === '/api/v03/guided/state') data = options.currentStep ? { currentStep: options.currentStep, history: [], journey: { position: 1, total: 1, paused: false }, scope: { status: 'NONE' } } : { currentStep: null, history: [] };
    else if (url === '/api/tasks') data = { tasks };
    else if (url === '/api/tasks/task-a') data = blockedTaskA ? await blockedTaskA : tasks[0];
    else if (url === '/api/tasks/task-b') data = tasks[1];
    else if (url === '/api/tasks/task-c') data = tasks[2];
    else if (url === '/api/approvals') data = { approvals: [] };
    else throw new Error('Unexpected URL: ' + url);
    return { ok: true, status: 200, json: async () => data };
  };
  const context = {
    document, fetch, navigator: { language: locale },
    sessionStorage: { getItem: () => null, setItem() {} },
    approvedText: (_locale, key) => options.currentStep ? ({ ok: true, text: key === 'guided.selectRoot.title' ? 'Choose the folder to work in' : 'Folder path' }) : ({ ok: false }),
    summarizeBrowserFolder: () => ({ status: 'REFUSED' }),
    guidedReceiptStatus: () => 'UNKNOWN',
    projectGuidedHistory: () => ({ status: 'READY', items: [] }),
    projectLocalObservation: () => ({ status: 'REFUSED' }),
    projectRoutineState: () => ({ status: 'REFUSED' }),
    projectRoutineExecution: () => ({ status: 'REFUSED' }),
    projectDisclosurePreview: () => ({ status: 'REFUSED' }),
    currentStepModel: () => options.currentStep ? ({
      status: 'CURRENT', journeyId: 'journey-a', taskId: 'task-a', stepId: 'step-1',
      caseRef: { snapshotId: 'case-a', digest: 'a'.repeat(64) },
      templateId: 'shun.guided.select-root', templateDigest: 'b'.repeat(64),
      issuedAtUnixMs: 1, validUntilUnixMs: Number.MAX_SAFE_INTEGER,
      kind: 'ASK', titleKey: 'guided.selectRoot.title', requiresExplicitApproval: false,
      fields: [{ id: 'selectedRoot', type: 'TEXT', labelKey: 'guided.selectRoot.path', required: true, maxLength: 1024 }],
    }) : ({ status: 'REFUSED' }),
    buildStepOutcome: () => ({ ok: false }),
    userDecisionRelay: () => ({ ok: false }),
    replayGuard: () => ({ allowed: false }),
    progressModel: () => options.currentStep ? ({ ok: true, status: 'RUNNING', position: { text: '1 of 1' } }) : ({ ok: true, status: 'UNKNOWN', position: { text: 'unknown' } }),
    ...approvals,
  };
  runInNewContext(script + '\nglobalThis.__ui = { loadHostTasks, loadHostTaskDetail, loadHomeRecentTasks, refresh };',
    context, { timeout: 2000 });
  return { ui: context.__ui, node: (id) => document.getElementById(id), requests,
    releaseTaskA: () => releaseTaskA?.(tasks[0]) };
}

describe('R04 real desktop.js task-list interactions (controlled DOM)', () => {
  for (const locale of ['en-US', 'zh-CN']) {


    it('shows the newest local tasks on Home with plain status labels: ' + locale, async () => {
      const { ui, node, requests } = setup(locale);
      await ui.loadHomeRecentTasks();
      const rows=node('home-recent-tasks').children;
      expect(rows).toHaveLength(2);
      expect(rows[0].children[0].textContent).toBe('Folder question');
      expect(rows[0].children[1].textContent).toContain(locale.startsWith('zh') ? '需要你补充信息' : 'Needs your input');
      expect(rows[0].children[2].textContent).toBe(locale.startsWith('zh') ? '打开任务' : 'Open task');
      expect(requests.every(item=>item.method==='GET')).toBe(true);
    });
    it('warns that a typed folder path is only a request, not a selected scope: ' + locale, async () => {
      const currentStep = { stepId: 'step-1', taskId: 'task-a' };
      const { ui, node, requests } = setup(locale, { currentStep });
      await ui.refresh();
      const notice = node('step-container').children[0];
      expect(notice.textContent).toBe(locale.startsWith('zh')
        ? '这里只记录你输入的文件夹路径，不代表已选中该文件夹，也不会因此访问其中的文件。'
        : 'This only records the folder path you entered. It does not select the folder or allow file access.');
      expect(node('dynamic-form').hidden).toBe(false);
      expect(requests.every((item) => item.method === 'GET')).toBe(true);
    });
    it('focuses selected details, fences old selection and never sends mutations: ' + locale, async () => {
      const { ui, node, requests } = setup(locale);
      node('host-task-filter').value = 'all';
      await ui.loadHostTasks();
      const list = node('host-task-list');
      const detail = node('host-task-detail');
      expect(list.children).toHaveLength(2);
      await ui.loadHostTaskDetail('task-a', true);
      expect(detail.hidden).toBe(false);
      expect(detail.focused).toBe(true);
      expect(detail.children.length).toBeGreaterThan(2);
      expect(list.children[0].className).toContain('host-task-selected');
      expect(list.children[0].children.at(-1).attrs['aria-expanded']).toBe('true');
      node('host-task-filter').value = 'finished';
      node('host-task-filter').events.change();
      expect(detail.hidden).toBe(true);
      expect(list.children).toHaveLength(1);
      expect(node('host-task-count').textContent).toContain('1');
      expect(requests.every((item) => item.method === 'GET')).toBe(true);
      expect(requests.map((item) => item.url)).toContain('/api/tasks/task-a');
    });

    it('does not let a late older Host read replace a more recently selected task: ' + locale, async () => {
      const { ui, node, requests, releaseTaskA } = setup(locale, { deferTaskA: true });
      node('host-task-filter').value = 'all';
      await ui.loadHostTasks();
      const older = ui.loadHostTaskDetail('task-a', true);
      const newer = ui.loadHostTaskDetail('task-b', true);
      await newer;
      releaseTaskA();
      await older;
      const detail = node('host-task-detail');
      expect(detail.hidden).toBe(false);
      expect(detail.children[0].textContent).toBe('Finished check');
      expect(node('host-task-list').children[1].className).toContain('host-task-selected');
      expect(requests.every((item) => item.method === 'GET')).toBe(true);
    });
    it('renders verified progress while hiding Host note text: ' + locale, async () => {
      const {ui,node,requests}=setup(locale);
      node('host-task-filter').value='all';await ui.loadHostTasks();
      await ui.loadHostTaskDetail('task-b',true);
      const list=node('host-task-detail').children.find(entry=>entry.tagName==='OL');
      expect(list).toBeDefined();
      expect(list.children).toHaveLength(2);
      expect(list.children[0].textContent).not.toContain('private');
      expect(list.children[1].textContent).not.toContain('private');
      expect(requests.every(entry=>entry.method==='GET')).toBe(true);
    });
    it('does not re-open a task when a filter changes during a pending read: ' + locale, async () => {
      const { ui, node, requests, releaseTaskA } = setup(locale, { deferTaskA: true });
      node('host-task-filter').value = 'all';
      await ui.loadHostTasks();
      const pending = ui.loadHostTaskDetail('task-a', true);
      expect(node('host-task-detail').hidden).toBe(false);
      node('host-task-filter').value = 'finished';
      node('host-task-filter').events.change();
      releaseTaskA();
      await pending;
      expect(node('host-task-detail').hidden).toBe(true);
      expect(node('host-task-list').children).toHaveLength(1);
      expect(node('host-task-list').children[0].className).not.toContain('host-task-selected');
      expect(requests.every((item) => item.method === 'GET')).toBe(true);
    });

    it('offers approval navigation for Host-authorized waiting tasks, without submitting approval: ' + locale, async () => {
      const { ui, node, requests } = setup(locale, { includeApprovalTask: true });
      node('host-task-filter').value = 'all';
      await ui.loadHostTasks();
      expect(node('host-task-list').children).toHaveLength(3);
      await ui.loadHostTaskDetail('task-c', true);
      const inspector = node('host-task-detail');
      const openApproval = inspector.children.find((element) => element.tagName === 'BUTTON');
      expect(openApproval).toBeDefined();
      expect(openApproval.textContent).toBe(locale.startsWith('zh') ? '查看待审批事项' : 'Review required approval');
      openApproval.events.click();
      await Promise.resolve();
      await Promise.resolve();
      expect(requests.every((item) => item.method === 'GET')).toBe(true);
      expect(requests.map((item) => item.url)).toContain('/api/approvals');
    });
  }
});
