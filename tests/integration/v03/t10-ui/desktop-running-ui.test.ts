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

function setup(locale) {
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
  const tasks = [
    { taskId: 'task-a', title: 'Folder question', revision: 1, state: 'CLARIFICATION',
      updatedAt: '2026-11-02T02:00:00Z', clarification: { question: 'Which folder?' } },
    { taskId: 'task-b', title: 'Finished check', revision: 2, state: 'SUCCEEDED',
      updatedAt: '2026-11-01T23:00:00Z' },
  ];
  const fetch = async (url, options) => {
    requests.push({ url, method: options?.method || 'GET' });
    let data;
    if (url === '/api/health') data = {
      ok: true, loopbackOnly: true, simulated: false,
      policy: { kind: 'ACTIVE', revision: 'fixture' }, cloudMode: 'DISABLED',
    };
    else if (url === '/api/v03/guided/state') data = { currentStep: null, history: [] };
    else if (url === '/api/tasks') data = { tasks };
    else if (url === '/api/tasks/task-a') data = tasks[0];
    else if (url === '/api/tasks/task-b') data = tasks[1];
    else throw new Error('Unexpected URL: ' + url);
    return { ok: true, status: 200, json: async () => data };
  };
  const context = {
    document, fetch, navigator: { language: locale },
    sessionStorage: { getItem: () => null, setItem() {} },
    approvedText: () => ({ ok: false }),
    summarizeBrowserFolder: () => ({ status: 'REFUSED' }),
    guidedReceiptStatus: () => 'UNKNOWN',
    projectGuidedHistory: () => ({ status: 'READY', items: [] }),
    projectLocalObservation: () => ({ status: 'REFUSED' }),
    projectRoutineState: () => ({ status: 'REFUSED' }),
    projectRoutineExecution: () => ({ status: 'REFUSED' }),
    projectDisclosurePreview: () => ({ status: 'REFUSED' }),
    currentStepModel: () => ({ status: 'REFUSED' }),
    buildStepOutcome: () => ({ ok: false }),
    userDecisionRelay: () => ({ ok: false }),
    replayGuard: () => ({ allowed: false }),
    progressModel: () => ({ ok: true, status: 'UNKNOWN', position: { text: 'unknown' } }),
    ...approvals,
  };
  runInNewContext(script + '\nglobalThis.__ui = { loadHostTasks, loadHostTaskDetail };',
    context, { timeout: 2000 });
  return { ui: context.__ui, node: (id) => document.getElementById(id), requests };
}

describe('R04 real desktop.js task-list interactions (controlled DOM)', () => {
  for (const locale of ['en-US', 'zh-CN']) {
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
  }
});
