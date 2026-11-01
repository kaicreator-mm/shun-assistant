/**
 * Minimal DOM shim for driving the REAL shipped v03 UI code (app.js and its
 * view-model/strings imports) inside a Node test process
 * (OWNER_SHUN_V030_R03B_CROSSCASE_UI_COMPOSITE_APPROVE).
 *
 * This is browser INFRASTRUCTURE, not a product double: it implements only
 * the exact DOM surface app.js itself uses. The UI's fetch stays the REAL
 * global fetch — the test only resolves the UI's relative same-origin paths
 * against the live loopback origin, exactly what a browser does for a page
 * it served.
 */

export class ShimElement {
  readonly tagName: string;
  id = '';
  className = '';
  value = '';
  type = '';
  checked = false;
  #text = '';
  #children: ShimElement[] = [];
  #listeners = new Map<string, (() => void)[]>();
  #attributes = new Map<string, string>();
  dataFieldId = '';

  constructor(tagName: string) {
    this.tagName = tagName.toUpperCase();
  }

  get textContent(): string {
    let text = this.#text;
    for (const child of this.#children) text += child.textContent;
    return text;
  }

  set textContent(value: string) {
    this.#text = value;
    this.#children = [];
  }

  /** innerHTML='' clears content — the only innerHTML use in app.js. */
  set innerHTML(value: string) {
    if (value === '') {
      this.#text = '';
      this.#children = [];
    } else {
      this.#text = value;
    }
  }

  get innerHTML(): string {
    return this.textContent;
  }

  append(...nodes: (ShimElement | string)[]): void {
    for (const node of nodes) {
      if (typeof node === 'string') {
        this.#text += node;
      } else {
        this.#children.push(node);
        if (node.id) registerElement(node);
      }
    }
  }

  setAttribute(name: string, value: string): void {
    this.#attributes.set(name, value);
    if (name === 'id') this.id = value;
    if (name === 'type') this.type = value;
    if (name === 'data-field-id') this.dataFieldId = value;
  }

  getAttribute(name: string): string | null {
    return this.#attributes.get(name) ?? null;
  }

  addEventListener(event: string, listener: () => void): void {
    const list = this.#listeners.get(event) ?? [];
    list.push(listener);
    this.#listeners.set(event, list);
  }

  /** User gesture: dispatch exactly the registered click listeners. */
  click(): void {
    for (const listener of [...(this.#listeners.get('click') ?? [])]) listener();
  }

  /** Selector support is intentionally limited to [data-field-id]. */
  querySelectorAll(selector: string): ShimElement[] {
    if (selector !== '[data-field-id]') return [];
    const found: ShimElement[] = [];
    const walk = (node: ShimElement): void => {
      if (node.dataFieldId) found.push(node);
      for (const child of node.#children) walk(child);
    };
    walk(this);
    return found;
  }
}

export class ShimInputElement extends ShimElement {
  constructor() {
    super('input');
  }
}

export class ShimSelectElement extends ShimElement {
  constructor() {
    super('select');
  }
}

const registry = new Map<string, ShimElement>();

function registerElement(element: ShimElement): void {
  if (element.id) registry.set(element.id, element);
}

/** All element ids the shipped page (plus the R03B journeys panel) uses. */
export const PAGE_ELEMENT_IDS = [
  'v03-title',
  'v03-subtitle',
  'v03-banner',
  'v03-scope',
  'v03-scope-title',
  'v03-progress',
  'v03-progress-title',
  'v03-step',
  'v03-step-title',
  'v03-step-form',
  'v03-approve',
  'v03-refuse',
  'v03-decision-feedback',
  'v03-history',
  'v03-history-title',
  'v03-advisory',
  'v03-advisory-title',
  'v03-journeys-section',
  'v03-journeys-title',
  'v03-journeys-note',
  'v03-journeys',
  'v03-j-refs-panel',
  'v03-j-currentness',
  'v03-j-approval',
  'v03-j-effect-panel',
  'v03-j-action',
  'v03-j-plan',
  'v03-j-grant',
  'v03-j-effect-run',
  'v03-j-effect-status',
  'v03-j-provider-panel',
  'v03-j-provider-task',
  'v03-j-provider-run',
  'v03-j-provider-status',
  'v03-j-meta-panel',
  'v03-j-meta-case',
  'v03-j-meta-revision',
  'v03-j-meta-rating',
  'v03-j-meta-category',
  'v03-j-meta-correction',
  'v03-j-meta-run',
  'v03-j-meta-status',
];

/** The exact document surface app.js uses (structural, no DOM lib). */
export interface ShimDocument {
  getElementById(id: string): ShimElement | undefined;
  createElement(tag: string): ShimElement;
}

export interface InstalledDom {
  document: ShimDocument;
  navigator: { language: string };
  byId(id: string): ShimElement | undefined;
  restore(): void;
}

/**
 * Install the page fixture + document/navigator/element-class globals the
 * REAL app.js expects, then restore the prior globals afterwards. Must run
 * BEFORE importing the UI module.
 */
export function installDom(locale: 'en' | 'zh'): InstalledDom {
  registry.clear();
  for (const id of PAGE_ELEMENT_IDS) {
    const element = new ShimElement('div');
    element.setAttribute('id', id);
    registry.set(id, element);
  }
  const document = {
    getElementById: (id: string): ShimElement | undefined => registry.get(id),
    createElement: (tag: string): ShimElement => {
      if (tag === 'input') return new ShimInputElement();
      if (tag === 'select') return new ShimSelectElement();
      return new ShimElement(tag);
    },
  } satisfies ShimDocument;
  const navigator = { language: locale === 'zh' ? 'zh-CN' : 'en-US' };
  const globals = globalThis as unknown as Record<string, unknown>;
  const prior = {
    document: globals.document,
    navigator: globals.navigator,
    HTMLInputElement: globals.HTMLInputElement,
    HTMLSelectElement: globals.HTMLSelectElement,
  };
  const install = (key: string, value: unknown): void => {
    Object.defineProperty(globalThis, key, {
      value,
      configurable: true,
      writable: true,
      enumerable: true,
    });
  };
  install('document', document);
  install('navigator', navigator);
  install('HTMLInputElement', ShimInputElement);
  install('HTMLSelectElement', ShimSelectElement);
  return {
    document,
    navigator,
    byId: (id: string) => registry.get(id),
    restore(): void {
      const install = (key: string, value: unknown): void => {
        Object.defineProperty(globalThis, key, {
          value,
          configurable: true,
          writable: true,
          enumerable: true,
        });
      };
      install('document', prior.document);
      install('navigator', prior.navigator);
      install('HTMLInputElement', prior.HTMLInputElement);
      install('HTMLSelectElement', prior.HTMLSelectElement);
    },
  };
}
