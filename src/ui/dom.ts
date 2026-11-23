/** Tiny, dependency-free DOM helpers shared by the panels. */

type Attrs = Record<string, string | number | boolean | EventListener | undefined>;
type Child = Node | string | null | undefined;

/** Hyperscript: h('button', { class: 'x', onclick: fn }, 'label'). */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === 'class') {
      node.className = String(value);
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

/** A labelled read-only value shown as wrapping monospace (no scroll region needed). */
export function field(label: string, value: string, opts: { mono?: boolean; sub?: string } = {}): HTMLElement {
  return h(
    'div',
    { class: 'field' },
    h('span', { class: 'field-label' }, label, opts.sub ? h('span', { class: 'field-sub' }, ` ${opts.sub}`) : null),
    h('code', { class: opts.mono === false ? 'field-value plain' : 'field-value' }, value),
  );
}

/** A big pass/fail verdict: icon + text + color (never color alone). */
export function verdict(state: 'pass' | 'fail' | 'alarm', text: string): HTMLElement {
  const icon = state === 'pass' ? '✓' : state === 'alarm' ? '⚠' : '✕';
  return h(
    'div',
    { class: `verdict verdict-${state}`, role: 'status' },
    h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, icon),
    h('span', {}, text),
  );
}

/** Section heading + intro paragraph(s) for a panel. */
export function panelIntro(title: string, ...paras: (string | HTMLElement)[]): HTMLElement {
  return h(
    'div',
    { class: 'panel-intro' },
    h('h2', {}, title),
    ...paras.map((p) => (typeof p === 'string' ? h('p', {}, p) : p)),
  );
}

/** A "not production" / scoping note. */
export function note(kind: 'info' | 'danger' | 'caveat', ...children: Child[]): HTMLElement {
  return h('p', { class: `callout callout-${kind}` }, ...children);
}

/** Replace evidence that no longer belongs to the controls currently on screen. */
export function evidenceRetired(text: string): HTMLElement {
  return h(
    'p',
    { class: 'callout callout-caveat evidence-retired', role: 'status', 'aria-live': 'polite' },
    text,
  );
}


/** A metric verdict chip: icon + words + tone class (never colour alone). */
export function toneChip(tone: 'optimal' | 'ok' | 'alarm', text: string, key: string): HTMLElement {
  const icon = tone === 'optimal' ? '✓' : tone === 'alarm' ? '⚠' : '•';
  return h(
    'span',
    { class: `tone tone-${tone}`, 'data-verdict': key, 'data-tone': tone },
    h('span', { class: 'tone-icon', 'aria-hidden': 'true' }, icon),
    h('span', {}, text),
  );
}

export function hex(v: number, width: number): string {
  return v.toString(16).padStart(width, '0');
}

/** Hex digits needed to print an m-bit value. */
export function hexWidth(bits: number): number {
  return Math.max(1, Math.ceil(bits / 4));
}

/** A labelled control wrapper. */
export function control(id: string, label: string, input: HTMLElement, help?: string): HTMLElement {
  const helpId = help ? `${id}-help` : undefined;
  if (helpId) input.setAttribute('aria-describedby', helpId);
  return h(
    'div',
    { class: 'control' },
    h('label', { for: id }, label),
    input,
    help ? h('p', { class: 'help', id: helpId }, help) : null,
  );
}

/** A native select inside the styled wrapper. */
export function select(id: string, options: [string, string][], value: string): HTMLSelectElement {
  const s = h('select', { id, class: 'select' }) as HTMLSelectElement;
  for (const [v, text] of options) s.append(h('option', { value: v }, text));
  s.value = value;
  return s;
}

export function selectWrap(s: HTMLSelectElement): HTMLElement {
  return h('div', { class: 'select-wrap' }, s);
}

/**
 * Parse a number typed by the reader. Returns null, and marks the input invalid, if
 * the text is not a plain decimal inside [min, max] (and a whole number when asked).
 */
export function readNumber(input: HTMLInputElement, min: number, max: number, integer = false): number | null {
  const t = input.value.trim();
  const ok = /^-?\d+(\.\d+)?$|^-?\.\d+$/.test(t);
  const v = ok ? Number(t) : Number.NaN;
  const good = ok && v >= min && v <= max && (!integer || Number.isInteger(v));
  if (good) input.removeAttribute('aria-invalid');
  else input.setAttribute('aria-invalid', 'true');
  return good ? v : null;
}

export function numberInput(id: string, value: string, width = 8): HTMLInputElement {
  return h('input', { id, class: 'mono-input', type: 'text', inputmode: 'decimal', value, size: width, autocomplete: 'off', spellcheck: 'false' }) as HTMLInputElement;
}

export const pct = (x: number, digits = 1): string => `${(x * 100).toFixed(digits)}%`;
export const fmtP = (x: number): string => x.toFixed(7);

/** A threat-model line (batch requirement 7). */
export function threatModel(parts: { attacker: string; access: string; trusted: string; success: string; notShown: string }): HTMLElement {
  return h(
    'details',
    { class: 'disclosure threat' },
    h('summary', {}, 'Threat model for this exhibit'),
    h(
      'dl',
      { class: 'threat-list' },
      h('dt', {}, 'Attacker controls'), h('dd', {}, parts.attacker),
      h('dt', {}, 'Access'), h('dd', {}, parts.access),
      h('dt', {}, 'Trusted'), h('dd', {}, parts.trusted),
      h('dt', {}, 'Success means'), h('dd', {}, parts.success),
      h('dt', {}, 'Does not establish'), h('dd', {}, parts.notShown),
    ),
  );
}

/** A 2048-bit value shortened for tables: first 10 and last 6 hex digits. */
export function abbrev(x: bigint): string {
  const s = x.toString(16);
  return s.length <= 20 ? s : `${s.slice(0, 10)}…${s.slice(-6)}`;
}

/** A check row: icon + text + tone, and which verifiability property it supports. */
export function checkRow(ok: boolean, text: string, key: string, property?: string): HTMLElement {
  return h(
    'li',
    { class: `check ${ok ? 'check-pass' : 'check-fail'}`, 'data-check': key, 'data-ok': String(ok) },
    h('span', { class: 'check-icon', 'aria-hidden': 'true' }, ok ? '✓' : '✕'),
    h('span', {}, text, property ? h('span', { class: 'check-prop' }, ` — ${property}`) : null),
  );
}

export function brokenBadge(text: string): HTMLElement {
  return h('p', { class: 'broken-badge', role: 'note' }, h('span', { 'aria-hidden': 'true' }, '⚠ '), text);
}
