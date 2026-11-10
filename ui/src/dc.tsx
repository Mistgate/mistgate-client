// The runtime for the design components: a template (markup with {{holes}}, <sc-if>, <sc-for>, <dc-import>) rendered
// with the values its logic class returns from renderVals(). The format is the one of the design canvas, so a screen
// of the app is the designer's file, not a redrawing of it.
import React from 'react';

type Scope = Record<string, unknown>;
export type Navigate = (screen: string) => void;
export const NavContext = React.createContext<Navigate>(() => {});
const registry: Record<string, typeof DCLogic> = {};

const HOLE = /\{\{\s*([^}]*?)\s*\}\}/g;
const WHOLE = /^\{\{\s*([^}]*?)\s*\}\}$/;

function lookup(scope: Scope, path: string): unknown {
  if (path === 'true') return true;
  if (path === 'false') return false;
  if (path !== '' && !isNaN(Number(path))) return Number(path);
  let v: unknown = scope;
  for (const key of path.split('.')) {
    if (v == null) return undefined;
    v = (v as Scope)[key];
  }
  return v;
}

const text = (v: unknown) => (v == null || v === false ? '' : String(v));
const fill = (s: string, scope: Scope) => s.replace(HOLE, (_, p) => text(lookup(scope, p)));
const value = (s: string, scope: Scope) => {
  const m = s.match(WHOLE);
  return m ? lookup(scope, m[1]) : fill(s, scope);
};
const camel = (s: string) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

function styleOf(css: string): React.CSSProperties {
  const out: Record<string, string> = {};
  for (const part of css.split(';')) {
    const i = part.indexOf(':');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k) out[k.startsWith('--') ? k : camel(k)] = part.slice(i + 1).trim();
  }
  return out as React.CSSProperties;
}

// The HTML parser lower-cases attribute names; React wants its own spelling for these.
const NAMES: Record<string, string> = {
  class: 'className', for: 'htmlFor', onclick: 'onClick', tabindex: 'tabIndex', maxlength: 'maxLength',
  spellcheck: 'spellCheck', readonly: 'readOnly', autocomplete: 'autoComplete',
};

function attrs(el: Element, scope: Scope, nav: Navigate): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of Array.from(el.attributes)) {
    if (a.name.startsWith('hint-')) continue;
    const v = value(a.value, scope);
    if (a.name === 'style') out.style = styleOf(text(v));
    else if (a.name.startsWith('aria-') || a.name.startsWith('data-')) out[a.name] = v;
    else out[NAMES[a.name] ?? camel(a.name)] = v;
  }
  if (el.localName === 'a' && typeof out.href === 'string') {
    const page = out.href.match(/^([A-Za-z]+)\.dc\.html$/);
    if (page) {
      out.href = '#';
      out.onClick = (e: React.MouseEvent) => { e.preventDefault(); nav(page[1]); };
    }
  }
  if (out.src === '') delete out.src;
  if (el.localName === 'input' && 'value' in out && !out.onChange) {
    out.defaultValue = out.value;
    delete out.value;
  }
  return out;
}

function children(el: Element | DocumentFragment, scope: Scope, nav: Navigate): React.ReactNode[] {
  return Array.from(el.childNodes).map((n, i) => node(n, scope, nav, i));
}

function node(n: ChildNode, scope: Scope, nav: Navigate, key: number): React.ReactNode {
  if (n.nodeType === Node.TEXT_NODE) return fill(n.nodeValue ?? '', scope);
  if (n.nodeType !== Node.ELEMENT_NODE) return null;
  const el = n as Element;
  switch (el.localName) {
    case 'sc-if':
      return lookup(scope, (el.getAttribute('value') ?? '').replace(WHOLE, '$1'))
        ? <React.Fragment key={key}>{children(el, scope, nav)}</React.Fragment> : null;
    case 'sc-for': {
      const list = lookup(scope, (el.getAttribute('list') ?? '').replace(WHOLE, '$1'));
      const as = el.getAttribute('as') ?? 'item';
      return <React.Fragment key={key}>{(Array.isArray(list) ? list : []).map((item, i) => (
        <React.Fragment key={i}>{children(el, Object.assign(Object.create(scope), { [as]: item, $index: i }), nav)}</React.Fragment>
      ))}</React.Fragment>;
    }
    case 'dc-import': {
      const { name, ...props } = attrs(el, scope, nav) as { name: string };
      const C = registry[name];
      return C ? <C key={key} {...props} /> : null;
    }
  }
  const kids = children(el, scope, nav);
  return React.createElement(el.localName, { key, ...attrs(el, scope, nav) }, ...kids);
}

export function parseTemplate(html: string): DocumentFragment {
  const t = document.createElement('template');
  t.innerHTML = html;
  return t.content;
}

// What a design `class Component extends DCLogic` expects: props, state, the React lifecycle, and renderVals().
export class DCLogic<P = Record<string, unknown>> extends React.Component<P, any> {
  static template: DocumentFragment;
  static contextType = NavContext;
  declare context: Navigate;
  renderVals(): Scope { return {}; }
  render() {
    const tpl = (this.constructor as typeof DCLogic).template;
    return <>{children(tpl, this.renderVals(), this.context)}</>;
  }
}

export function register(name: string, logic: typeof DCLogic, html: string) {
  logic.template = parseTemplate(html);
  registry[name] = logic;
  return logic;
}
