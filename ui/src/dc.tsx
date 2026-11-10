// The runtime for the design components: a template (markup with {{holes}}, <sc-if>, <sc-for>, <dc-import>) rendered
// with the values its logic class returns from renderVals(). The format is the one of the design canvas, so a screen
// of the app is the designer's file, not a redrawing of it.
//
// A template is compiled once into render functions. A subtree without holes becomes one React element made at compile
// time and reused on every render, so React skips it: a screen that ticks once a second only rebuilds what can change.
import React from 'react';

type Scope = Record<string, unknown>;
export type Navigate = (screen: string) => void;
type Render = (scope: Scope, nav: Navigate) => React.ReactNode;
type Compiled = { render: Render; fixed?: React.ReactNode };

export const NavContext = React.createContext<Navigate>(() => {});
const registry: Record<string, typeof DCLogic> = {};

// How many times templates were rendered and how long building their trees took: the number to watch for lag.
// (valsMs is the logic's renderVals(), ms the template.)
// last() builds the tree of the screen rendered last once more: call it in a loop to benchmark.
export const perf = { renders: 0, ms: 0, valsMs: 0, last: (): unknown => null };
(globalThis as any).__dcPerf = perf;

const HOLE = /\{\{\s*([^}]*?)\s*\}\}/g;
const WHOLE = /^\{\{\s*([^}]*?)\s*\}\}$/;

// {{ a.b }} is a dotted lookup or a literal, never an expression.
function getter(path: string): (scope: Scope) => unknown {
  if (path === 'true') return () => true;
  if (path === 'false') return () => false;
  if (path !== '' && !isNaN(Number(path))) { const n = Number(path); return () => n; }
  const keys = path.split('.');
  if (keys.length === 1) return (scope) => scope[path];
  return (scope) => {
    let v: unknown = scope;
    for (const key of keys) {
      if (v == null) return undefined;
      v = (v as Scope)[key];
    }
    return v;
  };
}

const text = (v: unknown) => (v == null || v === false ? '' : String(v));

// "a {{p}} b" → a function of the scope; a string without holes → undefined (it is a constant).
function filler(s: string): ((scope: Scope) => string) | undefined {
  const parts: (string | ((scope: Scope) => unknown))[] = [];
  let last = 0;
  for (const m of s.matchAll(HOLE)) {
    if (m.index > last) parts.push(s.slice(last, m.index));
    parts.push(getter(m[1]));
    last = m.index + m[0].length;
  }
  if (!parts.length) return undefined;
  if (last < s.length) parts.push(s.slice(last));
  return (scope) => {
    let out = '';
    for (const p of parts) out += typeof p === 'string' ? p : text(p(scope));
    return out;
  };
}

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
const propName = (attr: string) =>
  attr.startsWith('aria-') || attr.startsWith('data-') ? attr : NAMES[attr] ?? camel(attr);
const PAGE = /^([A-Za-z]+)\.dc\.html$/;

function compileElement(el: Element, key: number): Compiled {
  const fixed: Record<string, unknown> = { key };
  const live: [string, (scope: Scope) => unknown][] = [];
  let page: string | undefined;
  for (const a of Array.from(el.attributes)) {
    if (a.name.startsWith('hint-')) continue;
    const name = propName(a.name);
    const whole = a.value.match(WHOLE);
    const get = whole ? getter(whole[1]) : filler(a.value);
    if (name === 'style') {
      if (get) live.push([name, (scope) => styleOf(text(get(scope)))]);
      else fixed.style = styleOf(a.value);
    } else if (get) live.push([name, get]);
    else if (el.localName === 'a' && name === 'href' && PAGE.test(a.value)) page = a.value.match(PAGE)![1];
    else if (!(name === 'src' && a.value === '')) fixed[name] = a.value;
  }
  const input = el.localName === 'input';
  const kids = Array.from(el.childNodes).map(compile);
  const tag = el.localName;

  if (!live.length && !page && kids.every((k) => 'fixed' in k)) {
    if (input && 'value' in fixed) { fixed.defaultValue = fixed.value; delete fixed.value; }
    const node = React.createElement(tag, fixed, ...kids.map((k) => k.fixed));
    return { fixed: node, render: () => node };
  }
  return {
    render: (scope, nav) => {
      const props: Record<string, unknown> = { ...fixed };
      for (const [name, get] of live) {
        const v = get(scope);
        if (!(name === 'src' && v === '')) props[name] = v;
      }
      if (page) {
        const to = page;
        props.href = '#';
        props.onClick = (e: React.MouseEvent) => { e.preventDefault(); nav(to); };
      }
      if (input && 'value' in props && !props.onChange) { props.defaultValue = props.value; delete props.value; }
      return React.createElement(tag, props, ...kids.map((k) => ('fixed' in k ? k.fixed : k.render(scope, nav))));
    },
  };
}

function compile(n: ChildNode, key: number): Compiled {
  if (n.nodeType === Node.TEXT_NODE) {
    const s = n.nodeValue ?? '';
    const fill = filler(s);
    return fill ? { render: fill } : { fixed: s, render: () => s };
  }
  if (n.nodeType !== Node.ELEMENT_NODE) return { fixed: null, render: () => null };
  const el = n as Element;
  const hole = (attr: string) => getter((el.getAttribute(attr) ?? '').replace(WHOLE, '$1'));
  switch (el.localName) {
    case 'sc-if': {
      const cond = hole('value');
      const kids = Array.from(el.childNodes).map(compile);
      return {
        render: (scope, nav) =>
          cond(scope) ? React.createElement(React.Fragment, { key }, ...kids.map((k) => k.render(scope, nav))) : null,
      };
    }
    case 'sc-for': {
      const list = hole('list');
      const as = el.getAttribute('as') ?? 'item';
      const kids = Array.from(el.childNodes).map(compile);
      return {
        render: (scope, nav) => {
          const items = list(scope);
          return React.createElement(React.Fragment, { key }, ...(Array.isArray(items) ? items : []).map((item, i) => {
            const inner = Object.assign(Object.create(scope), { [as]: item, $index: i });
            return React.createElement(React.Fragment, { key: i }, ...kids.map((k) => k.render(inner, nav)));
          }));
        },
      };
    }
    case 'dc-import': {
      const inner = compileElement(el, key); // its attributes are the props of the child
      return {
        render: (scope, nav) => {
          const { name, ...props } = (inner.render(scope, nav) as React.ReactElement<{ name: string }>).props;
          const C = registry[name];
          return C ? React.createElement(C, { key, ...props }) : null;
        },
      };
    }
  }
  return compileElement(el, key);
}

export function compileTemplate(html: string): Render {
  const t = document.createElement('template');
  t.innerHTML = html;
  const kids = Array.from(t.content.childNodes).map(compile);
  return (scope, nav) => React.createElement(React.Fragment, null, ...kids.map((k) => k.render(scope, nav)));
}

// What a design `class Component extends DCLogic` expects: props, state, the React lifecycle, and renderVals().
export class DCLogic<P = Record<string, unknown>> extends React.Component<P, any> {
  static template: Render;
  static contextType = NavContext;
  declare context: Navigate;
  renderVals(): Scope { return {}; }
  render() {
    const t0 = performance.now();
    const vals = this.renderVals();
    const t1 = performance.now();
    const out = (this.constructor as typeof DCLogic).template(vals, this.context);
    perf.last = () => (this.constructor as typeof DCLogic).template(this.renderVals(), this.context);
    perf.renders++;
    perf.valsMs += t1 - t0;
    perf.ms += performance.now() - t1;
    return out;
  }
}

export function register(name: string, logic: typeof DCLogic, html: string) {
  logic.template = compileTemplate(html);
  registry[name] = logic;
  return logic;
}
