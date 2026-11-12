// The Home screen on the real service. The design's logic class stays as generated (it plays a mock connection and
// sample subscriptions); in the app window this subclass takes its place: the power button calls the service, and the
// phase, the step, the timer, the traffic, the subscriptions and their servers come from the service (docs/ipc.md).
// Where the design computes a text itself (titles, hints, button labels) its text is kept and only the data changes.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import FLAGS from './design/flags.json';
import { words } from './live-i18n';
import { pref } from './live-settings';

type Status = { state: string; step: string; since_unix: number; server: string; server_id?: string; protocol: string; error: string };
type Traffic = { rx_bps: number; tx_bps: number; rtt_ms: number };
// node, country, city, via (direct | relay | warp) and ipv6 come from a panel's client API only
export type Server = { id: string; name: string; protocol: string; node?: string; country?: string; city?: string; via?: string; ipv6?: boolean; load?: string; version?: string };
type Sub = {
  id: string; kind: 'url' | 'links' | 'awg'; name: string; host: string; updated_unix: number; expire_unix: number;
  used_bytes: number; total_bytes: number; error: string; notice?: string; unsupported: number; servers: Server[];
};

const rpc = <T = Status>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
// The design words four steps; its second ("UDP looks blocked") is a detector's line, not a step of ours.
const STEP: Record<string, number> = { resolve: 0, handshake: 2, tunnel: 3, verify: 3 };
export const PROTO: Record<string, [fam: string, label: string, full: string]> = {
  hysteria2: ['h2', 'HY2', 'Hysteria2'], awg: ['awg', 'AWG 3.1', 'AmneziaWG'],
};
// the design's flags, and Turkey's, which the canvas does not have yet (drawn for the region list)
// ponytail: a country outside this table has no picture; the canvas needs the rest of the flags
const FLAG: Record<string, string> = { ...(FLAGS as Record<string, string>), tr: '/blob/bc9caa2c3d3cb9a41eee59f9fe3669ed.svg' };
const mbps = (bps: number) => (bps / 1e6).toFixed(1);
const DAY = 86400;

// "🇩🇪 Germany" -> the design's flag for "de" and the name without the emoji. A name is shown as the subscription
// gives it; a flag appears only when the name carries one the design has.
export function flagOf(name: string) {
  const m = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (!m) return { flag: '', text: name };
  const cc = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0)! - 0x1f1e6 + 97)).join('');
  return { flag: FLAG[cc] ?? '', text: name.replace(m[0], '').trim() || name };
}

// One row per node, with its protocols in the menu. A plain subscription names its entries for people
// ("de · HY2 · WARP", "be · HY2 · через RU"), and the panel may word them differently.
// ponytail: grouped by the first part of the name; an entry that does not parse is a row of its own. The client
// API's servers[].paths (protocol, via, ipv6) replace this guess when the panel has it switched on.
type Entry = { s: Server; fam: string; label: string; full: string };
type Node = { key: string; name: string; flag: string; via: string; extra: string; entries: Entry[] };
const PROTO_WORD = /^(hy2|hysteria ?2?|awg( ?[\d.]+)?|amneziawg( ?[\d.]+)?)$/i;
const VIA_WORD = /^(через|via)\s+\S/i;
export function nodesOf(servers: Server[]): Node[] {
  const out = new Map<string, Node>();
  for (const s of servers) {
    if (s.node) {
      // the panel's own structure: one node, its paths as the protocol menu
      let [fam, label, full] = PROTO[s.protocol] ?? ['', s.protocol, s.protocol];
      // two AmneziaWG paths of one node differ by their generation
      if (s.protocol === 'awg' && s.version) [label, full] = ['AWG ' + s.version, full + ' ' + s.version];
      const cc = (s.country ?? '').toLowerCase();
      const tail = (s.via === 'warp' ? ' · WARP' : s.via && s.via !== 'direct' ? ' · ' + s.via : '') + (s.ipv6 ? ' · IPv6' : '');
      let node = out.get(s.node);
      if (!node) out.set(s.node, (node = { key: s.node, name: countryName(cc) || s.city || s.name, flag: FLAG[cc] ?? '', via: '', extra: countryName(cc) ? s.city ?? '' : '', entries: [] }));
      const entry = { s, fam, label: label + tail, full: full + tail };
      // the plain path first: it is what a press on the row connects to
      const plainPath = (x: Server) => (!x.via || x.via === 'direct') && !x.ipv6;
      if (tail) node.entries.push(entry); else node.entries.splice(node.entries.findIndex((e) => !plainPath(e.s)) >>> 0, 0, entry);
      continue;
    }
    const { flag, text } = flagOf(s.name);
    const [name, ...rest] = text.split(' · ').map((x) => x.trim());
    const [fam, label, full] = PROTO[s.protocol] ?? ['', s.protocol, s.protocol];
    let via = '', warp = false;
    const extra: string[] = [];
    for (const t of rest) {
      if (PROTO_WORD.test(t)) continue;
      if (/^warp$/i.test(t)) warp = true;
      else if (VIA_WORD.test(t)) via = t;
      else extra.push(t);
    }
    const key = [flag, name, via, ...extra].join('|');
    let node = out.get(key);
    if (!node) out.set(key, (node = { key, name, flag, via, extra: extra.join(' · '), entries: [] }));
    node.entries.push({ s, fam, label: warp ? label + ' · WARP' : label, full: warp ? full + ' · WARP' : full });
  }
  // nodes of one country with no city to tell them apart are numbered, as the design does ("Germany 2")
  const seen = new Map<string, number>();
  for (const n of out.values()) {
    if (n.extra || n.via) continue;
    const k = (seen.get(n.name) ?? 0) + 1;
    seen.set(n.name, k);
    if (k > 1) n.extra = String(k);
  }
  return [...out.values()];
}
// a number follows the name; a city comes after the design's dot
export const sufOf = (n: Node) => (!n.extra ? '' : /^\d+$/.test(n.extra) ? ' ' + n.extra : ' · ' + n.extra);
// "DE" -> "Germany", in the window's language
function countryName(cc: string) {
  if (!/^[a-z]{2}$/.test(cc)) return '';
  try { return new Intl.DisplayNames([words().locale], { type: 'region' }).of(cc.toUpperCase()) ?? ''; } catch { return ''; }
}
const quality = (ms: number) => (ms <= 50 ? 'q3' : ms <= 90 ? 'q2' : 'q1'); // the design's three bars

// Latency numbers outlive the screen: Home is built again on every visit, the numbers stay until the window closes.
const PINGS: Record<string, number> = {};
// where each server is (its name and addresses), for the hint on a row: two nodes of one country look the same
const HOSTS: Record<string, { host: string; ips: string[] }> = {};
let hostsFor = '';
// "via RU" for each relay path whose entry is a server of the list, as Home words it: Diagnostics names its rows
// the same way. ponytail: filled when Home draws (it is the first screen); empty before that, the row says "relay".
export const VIA: Record<string, string> = {};
let pingedAtStart = false; // the first list of the session is measured without being asked

export function liveHome(Base: typeof DCLogic): typeof DCLogic {
  return class LiveHome extends (Base as any) {
    off: Promise<UnlistenFn>[] = [];
    live: Status | null = null;
    traffic: Traffic | null = null;
    subsList: Sub[] | null = null; // null until the service has answered
    pending: { text: string; sub: Sub } | null = null; // the subscription on the confirm sheet
    lastText = '';
    refusal = ''; // the panel's own words when it refuses a subscription (device limit, expired, switched off…)
    pasted = ''; // what was pasted into the link field, with its line breaks (the field itself drops them)
    onPaste = (e: ClipboardEvent) => {
      if ((e.target as Element | null)?.closest?.('.onb-in')) this.pasted = e.clipboardData?.getData('text') ?? '';
    };
    onEnter = (e: KeyboardEvent) => {
      if (e.key === 'Enter' && (e.target as Element | null)?.closest?.('.onb-in')) this.addFromField();
    };
    // Esc, or a click outside it, closes the subscription switcher
    onKeyDown = (e: KeyboardEvent) => {
      this.onEnter(e);
      if (e.key === 'Escape') this.closeSubs();
      // the design's hint on the search field
      if (e.ctrlKey && e.key.toLowerCase() === 'k') { e.preventDefault(); document.querySelector<HTMLInputElement>('.servers input[type=search]')?.focus(); }
    };
    // the search field is plain markup in the design: what is typed narrows the list
    onSearch = (e: Event) => {
      const t = e.target as HTMLInputElement | null;
      if (t?.matches?.('.servers input[type=search]')) this.setState({ q: t.value });
    };
    onClickAway = (e: MouseEvent) => {
      const t = e.target as Element;
      if (!t.closest('.subsel') && !document.querySelector('.pop-h')?.parentElement?.contains(t)) this.closeSubs();
    };
    closeSubs() { if (this.st().subsPop) this.setState({ subsPop: false, mFor: undefined }); }
    tipLast: unknown = null; // the card keeps its last content while it fades out
    route: { mode: string; effective: string } | null = null; // the route mode, for the chip beside the state
    rmId = '';

    componentDidMount() {
      super.componentDidMount();
      this.off = [
        listen<Status>('mg://status', (e) => this.apply(e.payload)),
        listen<Traffic>('mg://traffic', (e) => { this.traffic = e.payload; this.forceUpdate(); }),
        listen<{ subs: Sub[] }>('mg://subs', (e) => this.applySubs(e.payload.subs)),
        listen<{ up: boolean }>('mg://service', (e) => (e.payload.up ? this.sync() : this.setState({ cs: 'svc', wave: false }))),
        listen<{ mode: string; effective: string }>('mg://routes', (e) => { this.route = e.payload; this.paint(); }),
      ];
      document.addEventListener('paste', this.onPaste, true);
      document.addEventListener('keydown', this.onKeyDown, true);
      document.addEventListener('input', this.onSearch, true);
      document.addEventListener('click', this.onClickAway);
      // the choice made before the window went to another screen, or was closed
      this.setState({ sel: pref.get('server') || 'auto', liveSub: pref.get('sub') || undefined, pings: { ...PINGS } }, () => this.sync());
    }
    componentWillUnmount() {
      super.componentWillUnmount();
      document.removeEventListener('paste', this.onPaste, true);
      document.removeEventListener('keydown', this.onKeyDown, true);
      document.removeEventListener('input', this.onSearch, true);
      document.removeEventListener('click', this.onClickAway);
      this.off.forEach((p) => void p.then((un) => un()));
    }

    componentDidUpdate() {
      super.componentDidUpdate?.();
      this.paint();
    }
    // Words the design has as plain markup: the route chip (always "all except RU sites" there) and the link field's hint.
    paint() {
      const r = this.route;
      document.querySelectorAll<HTMLElement>('.rchip').forEach((a) => {
        const t = [...a.childNodes].find((n) => n.nodeType === Node.TEXT_NODE);
        if (!t || !r) return;
        a.dataset.smart ??= t.nodeValue ?? '';
        const [only, all, smart] = words().modes;
        // Smart without a region has no "except … sites": the mode's own name
        const region = /^[a-z]{2}$/.test(r.effective) ? r.effective.toUpperCase() : '';
        const text = r.mode === 'smart' ? (region ? a.dataset.smart.replace('RU', region) : smart) : r.mode === 'selected' ? only : all;
        if (t.nodeValue !== text) t.nodeValue = text;
      });
      const field = document.querySelector<HTMLInputElement>('.onb-in input');
      if (field?.placeholder.includes('vless://')) field.placeholder = field.placeholder.replace('vless://', 'hysteria2://');
    }

    sync() {
      this.ask('status');
      rpc<{ mode: string; effective: string }>('routes.get').then((r) => { this.route = r; this.paint(); }, () => {});
      rpc<{ subs: Sub[] }>('subs.list').then((r) => this.applySubs(r.subs), () => {});
    }
    ask(method: string, params?: object) {
      rpc(method, params).then((s) => this.apply(s), (err) => {
        // a failed call still comes back as a status event when the service is up; without the service, say so
        if (err?.code === 'service_down' || err?.code === 'timeout') this.setState({ cs: 'svc', wave: false });
      });
    }
    apply(s: Status) {
      const was = this.live?.state;
      this.live = s;
      if (s.state !== 'connected') this.traffic = null;
      const next: Record<string, unknown> = { sw: false, cs: '', wave: false };
      if (s.state === 'connected') {
        Object.assign(next, { phase: 'on', secs: Math.max(0, Math.floor(Date.now() / 1000) - s.since_unix), wave: was === 'connecting' });
        if (next.wave) { clearTimeout(this.t2); this.t2 = setTimeout(() => this.setState({ wave: false }), 1900); }
      } else if (s.state === 'connecting') Object.assign(next, { phase: 'ing', cstep: STEP[s.step] ?? 0 });
      else if (s.state === 'reconnecting') Object.assign(next, { phase: 'ing', cs: s.error === 'offline' ? 'offline' : 'rec' });
      else if (s.state === 'blocked') Object.assign(next, { phase: 'off', cs: 'ks' });
      else if (s.state === 'error' && s.error === 'no_subscription') next.phase = 'off';
      else if (s.state === 'error') Object.assign(next, { phase: 'off', cs: s.error === 'offline' ? 'offline' : 'error' });
      else next.phase = 'off';
      this.setState(next);
    }

    // ---- subscriptions
    sub(): Sub | null {
      const list = this.subsList ?? [];
      return list.find((u) => u.id === this.st().liveSub) ?? list[0] ?? null;
    }
    applySubs(list: Sub[]) {
      this.subsList = list;
      const sub = this.sub();
      // the design's own switches: which sample plan it thinks is shown (5 none, 4 expired) and whether it has servers
      const expired = !!sub && sub.expire_unix > 0 && sub.expire_unix * 1000 < Date.now();
      const sel = sub?.servers.some((s) => s.id === this.st().sel) ? this.st().sel : 'auto';
      pref.set('sub', sub?.id ?? '');
      pref.set('server', sel);
      this.setState({ si: !sub ? 5 : expired ? 4 : 0, svN: sub?.servers.length ? 8 : 0, subst: 'ok', liveSub: sub?.id, sel });
      const ids = sub ? sub.id + ':' + sub.servers.map((n) => n.id).join(',') : '';
      if (sub && ids !== hostsFor) {
        hostsFor = ids;
        rpc<{ hosts: typeof HOSTS }>('servers.hosts', { sub: sub.id }).then((r) => { Object.assign(HOSTS, r.hosts); this.forceUpdate(); }, () => {});
      }
      if (sub?.servers.length && !pingedAtStart) {
        pingedAtStart = true;
        this.pingNodes(sub.servers);
      }
    }
    connect() {
      const sel = this.st().sel;
      this.ask('connect', { server: sel && sel !== 'auto' ? sel : 'auto', sub: this.sub()?.id ?? '' });
    }
    // picked: the protocol was chosen in the protocol menu (the design words that "Picked by you"; its own switch
    // for it is `prof`, a protocol of its sample node)
    choose(id: string, picked = false) {
      pref.set('server', id);
      this.setState({ sel: id, pop: false, prof: picked ? 'h2' : 'auto' }, () => {
        if (this.live && ['connected', 'connecting', 'reconnecting'].includes(this.live.state)) this.connect();
      });
    }
    // node by node, as the design staggers it: the numbers arrive down the list
    pingNodes(servers: Server[]) {
      nodesOf(servers).forEach((n, i) => setTimeout(() => this.ping(n.entries.map((e) => e.s.id)), i * 140));
    }
    // latency to the given servers, measured by the service outside the tunnel
    ping(ids: string[]) {
      const sub = this.sub();
      if (!sub || !ids.length) return;
      const mark = (on: boolean) => Object.fromEntries(ids.map((id) => [id, on]));
      this.setState({ checking: { ...this.st().checking, ...mark(true) } });
      rpc<{ rtt: Record<string, number> }>('servers.ping', { sub: sub.id, servers: ids }).then((r) => r.rtt, () => ({} as Record<string, number>)).then((rtt) => {
        // a server that did not answer keeps no number
        Object.assign(PINGS, Object.fromEntries(ids.map((id) => [id, rtt[id] ?? 0])));
        this.setState({ pings: { ...PINGS }, checking: { ...this.st().checking, ...mark(false) }, flash: { ...this.st().flash, ...mark(true) } });
        setTimeout(() => this.setState({ flash: { ...this.st().flash, ...mark(false) } }), 750); // the design's flash on a fresh number
      });
    }
    // preview first: nothing is added until the user presses the button on the sheet
    startAdd(text: string) {
      text = text.trim();
      if (!text) return;
      this.lastText = text;
      this.pending = null;
      this.setState({ add: 'check', subsPop: false });
      rpc<Sub>('subs.preview', { text }).then(
        (sub) => { this.pending = { text, sub }; this.setState({ add: 'basic' }); },
        (err) => {
          this.refusal = err?.code === 'refused' ? String(err.message ?? '') : '';
          this.setState({ add: err?.code === 'offline' || err?.code === 'fetch_failed' ? 'offline' : 'badlink' });
        },
      );
    }
    fromClipboard() {
      invoke<string>('clipboard_text').then((t) => (t.trim() ? this.startAdd(t) : this.setState({ add: 'badlink', subsPop: false })),
        () => this.setState({ add: 'badlink', subsPop: false }));
    }
    addFromField() {
      const typed = (document.querySelector('.onb-in input') as HTMLInputElement | null)?.value ?? '';
      const same = (a: string, b: string) => a.replace(/\s/g, '') === b.replace(/\s/g, '');
      if (typed.trim()) this.startAdd(this.pasted && same(typed, this.pasted) ? this.pasted : typed);
      else this.fromClipboard();
    }
    addFromFile() {
      const input = Object.assign(document.createElement('input'), { type: 'file', accept: '.conf,.txt,text/plain' });
      input.onchange = () => void input.files?.[0]?.text().then((t) => this.startAdd(t));
      input.click();
    }

    // the mock's own timers must not move the phase
    runSteps() {}
    switchTo(id: string) { this.choose(id); }
    setPhase(p: string) { if (p === 'off') this.ask('disconnect'); else this.connect(); }
    toggle() {
      if (this.blk || this.cs === 'svc') return;
      // off, failed, or held closed after a retry that cannot succeed: the button connects; otherwise it stops
      const idle = !this.live || ['off', 'error', 'blocked'].includes(this.live.state);
      if (!idle) return this.ask('disconnect');
      this.setState({ phase: 'ing', cs: '', cstep: 0, wave: false }); // the button answers at once; the service confirms
      this.connect();
    }

    renderVals() {
      const v = super.renderVals();
      const s: Status | null = this.live;
      const on = !!s && s.state === 'connected';
      if (on && this.traffic) {
        v.down = mbps(this.traffic.rx_bps);
        v.up = mbps(this.traffic.tx_bps);
        v.msTxt.cur = v.cur.ms = this.traffic.rtt_ms ? String(this.traffic.rtt_ms) : '—'; // 0: not measured yet
      } else if (on) v.down = v.up = '0.0';
      // "Unblock": open the network, stay off. Held by the "always" kill switch, that means stepping it down:
      // the service opens the network and reports off.
      v.csUnblock = () => (s?.error === 'kill_switch' ? void rpc('settings.set', { kill_switch: 'while' }).catch(() => {}) : this.ask('disconnect'));
      v.det = { on: false }; // the detector's chip is the design's sample until the detectors exist
      if (v.isErr) v.csS = ''; // the design's line counts tried servers; the service does not report that yet
      if (this.subsList) this.subsVals(v, on ? s : null);
      return v;
    }

    subsVals(v: any, on: Status | null) {
      const w = words();
      const list = this.subsList!;
      const sub = this.sub();
      const sel: string = this.st().sel || 'auto';
      const now = Date.now() / 1000;

      const card = (u: Sub) => {
        const daysLeft = Math.ceil((u.expire_unix - now) / DAY);
        const ended = u.expire_unix > 0 && u.expire_unix <= now;
        const forever = u.expire_unix === 0;
        const st = forever ? w.noEndCap : ended ? w.expired : w.left(w.days(daysLeft));
        const tone = ended ? 'bad' : !forever && daysLeft <= 3 ? 'warn' : '';
        const capped = u.total_bytes > 0;
        const left = Math.max(0, u.total_bytes - u.used_bytes);
        const file = u.kind === 'awg'; // pasted links are links; an AmneziaWG config is a file
        return {
          name: u.name, ini: (u.name.trim()[0] ?? '?').toUpperCase(), tone: 'lav', host: u.host, st, stCls: tone,
          // a stopped subscription says why (a panel that is inactive puts its status, or its own text, in the notice)
          meta: u.error ? w.subErr[u.error === 'inactive' ? u.notice ?? '' : u.error] || (u.error === 'inactive' && u.notice) || w.stale(w.time(u.updated_unix)) : `${w.servers(nodesOf(u.servers).length)} · ${forever ? w.noEnd : ended ? w.expiredMeta(w.date(u.expire_unix)) : w.left(w.days(daysLeft))}`,
          metaC: u.error ? 'stale' : '',
          tV: forever ? w.lifetime : ended ? w.expired : w.days(daysLeft), tS: forever ? w.noEnd : ended ? w.expiredOn(w.date(u.expire_unix)) : w.until(w.date(u.expire_unix)),
          tP: forever ? '100%' : `${Math.max(0, Math.min(100, Math.round((daysLeft / 30) * 100)))}%`, tG: forever ? 'inf' : tone, tN: 1, tInf: forever, tFin: !forever,
          dV: ended ? '—' : capped ? w.size(left) : u.used_bytes ? w.size(u.used_bytes) : '—', dS: ended ? w.renew : capped ? w.leftOf(w.size(u.total_bytes)) : u.used_bytes ? w.used : '',
          dP: capped ? `${Math.round((left / u.total_bytes) * 100)}%` : '100%', dG: capped ? '' : 'inf', dN: 1, dInf: !capped, dFin: capped,
          vV: '—', vS: '', vP: '0%', vG: '', vN: 1, vInf: false, vFin: true, // devices: only a Mistgate panel reports them
          src: file ? 'file' : 'link', srcT: file ? w.file : w.link, srcCls: file ? 'src-file' : 'src-link',
        };
      };

      // ---- the subscription card and the switcher
      if (sub) v.sub = card(sub);
      const mFor = this.st().mFor;
      const rmT = v.subs?.[1]?.rmT ?? 'Remove';
      v.subs = list.map((u, i) => ({
        ...card(u), i, cls: u.id === sub?.id ? 'on' : '', on: u.id === sub?.id ? 'true' : 'false',
        pick: () => { this.setState({ liveSub: u.id, subsPop: false, mFor: undefined, sel: 'auto' }, () => this.applySubs(list)); },
        mOpen: mFor === i, menu: () => this.setState({ mFor: mFor === i ? undefined : i }),
        // the design words the dialog from its own sample at this index: 1 is its "link" sample ("Remove", not "Sign out")
        ask: () => { this.rmId = u.id; this.setState({ rmAsk: 1, mFor: undefined }); }, rmT,
      }));
      if (v.rmOpen) {
        const name = list.find((u) => u.id === this.rmId)?.name ?? '';
        v.rmTitle = v.rmTitle.replace(v.rmName, name);
        v.rmName = name;
        v.rmDo = () => { void rpc('subs.remove', { id: this.rmId }).catch(() => {}); this.setState({ rmAsk: null, subsPop: false }); };
      }
      const baseToggle = v.toggleSubs;
      v.toggleSubs = (e?: { currentTarget?: Element }) => {
        // the "Add subscription" row of the switcher shares the switcher's handler in the design
        if (e?.currentTarget?.classList.contains('add')) this.fromClipboard();
        else baseToggle();
      };
      v.addSub = () => this.addFromField();
      v.addFile = () => this.addFromFile();
      v.refCls = this.st().ref ? 'busy' : '';
      v.refreshSub = () => {
        if (!sub || this.st().ref) return;
        this.setState({ ref: true });
        // the button turns for a moment even when the panel answers at once
        void Promise.all([rpc('subs.refresh', { id: sub.id }).catch(() => {}), new Promise((done) => setTimeout(done, 800))]).then(() => this.setState({ ref: false }));
      };
      // Telegram proxies come from a Mistgate panel only
      Object.assign(v, { tgN: 0, noTg: true, hasTg: false });

      // ---- servers: one row per node
      const servers = sub?.servers ?? [];
      const nodes = nodesOf(servers);
      const has = (n: Node, id: string) => n.entries.some((e) => e.s.id === id);
      const pings: Record<string, number> = this.st().pings ?? {}, checking: Record<string, boolean> = this.st().checking ?? {}, flash: Record<string, boolean> = this.st().flash ?? {};
      // the card beside a row under the pointer: where the server is and what it offers (the design's own card;
      // its "straight to server" wording comes from the design's sample row)
      const direct: string = (v.rows as any[] | undefined)?.find((r) => !r.via)?.tipD?.route ?? '';
      // A relay is another server's address: when a path enters at the address of a server in this list, it goes
      // "via" that server's country, in the design's own wording of the mark ("via RU").
      const sample = (v.rows as any[] | undefined)?.find((r) => r.via && r.mark);
      const viaWord: string = sample ? String(sample.mark).replace(sample.via, '').trim() : 'via';
      const entryAt = new Map<string, string>(); // a directly reached address -> its country code
      for (const x of servers) {
        const h = HOSTS[x.id]?.host;
        if (h && x.country && (!x.via || x.via === 'direct')) entryAt.set(h, x.country.toUpperCase());
      }
      const through = (x: Server) => { const cc = x.via === 'relay' ? entryAt.get(HOSTS[x.id]?.host ?? '') : ''; return cc ? `${viaWord} ${cc}` : ''; };
      for (const x of servers) { const t = through(x); if (t) VIA[x.id] = t; else delete VIA[x.id]; }
      // a node reached only through relays says so on its row
      const viaOf = (n: Node) => n.via || (n.entries.every((e) => e.s.via === 'relay') ? through(n.entries[0].s) : '');
      const LOAD: Record<string, number> = { low: 25, medium: 55, high: 85 };
      const tipOf = (n: Node, ms: string) => {
        const at = n.entries.map((e) => HOSTS[e.s.id]).find(Boolean);
        const kinds = [...new Set(n.entries.map((e) => e.s.via).filter((k) => k && k !== 'direct'))] as string[];
        const plain = n.entries.some((e) => !e.s.via || e.s.via === 'direct');
        const load = LOAD[n.entries[0].s.load ?? ''] ?? 0; // 0: the panel did not say, the line is hidden
        return {
          flag: n.flag, title: n.name + sufOf(n), city: n.entries[0].s.node ? n.entries[0].s.city ?? '' : '',
          host: at?.host ?? '—', ip: at ? (at.ips[0] ?? (/^[\d.:a-f]+$/i.test(at.host) ? at.host : '—')) + (at.ips.length > 1 ? ` +${at.ips.length - 1}` : '') : '—',
          route: viaOf(n) || (plain || !kinds.length ? direct : kinds.map((k) => (k === 'warp' ? 'WARP' : k)).join(' · ')),
          pl: [...new Map(n.entries.map((e) => [e.fam, { c: e.fam, t: PROTO[e.s.protocol]?.[2] ?? e.s.protocol }])).values()],
          load, loadC: load > 70 ? 'hi' : '', ms, msC: ms === '—' ? 'nov' : '',
        };
      };
      // the server in use, by its id: names repeat (two servers of one country)
      const inUse = (e: Entry) => !!on && (on.server_id ? e.s.id === on.server_id : e.s.name === on.server);
      const row = (n: Node) => {
        const ids = n.entries.map((e) => e.s.id);
        const best = Math.min(...ids.map((id) => pings[id] || Infinity));
        const busy = ids.some((id) => checking[id]);
        const fams = new Set(n.entries.map((e) => e.fam));
        const ms = best === Infinity ? '—' : String(best);
        return {
          tipD: tipOf(n, ms), hout: () => this.setState({ tipId: '' }),
          // placed as the design places it: left of the list, level with the row, kept inside the list
          hin: (e: any) => {
            const el: HTMLElement = e.currentTarget, r = el.getBoundingClientRect(), sv = el.closest('.servers')!.getBoundingClientRect(), rtl = getComputedStyle(el).direction === 'rtl';
            const tall = (document.querySelector('.stip') as HTMLElement | null)?.offsetHeight || 250;
            this.setState({ tipId: n.key, tipX: Math.round(rtl ? sv.right + 10 : sv.left - 282), tipY: Math.round(Math.max(sv.top, Math.min(r.top - 10, sv.bottom - tall))) });
          },
          key: n.key, id: n.name, country: n.name, suf: sufOf(n), mark: viaOf(n), mkc: viaOf(n) ? '' : 'hide', flag: n.flag, via: viaOf(n), hasVia: !!viaOf(n),
          now: !!on && n.entries.some((e) => inUse(e)),
          h2: fams.has('h2'), vless: false, awg: fams.has('awg'), label: [...new Set(n.entries.map((e) => e.full))].join(', '),
          rcls: has(n, sel) ? 'on' : '', on: has(n, sel) ? 'true' : 'false', pick: () => { if (!has(n, sel)) this.choose(ids[0]); },
          vd: '', vt: '', vi: 'check', vc: 'hide', vo: 0, vrow: '', pisC: '',
          sigX: best === Infinity ? 'nov' : '', sig: (best === Infinity ? '' : quality(best)) + (busy ? ' busy' : '') + (ids.some((id) => flash[id]) ? ' flash' : ''), ping: () => this.ping(ids), ms: best === Infinity ? '—' : String(best),
        };
      };
      // the search: a country, a city, the panel's own wording, or a piece of the address
      const q = String(this.st().q ?? '').trim().toLowerCase();
      const found = (n: Node) => !q || [n.name, n.extra, n.via, ...n.entries.flatMap((e) => [e.s.name, e.s.city, e.s.country, HOSTS[e.s.id]?.host])].some((x) => x?.toLowerCase().includes(q));
      const allIds = servers.map((n) => n.id);
      const bestAll = Math.min(Infinity, ...allIds.map((id) => pings[id] || Infinity));
      Object.assign(v, {
        rows: nodes.filter(found).map(row), rowsBad: [], badLbl: 'hide', srvN: nodes.length, hasSrv: nodes.length > 0, noSrvList: nodes.length === 0,
        isAuto: sel === 'auto', autoCls: sel === 'auto' ? 'on' : '', pickAuto: () => this.choose('auto'),
        pingAll: () => this.pingNodes(servers), allBusy: allIds.some((id) => checking[id]) ? 'busy' : '',
      });
      const tipRow = (v.rows as any[]).find((x) => x.key === this.st().tipId);
      if (tipRow) this.tipLast = tipRow.tipD;
      v.tip = this.tipLast ?? v.rows[0]?.tipD ?? { pl: [] };
      // the Auto row carries the best number of the list (the design keys it to its sample node "de")
      v.sigCls.de = bestAll === Infinity ? 'nov' : quality(bestAll);
      v.msTxt.de = bestAll === Infinity ? '—' : String(bestAll);
      // the bar under the button: the node and protocol in use, or the ones a press would connect to
      // Auto connects to the server that answers quickest: the bar shows the one the numbers point to
      const quick = (n: Node) => Math.min(...n.entries.map((e) => pings[e.s.id] || Infinity));
      const quickest = nodes.reduce<Node | undefined>((a, n) => (quick(n) < (a ? quick(a) : Infinity) ? n : a), undefined);
      const node = (on && nodes.find((n) => n.entries.some((e) => inUse(e)))) || nodes.find((n) => has(n, sel)) || quickest || nodes[0];
      if (node) {
        // (the plain path first in the list: Auto does not choose a relay or a WARP exit when a plain path exists)
        const entry = (on && node.entries.find((e) => inUse(e))) || node.entries.find((e) => e.s.id === sel) || node.entries[0];
        const picked = this.st().prof === 'h2' && sel !== 'auto';
        Object.assign(v.cur, {
          country: node.name, suf: sufOf(node), title: node.name, flag: node.flag, fam: entry.fam, label: entry.label,
          isH2: entry.fam === 'h2', isAwg: entry.fam === 'awg', isVless: false,
          // the design says "direct" after the dot; a node reached through another says so in the subscription's words
          srvSub: viaOf(node) ? String(v.cur.srvSub).split(' · ')[0] + ' · ' + viaOf(node) : v.cur.srvSub,
        });
        if (!on || !this.traffic) v.msTxt.cur = v.cur.ms = '—';
        Object.assign(v, {
          profs: node.entries.map((e) => ({
            fam: e.fam, label: through(e.s) ? e.label.replace('relay', through(e.s)) : e.label, full: through(e.s) ? e.full.replace('relay', through(e.s)) : e.full, isH2: e.fam === 'h2', isVless: false, isAwg: e.fam === 'awg',
            cls: picked && e.s.id === sel ? 'on' : '', on: picked && e.s.id === sel ? 'true' : 'false', pick: () => this.choose(e.s.id, true),
          })),
          profAuto: !picked, poAutoCls: picked ? '' : 'on',
          pickProfAuto: () => this.choose(sel === 'auto' ? 'auto' : node.entries[0].s.id),
        });
      }

      // ---- the add sheet: the design's "from a file" variant is the basic mode's confirm
      const p = this.pending;
      if (v.ad.isCheck) v.ad.host = /^https:\/\/[^\s]+$/.test(this.lastText) ? this.lastText.split('/')[2] : '';
      if (v.ad.isConfirm && p) {
        const link = p.sub.kind !== 'awg'; // the design's "file on this PC" wording is for a config file only
        Object.assign(v.ad, {
          name: p.sub.name, host: link ? p.sub.host : v.ad.host, srcT: link ? w.link : v.ad.srcT, srcI: link ? 'link' : v.ad.srcI,
          f1: String(nodesOf(p.sub.servers).length), f2: String(new Set(p.sub.servers.map((n) => n.protocol)).size),
          goT: w.add(w.servers(nodesOf(p.sub.servers).length)),
          go: () => {
            this.setState({ add: 'check' });
            rpc<Sub>('subs.add', { text: p.text }).then(
              // the list may have arrived before this answer: re-derive the screen for the new choice
              (added) => {
                this.pending = null;
                // with the list asked again: this answer can come before the list that has the new subscription
                this.setState({ add: 'none', liveSub: added.id, sel: 'auto' }, () => rpc<{ subs: Sub[] }>('subs.list').then((r) => this.applySubs(r.subs), () => {}));
              },
              () => this.setState({ add: 'badlink' }),
            );
          },
        });
        if (p.sub.expire_unix) Object.assign(v.ad, { f3: w.date(p.sub.expire_unix), f3s: w.validUntil });
      }
      if (v.ad.isErr) {
        if (this.refusal) v.ad.ep = this.refusal; // the panel says why; the design's text would only guess
        const retry = this.st().add === 'offline';
        v.ad.b1Go = () => (retry ? this.startAdd(this.lastText) : this.setState({ add: 'none' }));
        v.ad.b2Go = () => this.setState({ add: 'none' });
      }
    }
  } as unknown as typeof DCLogic;
}
