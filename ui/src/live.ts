// The Home screen on the real service. The design's logic class stays as generated (it plays a mock connection and
// sample subscriptions); in the app window this subclass takes its place: the power button calls the service, and the
// phase, the step, the timer, the traffic, the subscriptions and their servers come from the service (docs/ipc.md).
// Where the design computes a text itself (titles, hints, button labels) its text is kept and only the data changes.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import FLAGS from './design/flags.json';
import { words } from './live-i18n';

type Status = { state: string; step: string; since_unix: number; server: string; protocol: string; error: string };
type Traffic = { rx_bps: number; tx_bps: number; rtt_ms: number };
type Server = { id: string; name: string; protocol: string };
type Sub = {
  id: string; kind: 'url' | 'links' | 'awg'; name: string; host: string; updated_unix: number; expire_unix: number;
  used_bytes: number; total_bytes: number; error: string; unsupported: number; servers: Server[];
};

const rpc = <T = Status>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
// The design words four steps; its second ("UDP looks blocked") is a detector's line, not a step of ours.
const STEP: Record<string, number> = { resolve: 0, handshake: 2, tunnel: 3, verify: 3 };
const PROTO: Record<string, [fam: string, label: string, full: string]> = {
  hysteria2: ['h2', 'HY2', 'Hysteria2'], awg: ['awg', 'AWG 3.1', 'AmneziaWG'],
};
const mbps = (bps: number) => (bps / 1e6).toFixed(1);
const DAY = 86400;

// "🇩🇪 Germany" -> the design's flag for "de" and the name without the emoji. A name is shown as the subscription
// gives it; a flag appears only when the name carries one the design has.
function flagOf(name: string) {
  const m = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (!m) return { flag: '', text: name };
  const cc = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0)! - 0x1f1e6 + 97)).join('');
  return { flag: (FLAGS as Record<string, string>)[cc] ?? '', text: name.replace(m[0], '').trim() || name };
}

export function liveHome(Base: typeof DCLogic): typeof DCLogic {
  return class LiveHome extends (Base as any) {
    off: Promise<UnlistenFn>[] = [];
    live: Status | null = null;
    traffic: Traffic | null = null;
    subsList: Sub[] | null = null; // null until the service has answered
    pending: { text: string; sub: Sub } | null = null; // the subscription on the confirm sheet
    lastText = '';
    pasted = ''; // what was pasted into the link field, with its line breaks (the field itself drops them)
    onPaste = (e: ClipboardEvent) => {
      if ((e.target as Element | null)?.closest?.('.onb-in')) this.pasted = e.clipboardData?.getData('text') ?? '';
    };
    rmId = '';

    componentDidMount() {
      super.componentDidMount();
      this.off = [
        listen<Status>('mg://status', (e) => this.apply(e.payload)),
        listen<Traffic>('mg://traffic', (e) => { this.traffic = e.payload; this.forceUpdate(); }),
        listen<{ subs: Sub[] }>('mg://subs', (e) => this.applySubs(e.payload.subs)),
        listen<{ up: boolean }>('mg://service', (e) => (e.payload.up ? this.sync() : this.setState({ cs: 'svc', wave: false }))),
      ];
      document.addEventListener('paste', this.onPaste, true);
      this.sync();
    }
    componentWillUnmount() {
      super.componentWillUnmount();
      document.removeEventListener('paste', this.onPaste, true);
      this.off.forEach((p) => void p.then((un) => un()));
    }

    sync() {
      this.ask('status');
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
      this.setState({ si: !sub ? 5 : expired ? 4 : 0, svN: sub?.servers.length ? 8 : 0, subst: 'ok', liveSub: sub?.id, sel });
    }
    connect() {
      const sel = this.st().sel;
      this.ask('connect', { server: sel && sel !== 'auto' ? sel : 'auto', sub: this.sub()?.id ?? '' });
    }
    choose(id: string) {
      this.setState({ sel: id, pop: false }, () => {
        if (this.live && ['connected', 'connecting', 'reconnecting'].includes(this.live.state)) this.connect();
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
        (err) => this.setState({ add: err?.code === 'offline' || err?.code === 'fetch_failed' ? 'offline' : 'badlink' }),
      );
    }
    fromClipboard() {
      navigator.clipboard.readText().then((t) => (t.trim() ? this.startAdd(t) : this.setState({ add: 'badlink', subsPop: false })),
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
        v.msTxt.cur = v.cur.ms = String(this.traffic.rtt_ms);
      } else if (on) v.down = v.up = '0.0';
      v.csUnblock = () => this.ask('disconnect'); // "Unblock": open the network, stay off
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
        const file = u.kind !== 'url';
        return {
          name: u.name, ini: (u.name.trim()[0] ?? '?').toUpperCase(), tone: 'lav', host: u.host, st, stCls: tone,
          meta: u.error ? w.stale(w.time(u.updated_unix)) : `${w.servers(u.servers.length)} · ${forever ? w.noEnd : ended ? w.expiredMeta(w.date(u.expire_unix)) : w.left(w.days(daysLeft))}`,
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
        void rpc('subs.refresh', { id: sub.id }).catch(() => {}).then(() => this.setState({ ref: false }));
      };
      // Telegram proxies come from a Mistgate panel only
      Object.assign(v, { tgN: 0, noTg: true, hasTg: false });

      // ---- servers
      const servers = sub?.servers ?? [];
      const current = servers.find((n) => n.id === sel) ?? servers[0];
      const row = (n: Server) => {
        const { flag, text } = flagOf(n.name);
        const [fam, , full] = PROTO[n.protocol] ?? ['', '', n.protocol];
        return {
          id: n.id, country: text, suf: '', mark: '', mkc: 'hide', flag, via: '', hasVia: false,
          now: !!on && (sel === n.id || (sel === 'auto' && on.server === n.name)),
          h2: fam === 'h2', vless: false, awg: fam === 'awg', label: full,
          rcls: sel === n.id ? 'on' : '', on: sel === n.id ? 'true' : 'false', pick: () => this.choose(n.id),
          vd: '', vt: '', vi: 'check', vc: 'hide', vo: 0, vrow: '', pisC: '',
          sigX: 'nov', sig: '', ping: () => {}, ms: '—', // ponytail: no latency tests yet; they come with the detectors
        };
      };
      Object.assign(v, {
        rows: servers.map(row), rowsBad: [], badLbl: 'hide', srvN: servers.length, hasSrv: servers.length > 0, noSrvList: servers.length === 0,
        isAuto: sel === 'auto', autoCls: sel === 'auto' ? 'on' : '', pickAuto: () => this.choose('auto'), pingAll: () => {}, allBusy: '',
      });
      v.sigCls.de = 'nov';
      v.msTxt.de = '—';
      // the bar under the button: the server in use, or the one a press would connect to
      const shown = on ? { name: on.server, protocol: on.protocol } : current;
      if (shown) {
        const { flag, text } = flagOf(shown.name);
        const [fam, label] = PROTO[shown.protocol] ?? ['', shown.protocol];
        Object.assign(v.cur, { country: text, suf: '', title: text, flag, fam, label, isH2: fam === 'h2', isAwg: fam === 'awg', isVless: false });
        if (!on || !this.traffic) v.msTxt.cur = v.cur.ms = '—';
      }

      // ---- the add sheet: the design's "from a file" variant is the basic mode's confirm
      const p = this.pending;
      if (v.ad.isCheck) v.ad.host = /^https:\/\/[^\s]+$/.test(this.lastText) ? this.lastText.split('/')[2] : '';
      if (v.ad.isConfirm && p) {
        const url = p.sub.kind === 'url';
        Object.assign(v.ad, {
          name: p.sub.name, host: url ? p.sub.host : v.ad.host, srcT: url ? w.link : v.ad.srcT, srcI: url ? 'link' : v.ad.srcI,
          f1: String(p.sub.servers.length), f2: String(new Set(p.sub.servers.map((n) => n.protocol)).size),
          goT: w.add(w.servers(p.sub.servers.length)),
          go: () => {
            this.setState({ add: 'check' });
            rpc<Sub>('subs.add', { text: p.text }).then(
              // the list may have arrived before this answer: re-derive the screen for the new choice
              (added) => { this.pending = null; this.setState({ add: 'none', liveSub: added.id, sel: 'auto' }, () => this.subsList && this.applySubs(this.subsList)); },
              () => this.setState({ add: 'badlink' }),
            );
          },
        });
        if (p.sub.expire_unix) Object.assign(v.ad, { f3: w.date(p.sub.expire_unix), f3s: w.validUntil });
      }
      if (v.ad.isErr) {
        const retry = this.st().add === 'offline';
        v.ad.b1Go = () => (retry ? this.startAdd(this.lastText) : this.setState({ add: 'none' }));
        v.ad.b2Go = () => this.setState({ add: 'none' });
      }
    }
  } as unknown as typeof DCLogic;
}
