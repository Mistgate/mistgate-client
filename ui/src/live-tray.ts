// The tray: the icon (drawn from the design's glyphs for the current state) and the quick panel's window.
// As elsewhere, the design's logic stays as generated; the panel's subclass feeds it the service's state.
import { FLAG } from './flags';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import GLYPHS from './design/tray-icons.json';
import { words } from './live-i18n';
import { pref } from './live-settings';

type Status = { state: string; step: string; since_unix: number; server: string; protocol: string; error: string };
type Traffic = { rx_bps: number; tx_bps: number; rtt_ms: number };
type Server = { id: string; name: string; protocol: string };
type Sub = { id: string; name: string; servers: Server[] };

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
// the service's state as the design names it
const view = (s: Status | null) =>
  !s ? 'off' : s.state === 'connected' ? 'on' : s.state === 'connecting' || s.state === 'reconnecting' ? 'ing'
    : s.state === 'blocked' ? 'ks' : s.state === 'error' ? 'error' : 'off';
const LABEL: Record<string, string> = { hysteria2: 'HY2', awg: 'AWG 3.1', vless: 'VLESS' };

function flagOf(name: string) {
  const m = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (!m) return { flag: '', text: name };
  const cc = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0)! - 0x1f1e6 + 97)).join('');
  return { flag: FLAG[cc] ?? '', text: name.replace(m[0], '').trim() || name };
}

// ---- the icon: lives in the main window, which is always there (hidden when closed to the tray)
async function glyph(state: string, size: number) {
  // the glyphs take the text colour in the design; on the taskbar that is white, or dark on a light taskbar
  const ink = matchMedia('(prefers-color-scheme: light)').matches ? '#1b1b22' : '#ffffff';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="${ink}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><style>.f,.d{fill:${ink};stroke:none}.dash{stroke-dasharray:2.6 3.4}</style>${(GLYPHS as Record<string, string>)[state] ?? GLYPHS.off}</svg>`;
  const img = new Image();
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  await img.decode();
  const canvas = Object.assign(document.createElement('canvas'), { width: size, height: size });
  const ctx = canvas.getContext('2d')!;
  ctx.drawImage(img, 0, 0, size, size);
  return Array.from(ctx.getImageData(0, 0, size, size).data);
}

// The tooltip is the design's, in the window's language: asked from its Tray logic without mounting it.
function tooltip(Tray: typeof DCLogic, state: string, server: string) {
  const logic: any = new (Tray as any)({ state });
  logic.state = {};
  const v = logic.renderVals();
  const sample = v.rows?.[1]?.n; // the design's sample server in its texts
  return sample && server ? String(v.tipTxt).replace(sample, flagOf(server).text) : String(v.tipTxt);
}

export function startTrayIcon(Tray: typeof DCLogic) {
  let last = '', seq = 0;
  const show = (s: Status | null) => {
    const state = view(s);
    const key = state + '|' + (s?.server ?? '');
    if (key === last) return;
    last = key;
    const n = ++seq; // a slower drawing of an older state must not land on top of a newer one
    void glyph(state, 32).then((rgba) => n === seq && invoke('tray_state', { rgba, size: 32, tooltip: tooltip(Tray, state, state === 'on' ? s!.server : '') }));
  };
  void listen<Status>('mg://status', (e) => show(e.payload));
  void listen<{ up: boolean }>('mg://service', (e) => (e.payload.up ? rpc<Status>('status').then(show, () => show(null)) : show(null)));
  rpc<Status>('status').then(show, () => show(null));
}

// ---- the quick panel
export function liveTray(Base: typeof DCLogic): typeof DCLogic {
  return class LiveTray extends (Base as any) {
    off: Promise<UnlistenFn>[] = [];
    live: Status | null = null;
    traffic: Traffic | null = null;
    subs: Sub[] = [];
    clock = 0;
    height = 0;

    componentDidMount() {
      super.componentDidMount?.();
      this.off = [
        listen<Status>('mg://status', (e) => this.apply(e.payload)),
        listen<Traffic>('mg://traffic', (e) => { this.traffic = e.payload; this.paintSpeed(); }),
        listen<{ subs: Sub[] }>('mg://subs', (e) => { this.subs = e.payload.subs; this.forceUpdate(); }),
        listen<{ up: boolean }>('mg://service', () => this.sync()),
      ];
      // the panel's two plain buttons have no handler in the design
      document.addEventListener('click', this.onClick);
      // the panel is shown again and again without being loaded again: catch up each time
      window.addEventListener('focus', this.sync);
      this.clock = window.setInterval(() => this.live?.state === 'connected' && !document.hidden && this.forceUpdate(), 1000);
      this.sync();
    }
    componentWillUnmount() {
      super.componentWillUnmount?.();
      this.off.forEach((p) => void p.then((un) => un()));
      document.removeEventListener('click', this.onClick);
      window.removeEventListener('focus', this.sync);
      clearInterval(this.clock);
    }
    componentDidUpdate() { this.paintSpeed(); this.fit(); }

    onClick = (e: MouseEvent) => {
      const t = e.target as Element;
      if (t.closest('.fy-f button')) void invoke('show_main', {});
      else if (t.closest('.fy-ib')) void invoke('show_main', { screen: 'Settings' });
      else if (t.closest('.acts.err-go, .fy-strip .acts:not(.hide) .pri') && this.live?.state === 'error') void invoke('show_main', { screen: 'Diag' });
    };
    sync = () => {
      rpc<Status>('status').then((s) => this.apply(s), () => this.apply({ state: 'off', step: '', since_unix: 0, server: '', protocol: '', error: '' }));
      rpc<{ subs: Sub[] }>('subs.list').then((r) => { this.subs = r.subs; this.forceUpdate(); }, () => {});
      // the choice is kept beside the design's own "sel": its logic only knows its sample servers
      this.setState({ liveSel: pref.get('server') || 'auto', theme: pref.get('theme') || undefined });
    };
    apply(s: Status) {
      this.live = s;
      if (s.state !== 'connected') this.traffic = null;
      this.setState({ ts: view(s), sw: false, step: s.step === 'resolve' ? 0 : 3 });
    }
    sub() { return this.subs.find((u) => u.id === pref.get('sub')) ?? this.subs[0] ?? null; }
    connect() { void rpc('connect', { server: pref.get('server') || 'auto', sub: this.sub()?.id ?? '' }).catch(() => {}); }
    switchTo(id: string) { this.pick(id); }
    pick(id: string) {
      pref.set('server', id);
      this.setState({ liveSel: id });
      if (this.live && ['connected', 'connecting', 'reconnecting'].includes(this.live.state)) this.connect();
    }
    // the strip's numbers are plain text in the design: write the real ones into it
    paintSpeed() {
      const cells = document.querySelectorAll('.fy-strip .spd3 > span');
      const t = this.traffic;
      const put = (cell: Element | undefined, value: string) => {
        const text = cell && [...cell.childNodes].find((n) => n.nodeType === 3 && n.textContent!.trim());
        if (text) text.textContent = value + ' ';
      };
      put(cells[0], t ? (t.rx_bps / 1e6).toFixed(1) : '0.0');
      put(cells[1], t ? (t.tx_bps / 1e6).toFixed(1) : '0.0');
      put(cells[2], t ? String(t.rtt_ms) : '—');
    }
    fit() {
      const h = (document.querySelector('.ty-fly') as HTMLElement | null)?.offsetHeight ?? 0;
      if (h && h !== this.height) { this.height = h; void invoke('tray_fit', { height: h + 16 }); }
    }

    renderVals() {
      const v = super.renderVals();
      const s = this.live;
      const state = view(s);
      const sub = this.sub();
      const servers = sub?.servers ?? [];
      const sel: string = this.state?.liveSel || 'auto';
      const sample: string = v.rows?.[1]?.n ?? ''; // the design's sample server inside its own texts
      const target = s && s.state === 'connected' ? s.server : (servers.find((n) => n.id === sel) ?? servers[0])?.name ?? '';
      const name = flagOf(target).text;

      v.isFly = true; v.isMenu = v.isTip = v.isToast = false;
      v.subName = sub?.name ?? v.subName;
      v.subMeta = sub ? words().servers(servers.length) : '';
      v.H = { ...v.H };
      if (state === 'on' && s) {
        const secs = Math.max(0, Math.floor(Date.now() / 1000) - s.since_unix);
        v.H.t = Math.floor(secs / 3600) + ':' + String(Math.floor(secs / 60) % 60).padStart(2, '0') + ':' + String(secs % 60).padStart(2, '0');
        v.H.s = name + ' · ' + (LABEL[s.protocol] ?? s.protocol);
      } else if (state === 'ing') v.H.s = sample && name ? String(v.H.s).replace(sample, name) : '';
      else if (state === 'error') v.H.s = ''; // the design counts tried servers; the service does not report that yet
      v.toggle = () => (state === 'on' || state === 'ing' ? void rpc('disconnect').catch(() => {}) : this.connect());
      // held by the "always" kill switch, unblocking means stepping it down (as on Home)
      v.unblock = () => void (s?.error === 'kill_switch' ? rpc('settings.set', { kill_switch: 'while' }) : rpc('disconnect')).catch(() => {});
      const auto = v.rows?.[0];
      v.rows = [
        ...(auto ? [{ ...auto, ms: '—', c: sel === 'auto' ? 'on' : '', on: sel === 'auto' ? 'true' : 'false', nowC: 'hide', go: () => this.pick('auto') }] : []),
        ...servers.slice(0, 5).map((n) => {
          const { flag, text } = flagOf(n.name);
          return {
            n: text, suf: '', ms: '—', flag, c: sel === n.id ? 'on' : '', on: sel === n.id ? 'true' : 'false', fgC: '', imC: '', auC: 'hide', v: '', vC: 'hide',
            nowC: state === 'on' && (sel === n.id || (sel === 'auto' && s!.server === n.name)) ? '' : 'hide', go: () => this.pick(n.id),
          };
        }),
      ];
      return v;
    }
  } as unknown as typeof DCLogic;
}
