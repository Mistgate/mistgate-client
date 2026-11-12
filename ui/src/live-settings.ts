// The other screens on the real service: the VPN chip in their title bar, and Settings itself.
// As on Home, the design's logic stays as generated; these subclasses feed it the service's state and send its
// choices to the service. What the service has no setting for yet stays the design's local switch.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import { version } from '../package.json';
import type { Sub } from './live';
import { words } from './live-i18n';

type Status = { state: string; server: string; server_id?: string; protocol?: string };
type Settings = { kill_switch: 'off' | 'while' | 'always'; lan: boolean; protocol: 'auto' | 'hysteria2' | 'awg'; game: boolean; autoconnect: boolean };

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });

// What this window remembers between screens and starts: the chosen subscription and server, the theme, the language.
export const pref = {
  get: (key: string) => { try { return localStorage.getItem(key) ?? ''; } catch { return ''; } },
  set: (key: string, value: string) => { try { localStorage.setItem(key, value); } catch { /* lasts this start */ } },
};
export function setTheme(theme: string) {
  pref.set('theme', theme);
  window.dispatchEvent(new CustomEvent('mg-theme', { detail: theme }));
}
// the screens of a language are loaded at start: changing it starts the window's page again
function setLang(lang: string) {
  pref.set('lang', lang);
  location.reload();
}

// What the shell (the Rust side) keeps for the window: whether the × hides to the tray, and the Run key.
// "Connect when Windows starts" is both halves: the window starts with Windows, and the service connects on its own.
const flag = (key: string, fallback: boolean) => (pref.get(key) ? pref.get(key) === '1' : fallback);
export const shellPrefs = () => ({ auto: flag('auto', false), min: flag('min', true), tray: flag('tray', true) });
function applyShell(changed?: 'auto' | 'min' | 'tray') {
  const p = shellPrefs();
  void invoke('shell_prefs', { closeToTray: p.tray });
  if (changed === 'auto' || changed === 'min') void invoke('autostart', { enabled: p.auto, minimized: p.min }).catch(() => {});
}
export function startShell() {
  applyShell();
  void listen<string>('mg://nav', (e) => window.dispatchEvent(new CustomEvent('mg-nav', { detail: e.payload })));
  // "Subscription page" in the side bar of every screen: the design links its sample address. The page of the
  // subscription shown is opened in the browser; a subscription without a page (pasted servers, a config) has none.
  document.addEventListener('click', (e) => {
    if (!(e.target as Element | null)?.closest?.('a.rb.sub')) return;
    e.preventDefault();
    void rpc<{ url: string }>('subs.link', { id: pref.get('sub') }).then((r) => invoke('open_url', { url: r.url }), () => {});
  }, true);
  // Quit: "exit" is 'keep' (the VPN stays on, the default) or 'disconnect'.
  // ponytail: no control for it in the design yet, and no "ask" (that needs a designed dialog).
  void listen('mg://quit', async () => {
    if (pref.get('exit') === 'disconnect') await Promise.race([rpc('disconnect').catch(() => {}), new Promise((r) => setTimeout(r, 2000))]);
    void invoke('quit_now');
  });
}

// The chip in the title bar of every screen but Home: connected or not, where to, and a button for it.
export function liveChip(Base: typeof DCLogic): typeof DCLogic {
  return class LiveChip extends (Base as any) {
    off: Promise<UnlistenFn>[] = [];
    server = '';
    proto = '';
    serverId = ''; // the server in use: names repeat, ids do not
    componentDidMount() {
      super.componentDidMount?.();
      this.off = [listen<Status>('mg://status', (e) => this.status(e.payload))];
      rpc<Status>('status').then((s) => this.status(s), () => this.status({ state: 'off', server: '' }));
      this.mounted();
    }
    componentWillUnmount() {
      super.componentWillUnmount?.();
      this.off.forEach((p) => void p.then((un) => un()));
    }
    mounted() {}
    status(s: Status) {
      this.server = s.state === 'connected' ? s.server : '';
      this.proto = s.state === 'connected' ? s.protocol ?? '' : '';
      this.serverId = s.state === 'connected' ? s.server_id ?? '' : '';
      this.setState({ vp: s.state === 'connected' ? 'on' : s.state === 'connecting' || s.state === 'reconnecting' ? 'ing' : 'off' });
    }
    renderVals() {
      const v = super.renderVals();
      if (v.tbs) {
        const off = (this.state?.vp ?? 'on') === 'off';
        Object.assign(v.tbs, {
          m: this.server, mc: this.server ? '' : 'hide',
          go: () => void rpc(off ? 'connect' : 'disconnect', off ? { server: pref.get('server') || 'auto', sub: pref.get('sub') } : {}).catch(() => {}),
        });
      }
      return v;
    }
  } as unknown as typeof DCLogic;
}

const PR: Record<string, Settings['protocol']> = { auto: 'auto', h2: 'hysteria2', awg: 'awg' };
const PR_BACK: Record<string, string> = { auto: 'auto', hysteria2: 'h2', awg: 'awg' };

export function liveSettings(Base: typeof DCLogic): typeof DCLogic {
  return class LiveSettings extends (liveChip(Base) as any) {
    subs: Sub[] = [];
    mounted() {
      const subs = (list: Sub[]) => { this.subs = list; this.forceUpdate(); };
      this.off.push(listen<{ subs: Sub[] }>('mg://subs', (e) => subs(e.payload.subs)));
      rpc<{ subs: Sub[] }>('subs.list').then((r) => subs(r.subs), () => {});
      // "Subscription page" inside the Subscription section is a link to the design's sample address
      document.addEventListener('click', this.onPage, true);
      this.off.push(listen<Settings>('mg://settings', (e) => this.apply(e.payload)));
      rpc<Settings>('settings.get').then((s) => this.apply(s), () => {});
      this.setState({ lg: document.documentElement.lang || 'en' });
    }
    componentWillUnmount() {
      super.componentWillUnmount();
      document.removeEventListener('click', this.onPage, true);
    }
    onPage = (e: MouseEvent) => {
      if (!(e.target as Element | null)?.closest?.('.sb-act a')) return;
      e.preventDefault();
      const id = this.sub()?.id;
      if (id) void rpc<{ url: string }>('subs.link', { id }).then((r) => invoke('open_url', { url: r.url }), () => {});
    };
    sub(): Sub | null { return this.subs.find((u) => u.id === pref.get('sub')) ?? this.subs[0] ?? null; }
    // The Subscription section: the subscription shown on Home, with the service's numbers.
    subVals(v: any, u: Sub) {
      const w = words(), now = Date.now() / 1000, DAY = 86400;
      const daysLeft = Math.ceil((u.expire_unix - now) / DAY), forever = u.expire_unix === 0, ended = !forever && u.expire_unix <= now;
      const capped = u.total_bytes > 0, left = Math.max(0, u.total_bytes - u.used_bytes);
      const why = u.error ? w.subErr[u.error === 'inactive' ? u.notice ?? '' : u.error] || (u.error === 'inactive' && u.notice) || '' : '';
      const stale = u.error && !why; // the last update failed: the saved copy is in use
      Object.assign(v.S, {
        name: u.name, ini: (u.name.trim()[0] ?? '?').toUpperCase(), logoC: 'hide', iniC: '', host: u.host,
        srcT: u.managed ? 'Mistgate' : u.kind === 'awg' ? w.file : w.link, srcCls: u.managed ? 'src-mg' : 'src-link',
        st: why || (ended ? w.expired : v.S.st), stC: why || ended ? 'bad' : stale ? 'warn' : 'ok', pageCls: u.kind === 'url' ? '' : 'hide',
        e: forever ? w.lifetime : w.date(u.expire_unix), eS: forever ? w.noEnd : ended ? w.expired : w.left(w.days(daysLeft)),
        eP: forever ? '100%' : `${Math.max(0, Math.min(100, Math.round((daysLeft / 30) * 100)))}%`, eC: ended ? 'bad' : !forever && daysLeft <= 3 ? 'warn' : '',
        d: capped ? w.size(left) : u.used_bytes ? w.size(u.used_bytes) : '—', dS: capped ? w.leftOf(w.size(u.total_bytes)) : u.used_bytes ? w.used : '',
        dP: capped ? `${Math.round((left / u.total_bytes) * 100)}%` : '100%', dC: capped && left / u.total_bytes < 0.1 ? 'warn' : '',
        v: '—', vS: '', vP: '0%', vC: 'na', // devices: the panel does not say yet
      });
      v.B = { show: 'hide', c: '', tone: '', t: '', s: '', b: '', bc: 'hide' };
      const busy = !!this.state?.syncing;
      Object.assign(v, {
        subDim: '', devGrp: 'hide', renaming: false, basicGrp: u.managed ? 'hide' : '', syncGrp: u.kind === 'url' ? '' : 'hide',
        syncT: busy ? v.syncT : stale ? w.stale(w.time(u.updated_unix)) : w.synced(w.time(u.updated_unix)), syncS: '', syncCls: stale ? 'warn' : '',
        syncNow: () => {
          if (busy) return;
          this.setState({ syncing: true });
          void Promise.all([rpc('subs.refresh', { id: u.id }).catch(() => {}), new Promise((done) => setTimeout(done, 800))]).then(() => this.setState({ syncing: false }));
        },
      });
    }
    // into the design's own switches, so its notes and summaries follow
    apply(s: Settings) {
      this.setState((old: any) => ({
        ks: s.kill_switch, ksAsk: false, pr: PR_BACK[s.protocol] ?? 'auto',
        on: Object.assign({}, old?.on, { lan: s.lan, game: s.game, auto: s.autoconnect, min: shellPrefs().min, tray: shellPrefs().tray }),
      }));
    }
    save(patch: Partial<Settings>) {
      rpc<Settings>('settings.set', patch).then((s) => this.apply(s), () => {});
    }
    renderVals() {
      const v = super.renderVals();
      const on = Object.assign({ lan: true, game: false }, this.state?.on);
      v.ksSet.off = () => this.save({ kill_switch: 'off' });
      v.ksSet.while = () => this.save({ kill_switch: 'while' });
      v.ksYes = () => this.save({ kill_switch: 'always' }); // "always" goes through the design's confirmation first
      v.tg.lan = () => this.save({ lan: !on.lan });
      v.tg.game = () => this.save({ game: !on.game });
      // the window's own switches live with the window; "auto" is also the service's auto-connect
      const shell = shellPrefs();
      const flip = (key: 'auto' | 'min' | 'tray') => {
        pref.set(key, shell[key] ? '0' : '1');
        applyShell(key);
        this.setState((old: any) => ({ on: Object.assign({}, old?.on, { [key]: !shell[key] }) }));
      };
      v.tg.auto = () => { flip('auto'); this.save({ autoconnect: !shell.auto }); };
      v.tg.min = () => flip('min');
      v.tg.tray = () => flip('tray');
      for (const k of Object.keys(PR)) v.prSet[k] = () => this.save({ protocol: PR[k] });
      v.prSet.vless = () => {}; // drawn for the finished product; not in this build
      // Sections drawn for the finished product and not in this build (Privacy, Notifications, Updates, Local proxy;
      // Subscription while there is none): shown dimmed and closed, so that the design's samples are not taken for the real state.
      const u = this.sub();
      if (u) this.subVals(v, u);
      const soon = new Set([...(u ? [] : [1]), 2, 4, 5, 6]); // the design's order: conn, sub, priv, look, notif, upd, proxy, about
      v.nav = v.nav.map((n: any, i: number) => (soon.has(i) ? { ...n, c: 'soon', b: '', bc: 'hide', go: () => {} } : n));
      v.ver = version;
      v.tmSet.dark = () => setTheme('dark');
      v.tmSet.light = () => setTheme('light');
      const lang = document.documentElement.lang || 'en';
      const order = ['en', 'ru', 'zh', 'fa', 'tr']; // the design's list, in its order
      v.langs = v.langs.map((l: any, i: number) => ({
        ...l, c: order[i] === lang ? 'on' : '', a: order[i] === lang ? 'true' : 'false',
        go: () => (order[i] === lang ? this.setState({ lo: false }) : setLang(order[i])),
      }));
      return v;
    }
  } as unknown as typeof DCLogic;
}
