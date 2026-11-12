// Routes on the real service: the mode, the region, the collections and the user's sites are the service's.
// The design's logic stays as generated and keeps drawing its catalogue; this subclass keeps its switches in step
// with the service: what the service says is put into the design's own state, and what the user flips there is
// sent to the service. What this build does not do yet is drawn but cannot be pressed (shell.css): the lists'
// "update automatically" switch (the service refreshes a list older than a day by itself).
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import BRANDS from '../tools/brands.json';
import './brands.css';
import type { DCLogic } from './dc';
import { flagOf, PROTO } from './live';
import { words } from './live-i18n';
import { liveChip } from './live-settings';

type Selection = { collections: string[]; sites: string[]; apps?: string[] }; // apps: full paths of programs
// a program the service has seen running, or one the rules name
type App = { path: string; name: string; running: boolean };
type Routes = {
  mode: 'all' | 'smart' | 'selected'; region: string; effective: string; available: boolean; entries: number; updated_unix: number;
  rules?: { direct: Selection; vpn: Selection; block?: Selection };
  // sites that keep failing on their route: `vpn` fail direct, `direct` fail through the VPN
  suggest?: { vpn: { site: string; count: number }[]; direct: { site: string; count: number }[] };
};

// what `routes.check` says of a name, and the lists behind the rules as `routes.lists` reports them
type Verdict = { route: 'direct' | 'vpn' | 'block'; by: string; rule: string };
type ListInfo = { id: string; entries: number; updated_unix: number; error: string };
type Lists = { lists: ListInfo[]; unique: number; duplicates: number };

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
const KNOWN = ['ru', 'by', 'cn', 'ir', 'tr']; // the regions the design draws; anything else shows as its "None"
const geosite = (name: string) => 'geosite:' + name;

// The design's tiles and the public site lists behind them (MetaCubeX meta-rules-dat geosite, and two lists the
// awg-manager project uses for Russia). A tile without a list here cannot be switched on yet.
const COL: Record<string, string> = {
  rkn: 'list:https://raw.githubusercontent.com/itdoginfo/allow-domains/master/Russia/inside-raw.lst',
  geo: 'list:https://repo.hoaxisr.ru/rulesets/raw/unavailable-in-russia.txt',
  rusvc: geosite('category-ru'),
  yt: geosite('youtube'), ig: geosite('instagram'), fb: geosite('facebook'), wa: geosite('whatsapp'), tg: geosite('telegram'),
  dc: geosite('discord'), x: geosite('twitter'), tt: geosite('tiktok'), th: geosite('threads'), rd: geosite('reddit'),
  sg: geosite('signal'), pin: geosite('pinterest'), bsky: geosite('bluesky'), md: geosite('medium'), pat: geosite('patreon'),
  allmedia: geosite('category-entertainment'), nf: geosite('netflix'), sp: geosite('spotify'), tw: geosite('twitch'),
  dis: geosite('disney'), hbo: geosite('hbo'), pv: geosite('primevideo'), sc: geosite('soundcloud'), dz: geosite('deezer'),
  td: geosite('tidal'), vm: geosite('vimeo'), wiki: geosite('wikimedia'), hulu: geosite('hulu'), bbc: geosite('bbc'),
  tor: geosite('category-public-tracker'),
  allai: geosite('category-ai-!cn'), oai: geosite('openai'), cl: geosite('anthropic'), gem: geosite('google-gemini'),
  grok: geosite('xai'), ppx: geosite('perplexity'),
  allgames: geosite('category-games'), steam: geosite('steam'), epic: geosite('epicgames'), ps: geosite('playstation'),
  xb: geosite('xbox'), nin: geosite('nintendo'), bz: geosite('blizzard'), ea: geosite('ea'), ubi: geosite('ubisoft'),
  rbx: geosite('roblox'), quest: geosite('oculus'),
  ms: geosite('microsoft'), apple: geosite('apple'), zoom: geosite('zoom'), gplay: geosite('google-play'),
};
// every tile the design has (so a switch the design turns on by default is turned off unless the service has it)
const ALL = ['rkn', 'geo', 'allblk', 'rusvc', 'rusites', 'lan', 'ads', 'yt', 'ig', 'fb', 'wa', 'tg', 'dc', 'x', 'tt', 'th', 'rd', 'sg', 'pin',
  'allmedia', 'nf', 'sp', 'tw', 'dis', 'hbo', 'pv', 'sc', 'dz', 'td', 'vm', 'wiki', 'allai', 'oai', 'cl', 'gem', 'grok', 'ppx', 'cop', 'allgames',
  'steam', 'epic', 'ps', 'xb', 'nin', 'bz', 'ea', 'ubi', 'rbx', 'quest', 'bng', 'ms', 'apple', 'zoom', 'gplay', 'bsky', 'md', 'pat', 'hulu', 'bbc', 'tor'];
// the "Ads" tile is not a route: its names are refused (the service answers "no such site")
const ADS = geosite('category-ads-all');
const BACK = Object.fromEntries(Object.entries(COL).map(([k, v]) => [v, k]));
// Public lists worth offering where they apply, shown on the Lists sheet, off: in "Only selected" what a region
// blocks (that is what goes through the VPN there), in Smart the region's own services (they go direct).
// ponytail: Russia only, the lists the tiles already use.
const OFFER: Record<string, Record<string, string[]>> = { only: { ru: [COL.rkn, COL.geo] }, except: { ru: [COL.rusvc] } };
const TONES = ['lav', 'sky', 'mint', 'sand', 'rose'];
// a list as its row names it: the public collection's id, or the host and path of a link
const listName = (id: string) => id.replace(/^geosite:/, '').replace(/^list:https:\/\/(www\.)?/, '').replace(/^raw\.githubusercontent\.com\//, '');
// the links the user added and switched off: the window keeps them so their row stays (the service knows only lists in use)
const OFF_KEY = 'mg.lists.off';
const offLinks = (): string[] => { try { return JSON.parse(localStorage.getItem(OFF_KEY) ?? '[]'); } catch { return []; } };
const keepOff = (ids: string[]) => { try { localStorage.setItem(OFF_KEY, JSON.stringify(ids)); } catch { /* the row is lost with the window */ } };
const MODE: Record<string, string> = { smart: 'except', selected: 'only', all: 'all' };

export function liveRoutes(Base: typeof DCLogic): typeof DCLogic {
  return class LiveRoutes extends (liveChip(Base) as any) {
    routes: Routes | null = null;
    sent = ''; // the rules as last heard from or sent to the service
    lists: Lists | null = null;
    offIds: string[] = offLinks(); // lists switched off on the Lists sheet, kept as rows
    seen = new Map<string, ListInfo>(); // the last known numbers of a list, for a row that is switched off
    apps: App[] = [];
    verdict: Verdict | null = null;
    asked = ''; // the name the verdict is for
    timer = 0;
    wait = 0; // the update's own timers

    mounted() {
      this.off.push(listen<Routes>('mg://routes', (e) => { this.applyRoutes(e.payload); if (this.state?.upd === 'busy') this.updated('done'); }));
      // the kill switch tile says the design's "on": only true when the setting is not off
      const ks = (s: { kill_switch: string }) => this.setState({ ksOff: s.kill_switch === 'off' });
      this.off.push(listen<{ kill_switch: string }>('mg://settings', (e) => ks(e.payload)));
      rpc<{ kill_switch: string }>('settings.get').then(ks, () => {});
      rpc<Routes>('routes.get').then((r) => this.applyRoutes(r), () => {});
      this.loadLists(); // the Lists button counts them
      void this.loadApps();
      // the "add a site" row is plain markup in the design
      document.addEventListener('click', this.onClick);
      document.addEventListener('keydown', this.onKey);
      document.addEventListener('input', this.onInput);
    }
    // "Check where a site goes": the service answers by the same code as a real flow
    onInput = (e: Event) => {
      const find = (e.target as Element | null)?.closest?.('.lc-s input') as HTMLInputElement | null;
      if (find && this.state?.view === 'apps') return this.setState({ appQ: find.value.trim().toLowerCase() });
      const input = (e.target as Element | null)?.closest?.('.chk-in input') as HTMLInputElement | null;
      if (!input) return;
      window.clearTimeout(this.timer);
      this.timer = window.setTimeout(() => this.check(input.value.trim()), 250);
    };
    check(site: string) {
      this.asked = site;
      const done = (x: Verdict | null) => { if (this.asked === site) { this.verdict = x; this.forceUpdate(); } };
      if (!site) return done(null);
      rpc<Verdict>('routes.check', { site }).then(done, () => done(null));
    }
    loadApps = () => rpc<{ apps: App[] }>('apps.list').then((x) => { this.apps = x.apps; this.forceUpdate(); }, () => {});
    // a program goes on or off for the mode on screen
    flipApp(path: string, on: boolean) {
      const m = this.state?.mode === 'only' ? 'only' : 'except';
      const cur: string[] = this.state?.xapps?.[m] ?? [];
      this.setState({ xapps: { ...this.state?.xapps, [m]: on ? [...new Set([...cur, path])] : cur.filter((x) => x !== path) } });
    }
    // "Add .exe": Windows' own file dialog; the program is switched on and stays in the list
    pickApp() {
      void invoke<string>('pick_exe').then((path) => {
        if (!path) return;
        this.flipApp(path.toLowerCase(), true);
        window.setTimeout(this.loadApps, 600); // once the rules are saved, the service lists it
      }, () => {});
    }
    loadLists() {
      rpc<Lists>('routes.lists').then((x) => { this.lists = x; x.lists.forEach((l) => this.seen.set(l.id, l)); this.forceUpdate(); }, () => {});
    }
    updateNow() {
      if (this.state?.upd === 'busy') return;
      this.setState({ upd: 'busy' });
      // the service answers at once and says `routes` when the downloads are over (at most a minute)
      rpc<Routes>('routes.update').then(() => { this.wait = window.setTimeout(() => this.updated('idle'), 70_000); }, () => this.updated('idle'));
    }
    updated(upd: string) {
      window.clearTimeout(this.wait);
      this.setState({ upd });
      this.loadLists();
      if (upd === 'done') this.wait = window.setTimeout(() => this.state?.upd === 'done' && this.setState({ upd: 'idle' }), 4000);
    }
    // a list of the Lists sheet goes on or off: a tile's list through its tile, any other through `extra`
    flipList(id: string, on: boolean) {
      const m = this.state?.mode === 'only' ? 'only' : 'except';
      this.offIds = on ? this.offIds.filter((x) => x !== id) : [...new Set([...this.offIds, id])];
      keepOff(this.offIds.filter((x) => !BACK[x]));
      if (BACK[id]) this.setState({ sel: { ...this.state.sel, [m]: { ...this.state.sel?.[m], [BACK[id]]: on } } });
      else {
        const cur: string[] = this.state?.extra?.[m] ?? [];
        this.setState({ extra: { ...this.state?.extra, [m]: on ? [...new Set([...cur, id])] : cur.filter((x) => x !== id) } });
      }
    }
    addList() {
      const input = document.querySelector<HTMLInputElement>('.lcard .addrow .add-in input');
      const link = (input?.value ?? '').trim();
      if (!input || !/^https:\/\/[^\s/]+\/\S+$/.test(link) || link.length > 512) return;
      input.value = '';
      this.flipList('list:' + link, true);
    }
    componentWillUnmount() {
      document.removeEventListener('input', this.onInput);
      window.clearTimeout(this.timer);
      window.clearTimeout(this.wait);
      super.componentWillUnmount();
      document.removeEventListener('click', this.onClick);
      document.removeEventListener('keydown', this.onKey);
    }
    // (the design has a second such row, for list links, on its Lists sheet: that one is not this build's)
    row = (t: EventTarget | null) => { const r = (t as Element | null)?.closest?.('.addrow'); return r?.closest('.lcard') && !this.state?.view?.includes('lists') ? r : null; };
    onClick = (e: MouseEvent) => {
      const t = e.target as Element;
      // the Apps tab's plain buttons: add a program file, look again
      if (this.state?.view === 'apps') {
        if (t.closest('.lc-row .lsb, .e-act .addb')) return this.pickApp();
        if (t.closest('.found .lnk, .e-act .lsb')) return void this.loadApps();
      }
      if (t.closest('.addb')) this.addSites(this.row(e.target));
    };
    onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Enter') return;
      if (this.state?.view === 'lists' && (e.target as Element | null)?.closest?.('.add-in')) this.addList();
      else this.addSites(this.row(e.target));
    };
    addSites(row: Element | null) {
      const input = row?.querySelector('input') as HTMLInputElement | null;
      const names = (input?.value ?? '').split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
      if (!names.length) return;
      input!.value = '';
      this.addNames(names);
    }
    addNames(names: string[]) {
      const m = this.state?.mode === 'only' ? 'only' : 'except';
      const cur: string[][] = this.state?.sites?.[m] ?? [];
      const have = new Set(cur.map((x) => x[0]));
      this.setState({ sites: { ...this.state?.sites, [m]: cur.concat(names.filter((n) => !have.has(n)).map((n) => [n, ''])) } });
    }

    // The service's rules as the design's switches: every tile explicitly on or off.
    switches(r: Routes) {
      const tiles = (chosen: string[], extra: Record<string, boolean>) =>
        Object.assign(Object.fromEntries(ALL.map((k) => [k, false])), Object.fromEntries(chosen.map((c) => [BACK[c], true]).filter(([k]) => k)), extra);
      const rules = r.rules ?? { direct: { collections: [], sites: [] }, vpn: { collections: [], sites: [] } };
      const ads = !!rules.block?.collections.includes(ADS);
      return {
        // in Smart the region's own addresses and the local network always go direct: their tiles show it
        sel: { except: tiles(rules.direct.collections, { rusites: r.available, lan: true, ads }), only: tiles(rules.vpn.collections, { ads }) },
        sites: { except: rules.direct.sites.map((s) => [s, '']), only: rules.vpn.sites.map((s) => [s, '']) },
        // lists in the rules that no tile stands for: the links added on the Lists sheet
        extra: { except: rules.direct.collections.filter((c) => !BACK[c]), only: rules.vpn.collections.filter((c) => !BACK[c]) },
        xapps: { except: rules.direct.apps ?? [], only: rules.vpn.apps ?? [] },
      };
    }
    wanted(state: any) {
      const pick = (m: string) => [...ALL.filter((k) => state.sel?.[m]?.[k] && COL[k]).map((k) => COL[k]), ...((state.extra?.[m] ?? []) as string[])].sort();
      const sites = (m: string) => ((state.sites?.[m] ?? []) as string[][]).map((x) => x[0]);
      const apps = (m: string) => [...((state.xapps?.[m] ?? []) as string[])].sort();
      const m = state.mode === 'only' ? 'only' : 'except'; // the Ads tile of the mode on screen is the one the user flips
      const others = (this.routes?.rules?.block?.collections ?? []).filter((c) => c !== ADS);
      return {
        direct: { collections: pick('except'), sites: sites('except'), apps: apps('except') }, vpn: { collections: pick('only'), sites: sites('only'), apps: apps('only') },
        block: { collections: [...others, ...(state.sel?.[m]?.ads ? [ADS] : [])].sort(), sites: this.routes?.rules?.block?.sites ?? [] },
      };
    }
    applyRoutes(r: Routes) {
      this.routes = r;
      const next = this.switches(r);
      this.sent = JSON.stringify(this.wanted(next));
      if (this.state?.view === 'lists') this.loadLists();
      if (this.asked) this.check(this.asked); // the rules changed under the name on the test line
      this.setState({ mode: MODE[r.mode] ?? 'all', reg: KNOWN.includes(r.effective) ? r.effective : KNOWN.includes(r.region) ? r.region : 'other', regOpen: false, ...next });
    }
    // The server on the scheme: the design draws its sample's flag; show the flag of the server in use, or the
    // design's own server glyph when its name carries none. Off, the design draws the glyph by itself.
    paintServer() {
      const node = document.querySelector<HTMLElement>('.sch .nd.srv');
      const img = node?.querySelector('img'), glyph = node?.querySelector<HTMLElement>('.gl');
      if (!img || !glyph) return;
      const flag = this.server ? flagOf(this.server).flag : '';
      if (flag && img.getAttribute('src') !== flag) img.setAttribute('src', flag);
      img.style.display = this.server && !flag ? 'none' : '';
      glyph.style.display = this.server && !flag ? 'block' : '';
    }
    componentDidUpdate() {
      super.componentDidUpdate?.();
      this.paintServer();
      const r = this.routes;
      if (!r || !this.state?.sel) return;
      const want = this.wanted(this.state);
      const key = JSON.stringify(want);
      if (key !== this.sent) {
        // the user flipped a tile or changed the sites
        this.sent = key;
        void rpc<Routes>('routes.set', want).then((x) => this.applyRoutes(x), () => rpc<Routes>('routes.get').then((x) => this.applyRoutes(x), () => {}));
        return;
      }
      // a tile without a list behind it, or one of the two that follow the mode, was flipped: put it back
      const fixed = this.switches({ ...r, rules: want });
      if (JSON.stringify(fixed.sel) !== JSON.stringify(this.state.sel)) this.setState({ sel: fixed.sel });
    }
    save(patch: object) {
      void rpc('settings.set', patch).then(() => rpc<Routes>('routes.get')).then((r) => this.applyRoutes(r), () => {});
    }

    renderVals() {
      const v = super.renderVals();
      const r = this.routes;
      if (this.state?.ksOff) Object.assign(v, { ksSub: words().off, ksTone: 'neu' });
      // the server in use instead of the design's sample (off, the design words it itself)
      if (this.server) Object.assign(v, { srvName: flagOf(this.server).text, srvSub: PROTO[this.proto]?.[2] ?? '' });
      v.setExc = () => this.save({ route_mode: 'smart' });
      v.setOnly = () => this.save({ route_mode: 'selected' });
      v.setAll = () => this.save({ route_mode: 'all' });
      v.regs = v.regs.map((x: any, i: number) => {
        const cc = [...KNOWN, 'none'][i];
        const detected = r?.region === 'auto' && r.effective === cc;
        return { ...x, det: detected, detCls: detected ? '' : 'hide', pick: () => this.save({ route_region: cc }) };
      });
      const auto = r?.region === 'auto';
      Object.assign(v, { regAuto: auto, regAutoCls: auto ? '' : 'hide' });
      // "Local lists updated today, 09:12": the design's line with the real time, shown only when it is true
      const today = !!r && r.available && new Date(r.updated_unix * 1000).toDateString() === new Date().toDateString();
      v.regUpCls = today ? '' : 'hide';
      if (today) v.regUp = String(v.regUp).replace(/\d{1,2}:\d{2}/, words().time(r!.updated_unix));
      v.sites = v.sites.map((s: any) => ({ ...s, meta: String(s.meta).replace(/^\s*·\s*/, '') }));
      // "Suggested from your traffic": the service's list for this mode, in the design's words (its first sample's line)
      const m = this.state?.mode === 'only' ? 'only' : 'except';
      const line = String(v.sugs?.[0]?.meta ?? '');
      const listed = new Set(((this.state?.sites?.[m] ?? []) as string[][]).map((x) => x[0]));
      v.sugs = (this.state?.mode === 'all' ? [] : (m === 'only' ? r?.suggest?.vpn : r?.suggest?.direct) ?? [])
        .filter((x) => !listed.has(x.site))
        .map((x) => ({ name: x.site, meta: line.replace(/\d+/, String(x.count)), add: () => this.addNames([x.site]) }));
      // the Apps tab: the programs the service sees (running ones first), switched for the mode on screen. The design's
      // sample tiles lend their words: "Running" / "Installed" and the way a chosen one goes.
      const sample: any[] = v.apps ?? [];
      const onTile = sample.find((a) => a.way) ?? {}, runTile = sample.find((a) => a.mcls === 'run') ?? {}, idleTile = sample.find((a) => a.mcls !== 'run') ?? {};
      const chosen = new Set<string>((this.state?.xapps?.[m] ?? []) as string[]);
      const q: string = this.state?.appQ ?? '';
      v.apps = this.apps.filter((a) => !q || a.name.toLowerCase().includes(q) || a.path.includes(q)).map((a, i) => {
        const on = chosen.has(a.path);
        return {
          name: a.name, g: 'app-window', tone: TONES[i % TONES.length], meta: a.running ? runTile.meta ?? '' : idleTile.meta ?? '', mcls: a.running ? 'run' : '',
          way: on ? onTile.way ?? '' : '', wayC: on ? onTile.wayC ?? '' : 'hide', cls: on ? onTile.cls ?? 'on' : '', on: on ? 'true' : 'false',
          flip: () => this.flipApp(a.path, !on),
        };
      });
      Object.assign(v, { appCnt: chosen.size, appTotal: this.apps.length, hasApps: this.apps.length > 0, noApps: this.apps.length === 0 });
      const openApps = v.vPick.apps;
      v.vPick = { ...v.vPick, apps: () => { openApps(); void this.loadApps(); } };

      // a service's own logo instead of the design's symbol, where an open one exists
      const brands = BRANDS as Record<string, string>;
      v.tiles = v.tiles.map((t: any) => (brands[t.name] ? { ...t, g: 'b-' + brands[t.name] } : t));

      // the test line: what the service would do with the typed name (the design cycles three samples)
      const w = words(), x = this.verdict;
      const [cVPN, cDir, cBlock, cAll, cOn, cNotSel, cDirect, cNotExc] = w.chk;
      const named = (rule: string) => (x!.by === 'region' ? (r?.effective ?? '').toUpperCase() : listName(rule));
      v.chk = this.asked;
      v.nextChk = () => {};
      v.res = !x ? { cls: 'hide', short: '', why: '' }
        : x.route === 'block' ? { cls: 'dir', short: cBlock, why: cOn.replace('%s', named(x.rule)) }
        : x.by === 'mode' ? { cls: 'vpn', short: cVPN, why: cAll }
        : x.by === 'default' ? (x.route === 'vpn' ? { cls: 'vpn', short: cVPN, why: cNotExc } : { cls: 'dir', short: cDir, why: cNotSel })
        : x.route === 'vpn' ? { cls: 'vpn', short: cVPN, why: cOn.replace('%s', named(x.rule)) }
        : { cls: 'dir', short: cDir, why: cDirect.replace('%s', named(x.rule)) };

      // the Lists sheet: the lists behind the rules of the mode on screen, with the service's numbers
      v.updateNow = () => this.updateNow();
      v.openLists = () => { this.setState({ view: 'lists', back: this.state?.view }); this.loadLists(); };
      v.addList = () => this.addList();
      const inUse = new Set<string>([...(m === 'only' ? r?.rules?.vpn.collections : r?.rules?.direct.collections) ?? [], ...(m === 'except' && r?.available ? ['region:' + r.effective] : [])]);
      const offered = OFFER[m][r?.effective ?? ''] ?? [];
      const ids = [...new Set([...(this.lists?.lists ?? []).map((l) => l.id).filter((id) => inUse.has(id)), ...offered, ...this.offIds])];
      const num = (n: number) => n.toLocaleString(w.locale);
      v.mSegs = [];
      v.srcRows = ids.map((id, i) => {
        const l = this.seen.get(id), on = inUse.has(id), own = id.startsWith('list:') && !BACK[id], fixed = id.startsWith('region:');
        const tone = TONES[i % TONES.length];
        if (on && l && !l.error) v.mSegs.push({ c: tone, w: Math.max(l.entries, 1) });
        const name = fixed ? w.lists.region(id.slice(7).toUpperCase()) : listName(id);
        const meta = !l ? (on ? w.lists.checking : '') : l.error && !l.entries ? w.lists.failed
          : [w.lists.entries(num(l.entries)), l.error ? w.lists.failed : l.updated_unix ? w.lists.updated(w.time(l.updated_unix)) : ''].filter(Boolean).join(' · ');
        return {
          name, g: fixed ? 'shield-check' : own ? 'link' : 'code-brackets', tone, meta, builtin: !own, biCls: own ? 'hide' : '', custom: own,
          err: !!l?.error, mcls: l?.error ? 'err' : '', cls: (on ? 'on' : 'off') + (l?.error ? ' bad' : ''), sw: on ? 'on' : '', on: on ? 'true' : 'false',
          // the region's own list follows the mode and the region, not a switch
          flip: () => { if (!fixed) this.flipList(id, !on); },
          rm: () => { if (on) this.flipList(id, false); this.offIds = this.offIds.filter((y) => y !== id); keepOff(this.offIds.filter((y) => !BACK[y])); this.forceUpdate(); },
          retry: () => this.updateNow(),
        };
      });
      v.mN = v.srcRows.filter((o: any) => o.on === 'true').length;
      // the region's addresses are a list of their own kind: counted on top of the site lists' unique names
      const region = (this.lists?.lists ?? []).find((l) => l.id.startsWith('region:') && inUse.has(l.id));
      v.mUnique = num((this.lists?.unique ?? 0) + (region?.entries ?? 0));
      v.mDup = num(this.lists?.duplicates ?? 0);
      Object.assign(v, { autoCls: 'on', autoOn: 'true', toggleAuto: () => {} });
      return v;
    }
  } as unknown as typeof DCLogic;
}
