// Routes on the real service: the mode, the region, the collections and the user's sites are the service's.
// The design's logic stays as generated and keeps drawing its catalogue; this subclass keeps its switches in step
// with the service: what the service says is put into the design's own state, and what the user flips there is
// sent to the service. What this build does not do yet is drawn but cannot be pressed (shell.css): apps, the
// "Lists" sheet, suggestions from traffic.
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import { words } from './live-i18n';
import { liveChip } from './live-settings';

type Selection = { collections: string[]; sites: string[] };
type Routes = {
  mode: 'all' | 'smart' | 'selected'; region: string; effective: string; available: boolean; entries: number; updated_unix: number;
  rules?: { direct: Selection; vpn: Selection };
  // sites that keep failing on their route: `vpn` fail direct, `direct` fail through the VPN
  suggest?: { vpn: { site: string; count: number }[]; direct: { site: string; count: number }[] };
};

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
const KNOWN = ['ru', 'by', 'cn', 'ir']; // the regions the design draws; anything else shows as its "None"
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
const BACK = Object.fromEntries(Object.entries(COL).map(([k, v]) => [v, k]));
const MODE: Record<string, string> = { smart: 'except', selected: 'only', all: 'all' };

export function liveRoutes(Base: typeof DCLogic): typeof DCLogic {
  return class LiveRoutes extends (liveChip(Base) as any) {
    routes: Routes | null = null;
    sent = ''; // the rules as last heard from or sent to the service

    mounted() {
      this.off.push(listen<Routes>('mg://routes', (e) => this.applyRoutes(e.payload)));
      rpc<Routes>('routes.get').then((r) => this.applyRoutes(r), () => {});
      // the "add a site" row is plain markup in the design
      document.addEventListener('click', this.onClick);
      document.addEventListener('keydown', this.onKey);
    }
    componentWillUnmount() {
      super.componentWillUnmount();
      document.removeEventListener('click', this.onClick);
      document.removeEventListener('keydown', this.onKey);
    }
    // (the design has a second such row, for list links, on its Lists sheet: that one is not this build's)
    row = (t: EventTarget | null) => { const r = (t as Element | null)?.closest?.('.addrow'); return r?.closest('.lcard') && !this.state?.view?.includes('lists') ? r : null; };
    onClick = (e: MouseEvent) => { if ((e.target as Element).closest('.addb')) this.addSites(this.row(e.target)); };
    onKey = (e: KeyboardEvent) => { if (e.key === 'Enter') this.addSites(this.row(e.target)); };
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
      return {
        // in Smart the region's own addresses and the local network always go direct: their tiles show it
        sel: { except: tiles(rules.direct.collections, { rusites: r.available, lan: true }), only: tiles(rules.vpn.collections, {}) },
        sites: { except: rules.direct.sites.map((s) => [s, '']), only: rules.vpn.sites.map((s) => [s, '']) },
      };
    }
    wanted(state: any) {
      const pick = (m: string) => ALL.filter((k) => state.sel?.[m]?.[k] && COL[k]).map((k) => COL[k]).sort();
      const sites = (m: string) => ((state.sites?.[m] ?? []) as string[][]).map((x) => x[0]);
      return { direct: { collections: pick('except'), sites: sites('except') }, vpn: { collections: pick('only'), sites: sites('only') } };
    }
    applyRoutes(r: Routes) {
      this.routes = r;
      const next = this.switches(r);
      this.sent = JSON.stringify(this.wanted(next));
      this.setState({ mode: MODE[r.mode] ?? 'all', reg: KNOWN.includes(r.effective) ? r.effective : KNOWN.includes(r.region) ? r.region : 'other', regOpen: false, ...next });
    }
    componentDidUpdate() {
      super.componentDidUpdate?.();
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
      return v;
    }
  } as unknown as typeof DCLogic;
}
