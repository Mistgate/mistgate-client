// Diagnostics on the real service: "Check network" runs the service's check, and its verdicts are shown in the
// design's rows. The design's logic stays as generated. Its wording is reused: the sample results it carries (in
// the window's language) are read once, by position, and real numbers are put into them. Only what this build
// really checks is shown; the design's other rows (route hops, speed limits, Wi-Fi) come with their detectors.
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import FLAGS from './design/flags.json';
import { words } from './live-i18n';
import { liveChip, pref } from './live-settings';

type Verdict = 'ok' | 'blocked' | 'down' | 'config' | 'app' | 'slow';
type Result = {
  at_unix: number; sub: string; network: { kind: string };
  servers: { id: string; name: string; protocol: string; verdict: Verdict; reason: string; rtt_ms: number }[];
  route: { verdict: string; hop: number; total: number };
  udp: { verdict: string }; nat: { verdict: string };
  dns: { verdict: string; checked: number; replaced: number };
  foreign: { verdict: string; total: number; open: number };
  freeze?: { verdict: string; targets: { name: string; bytes: number; verdict: string }[] };
  neighbours?: { kind: string; name: string }[];
  // measured through the tunnel, only when the VPN was up during the check
  speed?: { verdict: string; down_mbps: number; up_mbps: number; first_mbps: number; last_mbps: number; server: string };
};
type State = { state: 'idle' | 'running' | 'done' | 'failed'; step: number; pct: number; error: string; result: Result | null };
type LogEntry = { t_unix_ms: number; level: string; src?: string; msg: string };

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
const nums = (text: string, ...values: number[]) => { let i = 0; return text.replace(/\d+/g, (d) => (i < values.length ? String(values[i++]) : d)); };
const firstSentence = (text: string) => text.match(/^.*?[.。](\s|$)/)?.[0].trim() ?? text;
function flagOf(name: string) {
  const m = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (!m) return { flag: '', text: name };
  const cc = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0)! - 0x1f1e6 + 97)).join('');
  return { flag: (FLAGS as Record<string, string>)[cc] ?? '', text: name.replace(m[0], '').trim() || name };
}

// The design's own sample results, rendered by its logic without mounting it: the source of every phrase below.
function samples(Base: typeof DCLogic) {
  const of = (check: string) => { const l: any = new (Base as any)({ check, mode: 'mg' }); l.state = {}; return l.renderVals(); };
  const I = of('issues'), G = of('good');
  // how a verdict looks (label, glyph, colour), as the design's rows show it
  const look: Record<string, { vt: string; vi: string; vc: string }> = {};
  for (const v of [I, G]) for (const row of [...v.srvRows, ...v.netRows]) {
    if (!row.alt) look[row.v] ??= { vt: row.vt, vi: row.vi, vc: row.vc };
    row.paths.forEach((p: any, k: number) => { look[p.v] ??= { vt: row['p' + k].vt, vi: row['p' + k].vi, vc: row['p' + k].vc }; });
  }
  return { I, G, look };
}

export function liveDiag(Base: typeof DCLogic): typeof DCLogic {
  let S: ReturnType<typeof samples> | null = null;
  return class LiveDiag extends (liveChip(Base) as any) {
    diag: State = { state: 'idle', step: 0, pct: 0, error: '', result: null };
    log: LogEntry[] = [];

    mounted() {
      S ??= samples(Base);
      this.off.push(
        listen<State>('mg://diag', (e) => this.applyDiag(e.payload)),
        listen<LogEntry>('mg://log', (e) => { this.log = [...this.log.slice(-499), e.payload]; if (!this.state?.paused) this.forceUpdate(); }),
      );
      rpc<State>('diag.get').then((s) => this.applyDiag(s), () => {});
      rpc<{ entries: LogEntry[] }>('log.get').then((r) => { this.log = r.entries; this.forceUpdate(); }, () => {});
      // a link subscription has no panel behind it: the design's "basic" variant, reports not offered
      this.setState({ md: 'basic', anonK: 'old', rep: 'closed' });
    }
    applyDiag(s: State) {
      this.diag = s;
      const r = s.result;
      const clean = !!r && this.findings(r).every((f) => f.v === 'ok');
      this.setState({ ck: s.state === 'running' ? 'run' : r ? (clean ? 'good' : 'issues') : 'idle', step: s.step });
    }

    // the result as the design's rows, before its look is applied
    findings(r: Result) {
      const { I, G } = S!;
      const w = words();
      const way = (protocol: string) => (protocol === 'awg' ? I.srvRows[1].paths[2].n : I.srvRows[0].paths[2].n); // "AmneziaWG · direct" / "Hysteria2 · direct"
      const why: Record<string, string> = {
        udp_no_answer: I.srvRows[0].paths[2].m, no_answer: I.srvRows[3].paths[0].m, not_found: I.srvRows[3].paths[0].m,
        auth_rejected: I.srvRows[4].paths[0].m, bad_config: I.srvRows[4].paths[0].m, engine_error: I.srvRows[1].paths[2].m,
      };
      // "Mbps" as the design's samples write it in this language ("31 ms · 48.2 Mbps")
      const unit = String(G.srvRows[0].paths[0].m).split(' · ')[1]?.replace(/[d.,s]+/, '') ?? 'Mbps';
      const sp = r.speed && r.speed.verdict !== 'skipped' && r.speed.verdict !== 'failed' ? r.speed : null;
      const servers = r.servers.map((n) => {
        const { flag, text } = flagOf(n.name);
        const fast = sp && (sp.server === n.id || sp.server === n.name) ? ` · ${sp.down_mbps.toFixed(1)} ${unit}` : ''; // the server the VPN is on
        const m = n.verdict === 'ok' ? `${n.rtt_ms} ms${fast}` : why[n.reason] ?? '';
        const meta = n.verdict === 'ok' ? `${way(n.protocol).split(' · ')[0]} · ${n.rtt_ms} ms${fast}` : n.verdict === 'down' ? I.srvRows[3].meta : n.verdict === 'config' ? I.srvRows[4].meta : m;
        return { kind: 'srv', flag, name: text, v: n.verdict, alt: '', meta, paths: [{ n: way(n.protocol), v: n.verdict, m }], lines: [] as string[], hops: [] as any[], g: '', tone: '', term: '', act: [] as string[], hasFlag: true };
      });
      const net: any[] = [];
      const row = (sample: any, over: object) => net.push({ kind: 'net', flag: '', paths: [], hasFlag: false, conf: '', hops: [], act: [], ...sample, ...over });
      // the design draws eleven hops: a longer path keeps its last cells for the end
      const cells = (bad: number) => Array.from({ length: 11 }, (_, i) => ({ n: String(i + 1), c: bad && i + 1 === Math.min(bad, 11) ? 'bad' : bad && i + 1 > Math.min(bad, 11) ? 'off' : 'ok' }));
      if (r.route?.verdict === 'ok') row(G.netRows[0], { lines: [nums(G.netRows[0].lines[0], r.route.total)], hops: cells(0) });
      else if (r.route?.verdict === 'blocked') row(I.netRows[0], { alt: nums(I.netRows[0].alt, r.route.hop), meta: firstSentence(I.netRows[0].meta), lines: [nums(I.netRows[0].lines[0], r.route.hop, r.route.total), I.netRows[0].lines[1]], hops: cells(r.route.hop) });
      if (r.udp.verdict === 'ok') row(G.netRows[1], { lines: [] });
      else if (r.udp.verdict === 'blocked') row(I.netRows[1], { meta: firstSentence(I.netRows[1].meta), lines: [I.netRows[1].lines[0]], conf: '' });
      if (r.nat.verdict === 'open') row(G.netRows[2], {});
      else if (r.nat.verdict === 'limited' || r.udp.verdict === 'blocked') row(I.netRows[2], { conf: '' });
      if (r.dns.verdict === 'ok') row(I.netRows[4], { lines: [nums(I.netRows[4].lines[0], r.dns.checked)] });
      else if (r.dns.verdict === 'replaced') row(I.netRows[4], { v: 'blocked', alt: '', tone: 'sand', meta: w.dnsReplaced, lines: [w.dnsReplacedLine(r.dns.replaced, r.dns.checked)] });
      if (r.foreign.verdict === 'ok') row(I.netRows[6], { lines: [nums(I.netRows[6].lines[0], r.foreign.open, r.foreign.total)] });
      else if (r.foreign.verdict === 'cut') row(I.netRows[6], { v: 'blocked', alt: '', meta: w.foreignCut, lines: [nums(I.netRows[6].lines[0], r.foreign.open, r.foreign.total)] });
      // a download that stalls: the design words it for a server ("stops after 64 KB"); here it is the network's row
      const fz = r.freeze;
      const speedLine = sp ? [`↓ ${sp.down_mbps.toFixed(1)} · ↑ ${sp.up_mbps.toFixed(1)} ${unit}`] : [];
      if (sp?.verdict === 'throttled' && fz?.verdict !== 'freeze') row(I.netRows[5], { v: 'slow', alt: '', meta: w.throttled, lines: [`${sp.first_mbps.toFixed(1)} → ${sp.last_mbps.toFixed(1)} ${unit}`, ...speedLine] });
      else if (fz?.verdict === 'ok' || sp && fz?.verdict !== 'freeze') row(I.netRows[5], { meta: sp ? G.netRows[5].meta : '', lines: speedLine });
      else if (fz?.verdict === 'freeze') {
        const kb = String(Math.max(1, Math.round(Math.max(...fz.targets.filter((t) => t.verdict === 'freeze').map((t) => t.bytes)) / 1024)));
        row(I.netRows[5], { v: 'freeze', alt: '', meta: I.srvRows[2].meta.replace('64', kb), lines: [I.srvRows[2].paths[0].m.replace('64', kb)] });
      }
      if (r.neighbours?.length) row(I.netRows[3], { name: w.neighbours[0], v: 'slow', alt: w.neighbours[1], meta: w.neighbours[2], lines: [r.neighbours.map((n) => n.name).join(' · ')], g: I.netRows[6].g, tone: 'neu' });
      return [...servers, ...net];
    }

    renderVals() {
      const v = super.renderVals();
      if (!S) return v;
      const { I, G, look } = S;
      const d = this.diag, r = d.result;
      const open = this.state?.open ?? {};
      const acted = this.state?.acted ?? {};

      v.start = () => void rpc<State>('diag.run', { sub: pref.get('sub') }).then((s) => this.applyDiag(s), () => {});
      v.cancel = () => void rpc<State>('diag.cancel').then((s) => this.applyDiag(s), () => {});
      Object.assign(v, { showHelp: false, asked: false, bestCls: 'hide' });

      // a check that could not start (no subscription, no network) says so where the results would be
      const fail = d.state === 'failed' && !r ? words().diagFail[d.error] : undefined;
      if (fail) [v.emT, v.emS] = fail;
      if (d.state === 'running') {
        v.runPct = d.pct + '%';
        v.runTime = '';
        v.steps = v.steps.map((s: any, i: number) => ({ ...s, note: i < d.step ? '' : s.note, c: i === 1 ? 'sdone' : s.c }));
      }
      if (r && d.state !== 'running') {
        const all = this.findings(r);
        const dress = (x: any, id: string) => {
          const L = look[x.v] ?? look.ok;
          const o = !!open[id];
          const hasD = !!(x.lines.length || x.paths.length || x.hops.length);
          const ps = [0, 1, 2, 3].map((k) => { const q = x.paths[k]; const lq = q && (look[q.v] ?? look.ok); return q ? { c: '', n: q.n, m: q.m, vc: lq.vc, vi: lq.vi, vt: lq.vt } : { c: 'hide', n: '', m: '', vc: '', vi: '', vt: '' }; });
          const game = x.act.length > 0; // the one action this build has: "Turn on Game mode"
          return {
            ...x, vt: x.alt || L.vt, vi: L.vi, vc: L.vc, hc: x.hops.map((h: any) => h.c), hpc: x.hops.length ? '' : 'hide', ppc: x.paths.length ? '' : 'hide',
            p0: ps[0], p1: ps[1], p2: ps[2], p3: ps[3], l0: x.lines[0] ?? '', l1: x.lines[1] ?? '', l0c: x.lines[0] ? '' : 'hide', l1c: x.lines[1] ? '' : 'hide',
            cc: 'hide', ddc: hasD ? '' : 'hide', isOpen: o && hasD, oc: (o && hasD ? 'open' : '') + (hasD ? '' : ' nod'), ox: o ? 'true' : 'false',
            fc: x.hasFlag ? 'flag' : '', ic: x.hasFlag ? '' : 'hide', gc: x.hasFlag ? 'hide' : '', termC: x.term ? '' : 'hide',
            actC: game ? '' : 'hide', actT: x.act[0] ?? '', actDone: x.act[1] ?? '', actBtnC: acted[id] ? 'hide' : '', actOkC: acted[id] ? '' : 'hide',
            actGo: () => { void rpc('settings.set', { game: true }).catch(() => {}); this.setState({ acted: { ...acted, [id]: true } }); },
            tog: () => hasD && this.setState({ open: { ...open, [id]: !o } }),
          };
        };
        const srv = all.filter((x) => x.kind === 'srv'), net = all.filter((x) => x.kind === 'net');
        v.srvRows = srv.map((x, i) => dress(x, 'srv' + i));
        v.netRows = net.map((x, i) => dress(x, 'net' + i));
        const okSrv = srv.filter((x) => x.v === 'ok').length;
        const badNet = net.filter((x) => x.v !== 'ok');
        const worst = all.find((x) => x.v !== 'ok');
        const blocking = net.some((x) => x.v === 'blocked'); // the network's, not one server's
        const games = net.find((x) => x.term === 'NAT');
        const kind = r.network.kind === 'wifi' ? G.R.facts[0][2].split(' · ')[0] : r.network.kind === 'mobile' ? I.R.facts[0][2].split(' · ')[0] : r.network.kind === 'ethernet' ? 'Ethernet' : '—';
        const srvSum = nums(I.R.srvSum, okSrv, srv.length);
        v.R = {
          ...v.R, title: worst ? `${worst.name}: ${worst.alt || (look[worst.v] ?? look.ok).vt}` : G.R.title, sub: worst ? worst.meta : G.R.sub,
          srvSum, netSum: badNet.length ? nums(I.R.netSum, badNet.length) : G.R.netSum, best: '',
        };
        v.netCls = badNet.length ? 'warn' : 'okc';
        v.facts = [
          { g: I.R.facts[0][0], k: I.R.facts[0][1], v: kind, c: '' },
          { g: I.R.facts[1][0], k: I.R.facts[1][1], v: srvSum, c: okSrv === srv.length ? 'ok' : 'warn' },
          { g: I.R.facts[2][0], k: I.R.facts[2][1], v: blocking ? I.R.facts[2][2] : G.R.facts[2][2], c: blocking ? 'bad' : 'ok' },
          ...(games ? [{ g: I.R.facts[3][0], k: I.R.facts[3][1], v: games.v === 'ok' ? G.R.facts[3][2] : I.R.facts[3][2], c: games.v === 'ok' ? 'ok' : 'warn' }] : []),
        ];
        v.ovTxt = words().time(r.at_unix);
      }

      // ---- the Log tab: the service's own log
      const lf: string = this.state?.lf || 'all';
      const LV: Record<string, string> = { info: 'INFO', warn: 'WARN', error: 'ERR' };
      const clock = (ms: number) => new Date(ms).toTimeString().slice(0, 8);
      v.logRows = this.log
        .filter((e) => lf === 'all' || (lf === 'warn' ? e.level !== 'info' && e.level !== 'debug' : e.level === 'error'))
        .slice(-200).reverse()
        .map((e) => ({ t: clock(e.t_unix_ms), lv: LV[e.level] ? e.level : 'info', lvT: LV[e.level] ?? 'INFO', src: e.src ?? 'service', msg: e.msg }));
      v.logN = v.logRows.length;
      return v;
    }
  } as unknown as typeof DCLogic;
}
