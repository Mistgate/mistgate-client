// Diagnostics on the real service: "Check network" runs the service's check, and its verdicts are shown in the
// design's rows. The design's logic stays as generated. Its wording is reused: the sample results it carries (in
// the window's language) are read once, by position, and real numbers are put into them. Only what this build
// really checks is shown; the design's other rows (route hops, speed limits, Wi-Fi) come with their detectors.
import { clock as hhmm, named as withName, reportOff, reportState, type ReportSub } from './report';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import { FLAG } from './flags';
import { nodesOf, PROTO, sufOf, VIA, type Server } from './live';
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
// what a Mistgate panel says about diagnostics: it takes them, the person may send unasked, support asked for them
type Ask = { id: string; level: string; note?: string; expires_unix: number };
type DSub = ReportSub & { host: string; servers: Server[]; debug?: { intake: boolean; unasked?: boolean; request?: Ask } };
type Line = { ts: number; lvl: string; src: string; msg: string; kv?: Record<string, string> };
// the lines the service made and keeps: exactly these are sent
type Snap = { key: string; at: number; id: string; bytes: number; count: number; lines: Line[] };
// the design's six parts by position; this build has data for three of them
// ponytail: Timeline, Paths and Network come with the data for them
const PART: Record<number, string> = { 0: 'system', 3: 'checks', 5: 'log' };

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
const nums = (text: string, ...values: number[]) => { let i = 0; return text.replace(/\d+/g, (d) => (i < values.length ? String(values[i++]) : d)); };
const firstSentence = (text: string) => text.match(/^.*?[.。](\s|$)/)?.[0].trim() ?? text;
function flagOf(name: string) {
  const m = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (!m) return { flag: '', text: name };
  const cc = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0)! - 0x1f1e6 + 97)).join('');
  return { flag: FLAG[cc] ?? '', text: name.replace(m[0], '').trim() || name };
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

const toPrivacy = (e: MouseEvent) => { if ((e.target as Element | null)?.closest?.('.anon-l')) try { sessionStorage.setItem('mg.sec', 'priv'); } catch { /* opens on its first section */ } };

export function liveDiag(Base: typeof DCLogic): typeof DCLogic {
  let S: ReturnType<typeof samples> | null = null;
  return class LiveDiag extends (liveChip(Base) as any) {
    diag: State = { state: 'idle', step: 0, pct: 0, error: '', result: null };
    log: LogEntry[] = [];
    logFrame = 0;
    bySub = new Map<string, Server[]>();
    servers: Server[] = []; // the subscriptions' servers, to name a result row as Home names the server
    subs: DSub[] = [];
    snap: Snap | null = null;
    answered = new Set<string>(); // requests answered in this visit: the panel says so only at its next sync
    busy = false;
    sentId = '';

    mounted() {
      S ??= samples(Base);
      this.off.push(
        listen<State>('mg://diag', (e) => this.applyDiag(e.payload)),
        // a burst of lines draws once a frame, not once a line
        listen<LogEntry>('mg://log', (e) => {
          this.log = [...this.log.slice(-499), e.payload];
          if (this.state?.paused || this.logFrame || (this.state?.tab || this.props?.tab) !== 'log') return; // only the Log tab shows them
          this.logFrame = requestAnimationFrame(() => { this.logFrame = 0; this.forceUpdate(); });
        }),
      );
      rpc<State>('diag.get').then((s) => this.applyDiag(s), () => {});
      const subs = (list: DSub[]) => {
        this.subs = list; this.bySub = new Map(list.map((u) => [u.id, u.servers])); this.servers = list.flatMap((u) => u.servers);
        // only a panel that takes diagnostics gets the design's full variant; a link subscription has nobody to send to
        // block reports: the design's states of the switch, from the subscription's own
        const rs = reportState(this.cur());
        this.setState({ md: this.cur()?.debug?.intake ? 'mg' : 'basic', anonK: !rs.can ? 'old' : !rs.on ? 'off' : rs.at ? 'on' : 'fresh' });
      };
      this.off.push(listen<{ subs: DSub[] }>('mg://subs', (e) => subs(e.payload.subs)));
      rpc<{ subs: DSub[] }>('subs.list').then((r) => subs(r.subs), () => {});
      document.addEventListener('click', this.onShow);
      // "What's sent" leads to Settings: say which section it means (the design's link names the screen only)
      document.addEventListener('click', toPrivacy, true);
      rpc<{ entries: LogEntry[] }>('log.get').then((r) => { this.log = r.entries; this.forceUpdate(); }, () => {});
      // until the subscriptions are read: the design's "basic" variant, block reports not offered
      this.setState({ md: 'basic', anonK: 'old', rep: 'closed' });
    }
    // "Checked 2 min ago" is plain markup in the design: say when this result was made
    componentDidUpdate() {
      super.componentDidUpdate?.();
      const at = this.diag.result?.at_unix;
      const line = document.querySelector('.ck-meta > span');
      const text = line && [...line.childNodes].find((n) => n.nodeType === Node.TEXT_NODE);
      if (text && at && text.nodeValue !== words().time(at)) text.nodeValue = words().time(at);
      this.paintHelp();
    }
    componentWillUnmount() {
      document.removeEventListener('click', this.onShow);
      super.componentWillUnmount();
    }

    // ---- "Ask your admin for help": the service makes the lines, the person can read them, then they are sent
    cur() { return this.subs.find((u) => u.id === pref.get('sub')) ?? this.subs[0]; }
    // support's open request for this PC, if any
    ask() { const q = this.cur()?.debug?.request; return q && !this.answered.has(q.id) && q.expires_unix * 1000 > Date.now() ? q : undefined; }
    want() {
      const poff = this.state?.poff ?? {};
      const note = (document.querySelector<HTMLTextAreaElement>('.sheet .ta textarea')?.value ?? '').trim().slice(0, 1000);
      const q = this.ask();
      return { sub: this.cur()?.id ?? '', parts: Object.keys(PART).filter((i) => !poff[i]).map((i) => PART[Number(i)]), note, ...(q ? { request: q.id } : {}) };
    }
    // the lines for what is ticked now; made again only when the choice or the note changed (the service keeps them 10 min)
    async take() {
      const want = this.want(), key = JSON.stringify(want);
      if (this.snap?.key === key && Date.now() - this.snap.at < 9 * 60_000) return this.snap;
      this.snap = null; // a preview that fails must not leave the old lines on the screen
      const r = await rpc<Omit<Snap, 'key' | 'at'>>('debug.preview', want);
      return (this.snap = { ...r, key, at: Date.now() });
    }
    resize = () => void this.take().then(() => this.forceUpdate(), () => this.forceUpdate());
    // the lines the person has on the screen right now, if they are still what is ticked
    seen() { return this.state?.showC && this.snap?.key === JSON.stringify(this.want()) && Date.now() - this.snap.at < 9 * 60_000 ? this.snap : null; }
    async send() {
      if (this.busy) return;
      this.busy = true;
      this.setState({ dbgErr: '' });
      const w = words().dbg;
      try {
        // Only what was shown goes out. Anything else (never opened, the note changed since) is shown first, and the
        // next press sends it.
        const snap = this.seen();
        if (!snap) {
          await this.take();
          this.setState({ showC: true, dbgErr: w.look });
          return;
        }
        const r = await rpc<{ ok: boolean; id?: string; code?: string; retry_s?: number }>('debug.send', { id: snap.id });
        if (r.ok) {
          const q = this.ask();
          if (q) this.answered.add(q.id);
          this.sentId = r.id ?? '';
          this.snap = null;
          this.setState({ rep: 'sent', copied: false, showC: false });
        } else {
          if (r.code === 'expired') this.snap = null;
          const why = r.retry_s ? w.wait(Math.max(1, Math.ceil(r.retry_s / 60))) : r.code === 'offline' ? w.offline : r.code === 'no_request' ? w.gone : r.code === 'debug_full' ? w.full
            : (r.code !== 'expired' && words().subErr[r.code ?? '']) || w.fail; // a lasting reason (device removed, app off) in its own words
          if (r.code === 'no_request') { const q = this.ask(); if (q) this.answered.add(q.id); }
          this.setState({ dbgErr: why });
        }
      } catch {
        this.setState({ dbgErr: w.fail });
      } finally {
        this.busy = false;
      }
    }
    // "Show contents" is plain markup in the design
    onShow = (e: MouseEvent) => {
      if (!(e.target as Element | null)?.closest?.('.sheet .lnk2')) return;
      this.setState({ showC: !this.state?.showC });
      this.resize();
    };
    // What the design draws as samples or not at all: the request's note, the lines to be sent, why a send failed, the
    // code of what was sent.
    paintHelp() {
      const set = (node: Element | null | undefined, text: string) => { if (node && text && node.textContent !== text) node.textContent = text; };
      set(document.querySelector('.ask .tx span'), this.ask()?.note ?? '');
      const sheet = document.querySelector('.sheet');
      if (!sheet) return;
      const code = sheet.querySelector('.sent .code > span');
      code?.classList.add('mo'); // "mo" keeps the Persian digit pass off: the code is read out as it is written
      set(code, this.sentId);
      const warn = sheet.querySelector('.sh-warn');
      const text = warn && [...warn.childNodes].reverse().find((n) => n.nodeType === Node.TEXT_NODE);
      if (text && this.state?.dbgErr && text.nodeValue !== this.state.dbgErr) text.nodeValue = this.state.dbgErr;
      let box = sheet.querySelector<HTMLElement>('.mg-lines');
      const snap = this.state?.showC && this.state?.rep === 'open' ? this.snap : null;
      if (!snap) { box?.remove(); return; }
      if (!box) {
        box = document.createElement('pre');
        box.className = 'mg-lines mo'; // shown as sent: Latin digits, left to right
        box.dir = 'ltr';
        box.tabIndex = 0;
        sheet.querySelector('.sh-f')?.after(box);
      }
      const clock = (ms: number) => new Date(ms).toTimeString().slice(0, 8);
      const lines = snap.lines.map((l) => `${clock(l.ts)} ${l.lvl} ${l.src} ${l.msg}${l.kv ? ' ' + Object.entries(l.kv).map(([k, x]) => `${k}=${x}`).join(' ') : ''}`).join('\n');
      if (box.textContent !== lines) box.textContent = lines;
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
      const way = (protocol: string) => (protocol === 'awg' ? I.srvRows[1].paths[2].n : protocol === 'vless' ? I.srvRows[0].paths[0].n : I.srvRows[0].paths[2].n); // "AmneziaWG · direct" / "VLESS · TCP · direct" / "Hysteria2 · direct"
      const why: Record<string, string> = {
        udp_no_answer: I.srvRows[0].paths[2].m, no_answer: I.srvRows[3].paths[0].m, not_found: I.srvRows[3].paths[0].m,
        auth_rejected: I.srvRows[4].paths[0].m, bad_config: I.srvRows[4].paths[0].m, engine_error: I.srvRows[1].paths[2].m,
      };
      // "Mbps" as the design's samples write it in this language ("31 ms · 48.2 Mbps")
      const unit = String(G.srvRows[0].paths[0].m).split(' · ')[1]?.replace(/[\d.,\s]+/, '') ?? 'Mbps';
      const sp = r.speed && r.speed.verdict !== 'skipped' && r.speed.verdict !== 'failed' ? r.speed : null;
      // a result row is named as Home names the server: the country with its number, then what the path adds
      const named = new Map<string, { flag: string; text: string }>();
      // numbered as Home numbers them: within the subscription that was checked
      for (const node of nodesOf(this.bySub.get(r.sub) ?? this.servers)) for (const e of node.entries) {
        const tail = e.label.slice((PROTO[e.s.protocol]?.[1] ?? '').length).replace('relay', VIA[e.s.id] ?? 'relay');
        named.set(e.s.id, { flag: node.flag, text: node.name + sufOf(node) + tail });
      }
      const servers = r.servers.map((n) => {
        const { flag, text } = named.get(n.id) ?? flagOf(n.name);
        // (by id; the result names the server, and a name is shared by the servers of one country)
        const fast = sp && (sp.server === n.id || (this.serverId ? this.serverId === n.id : sp.server === n.name)) ? ` · ${sp.down_mbps.toFixed(1)} ${unit}` : ''; // the server the VPN is on
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
      else if (fz?.verdict === 'ok' || sp && fz?.verdict !== 'freeze') row(I.netRows[5], { meta: sp ? I.netRows[5].meta : '', lines: speedLine });
      else if (fz?.verdict === 'freeze') {
        const kb = String(Math.max(1, Math.round(Math.max(...fz.targets.filter((t) => t.verdict === 'freeze').map((t) => t.bytes)) / 1024)));
        row(I.netRows[5], { v: 'freeze', alt: '', meta: I.srvRows[2].meta.replace('64', kb), lines: [I.srvRows[2].paths[0].m.replace('64', kb)] });
      }
      if (r.neighbours?.length) row(I.netRows[3], { name: w.neighbours[0], v: 'slow', alt: w.neighbours[1], meta: w.neighbours[2], lines: [r.neighbours.map((n) => n.name).join(' · ')], g: I.netRows[6].g, tone: 'neu' });
      return [...servers, ...net];
    }

    renderVals() {
      const v = super.renderVals();
      // "Help find blocks": the switch of the subscription on screen, the design's sentence for its state
      const cu = this.cur(), rs = reportState(cu);
      v.toggleAnon = () => { if (rs.can && cu) void rpc('report.set', { sub: cu.id, on: !rs.on }).catch(() => {}); };
      if (!rs.can) { if (cu?.probe) v.anonTxt = reportOff(); } else v.anonTxt = withName(rs.on && rs.at ? String(v.anonTxt).replace(/\d{1,2}[:.]\d{2}/, hhmm(rs.at)) : v.anonTxt, cu!.name);
      if (!S) return v;
      const { I, G, look } = S;
      const d = this.diag, r = d.result;
      const open = this.state?.open ?? {};
      const acted = this.state?.acted ?? {};

      v.start = () => void rpc<State>('diag.run', { sub: pref.get('sub') }).then((s) => this.applyDiag(s), () => {});
      v.cancel = () => void rpc<State>('diag.cancel').then((s) => this.applyDiag(s), () => {});
      // help from the admin: only where the panel takes diagnostics, and unasked only where it lets the person
      const u = this.cur(), q = this.ask(), rep = this.state?.rep ?? 'closed';
      const can = !!u?.debug?.intake && (!!q || !!u.debug.unasked);
      Object.assign(v, {
        showHelp: v.showHelp && can && !q, asked: can && !!q && rep === 'closed', bestCls: 'hide',
        shSub: String(v.shSub).replace('vpn.example.com', u?.host || u?.name || ''),
        parts: v.parts.filter((_: any, i: number) => PART[i]).map((p: any) => ({ ...p, flip: () => { p.flip(); setTimeout(this.resize); } })),
        repSize: this.snap ? nums(v.repSize, Math.max(1, Math.round(this.snap.bytes / 1024))) : '',
        openRep: () => { this.setState({ rep: 'open', dbgErr: '', showC: false }); setTimeout(this.resize); },
        sendRep: () => void this.send(),
        offWarn: rep === 'open' && !!this.state?.dbgErr,
        copy: () => { void navigator.clipboard?.writeText(this.sentId).catch(() => {}); this.setState({ copied: true }); },
      });

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
      // the design's button only says "Copied"
      v.copySum = () => {
        void navigator.clipboard?.writeText([v.R?.title, v.R?.sub, v.R?.srvSum, v.R?.netSum].filter(Boolean).join('\n')).catch(() => {});
        this.setState({ sumCopied: true });
      };
      return v;
    }
  } as unknown as typeof DCLogic;
}
