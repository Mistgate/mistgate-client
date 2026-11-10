// The Home screen on the real service. The design's logic class stays as generated (it plays a mock connection);
// in the app window this subclass takes its place: the power button calls the service, and the phase, the step, the
// timer, the server and the traffic come from the service's status and events (docs/ipc.md).
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';

type Status = { state: string; step: string; since_unix: number; server: string; protocol: string; error: string };
type Traffic = { rx_bps: number; tx_bps: number; rtt_ms: number };

const rpc = (method: string, params: object = {}) => invoke<Status>('rpc', { method, params });
// The design words four steps; its second ("UDP looks blocked") is a detector's line, not a step of ours.
const STEP: Record<string, number> = { resolve: 0, handshake: 2, tunnel: 3, verify: 3 };
const PROTO: Record<string, [fam: string, label: string]> = { hysteria2: ['h2', 'HY2'], awg: ['awg', 'AWG 3.1'] };
const mbps = (bps: number) => (bps / 1e6).toFixed(1);

export function liveHome(Base: typeof DCLogic): typeof DCLogic {
  return class LiveHome extends (Base as any) {
    off: Promise<UnlistenFn>[] = [];
    live: Status | null = null;
    traffic: Traffic | null = null;

    componentDidMount() {
      super.componentDidMount();
      this.off = [
        listen<Status>('mg://status', (e) => this.apply(e.payload)),
        listen<Traffic>('mg://traffic', (e) => { this.traffic = e.payload; this.forceUpdate(); }),
        listen<{ up: boolean }>('mg://service', (e) => (e.payload.up ? this.ask('status') : this.setState({ cs: 'svc', wave: false }))),
      ];
      this.ask('status');
    }
    componentWillUnmount() {
      super.componentWillUnmount();
      this.off.forEach((p) => void p.then((un) => un()));
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
      else if (s.state === 'reconnecting') Object.assign(next, { phase: 'ing', cs: 'rec' });
      else if (s.state === 'blocked') Object.assign(next, { phase: 'off', cs: 'ks' });
      else if (s.state === 'error' && s.error === 'no_subscription') Object.assign(next, { phase: 'off', si: 5 });
      else if (s.state === 'error') Object.assign(next, { phase: 'off', cs: s.error === 'offline' ? 'offline' : 'error' });
      else next.phase = 'off';
      this.setState(next);
    }

    // the mock's own timers must not move the phase
    runSteps() {}
    switchTo(id: string) { this.setState({ sel: id, pop: false }); } // ponytail: no server list from the service yet; switching comes with subscriptions
    setPhase(p: string) { this.ask(p === 'off' ? 'disconnect' : 'connect'); }
    toggle() {
      if (this.blk || this.cs === 'offline' || this.cs === 'svc') return;
      const idle = !this.live || this.live.state === 'off' || this.live.state === 'error';
      if (idle) this.setState({ phase: 'ing', cs: '', cstep: 0, wave: false }); // the button answers at once; the service confirms
      this.ask(idle ? 'connect' : 'disconnect');
    }

    renderVals() {
      const v = super.renderVals();
      const s: Status | null = this.live;
      if (s && s.state === 'connected') {
        const [fam, label] = PROTO[s.protocol] ?? ['', s.protocol];
        Object.assign(v.cur, { country: s.server, suf: '', title: s.server, fam, label, isH2: fam === 'h2', isAwg: fam === 'awg', isVless: false });
        if (this.traffic) {
          v.down = mbps(this.traffic.rx_bps);
          v.up = mbps(this.traffic.tx_bps);
          v.msTxt.cur = v.cur.ms = String(this.traffic.rtt_ms);
        } else v.down = v.up = '0.0';
      }
      v.det = { on: false }; // the detector's chip is the design's sample until the detectors exist
      if (v.isErr) v.csS = ''; // the design's line counts tried servers; the service does not report that yet
      return v;
    }
  } as unknown as typeof DCLogic;
}
