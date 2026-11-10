// Routes on the real service: the mode (Smart or Everything) and the region are the service's settings.
// The design's logic stays as generated. What this build does not do yet is drawn but cannot be pressed
// (shell.css: "Only selected", the catalogue of collections, apps, sites and lists): Smart works by address
// only, so the one thing it sends direct is the region's own addresses, plus the local network.
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { DCLogic } from './dc';
import { words } from './live-i18n';
import { liveChip } from './live-settings';

type Routes = { mode: 'all' | 'smart'; region: string; effective: string; available: boolean; entries: number; updated_unix: number };

const rpc = <T>(method: string, params: object = {}) => invoke<T>('rpc', { method, params });
const KNOWN = ['ru', 'by', 'cn', 'ir']; // the regions the design draws; anything else shows as its "None"

export function liveRoutes(Base: typeof DCLogic): typeof DCLogic {
  return class LiveRoutes extends (liveChip(Base) as any) {
    routes: Routes | null = null;

    mounted() {
      this.off.push(listen<Routes>('mg://routes', (e) => this.applyRoutes(e.payload)));
      rpc<Routes>('routes.get').then((r) => this.applyRoutes(r), () => {});
    }
    // into the design's own switches, so its texts follow
    applyRoutes(r: Routes) {
      this.routes = r;
      this.setState({
        mode: r.mode === 'smart' ? 'except' : 'all', reg: KNOWN.includes(r.effective) ? r.effective : 'other', regOpen: false,
        // what Smart really sends direct in this build: the region's addresses and the local network
        sel: { except: { rusites: true, rusvc: true, lan: true, steam: false }, only: {} },
      });
    }
    save(patch: object) {
      void rpc('settings.set', patch).then(() => rpc<Routes>('routes.get')).then((r) => this.applyRoutes(r), () => {});
    }
    renderVals() {
      const v = super.renderVals();
      const r = this.routes;
      v.setExc = () => this.save({ route_mode: 'smart' });
      v.setAll = () => this.save({ route_mode: 'all' });
      v.setOnly = () => {};
      v.mOnly = 'soon';
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
      return v;
    }
  } as unknown as typeof DCLogic;
}
