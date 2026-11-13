// Updates of the app itself: a signed installer from the project's GitHub releases, through Tauri's updater. It reads
// latest.json of the newest release, and takes the installer only if its signature matches the key built into this app.
// One state for the whole window: Settings draws it, the start of the app begins a check.
import { check, type Update } from '@tauri-apps/plugin-updater';

export type UpState = {
  up: 'latest' | 'checking' | 'available' | 'downloading' | 'ready' | 'failed' | 'badsig';
  version: string; // the new version, when one is known
  date: string; // its release date, ISO, or ''
  size: number; // the installer's size in bytes, 0 when not told
  notes: string[]; // the release notes, one line each
  pct: number; // while downloading
  checked: number; // when the last check ended, ms; 0: never in this run
};

let state: UpState = { up: 'latest', version: '', date: '', size: 0, notes: [], pct: 0, checked: 0 };
let found: Update | null = null;
let busy = false;
const heard = new Set<() => void>();
const put = (next: Partial<UpState>) => { state = { ...state, ...next }; heard.forEach((f) => f()); };

export const updates = {
  get: () => state,
  on(f: () => void) { heard.add(f); return () => { heard.delete(f); }; },
  auto: () => { try { return localStorage.getItem('au') !== '0'; } catch { return true; } },
  setAuto(on: boolean) { try { localStorage.setItem('au', on ? '1' : '0'); } catch { /* lasts this start */ } heard.forEach((f) => f()); },

  // quiet: a check nobody asked for (the start of the app) does not show "checking" and keeps a failure to itself
  async check(quiet = false) {
    if (busy || state.up === 'downloading' || state.up === 'ready') return;
    busy = true;
    if (!quiet) put({ up: 'checking' });
    try {
      found = await check({ timeout: 15000 });
      if (!found) return put({ up: 'latest', checked: Date.now() });
      const size = Number((found.rawJson as { size?: unknown }).size) || 0;
      const notes = (found.body ?? '').split('\n').map((l) => l.replace(/^\s*[-*•]\s*/, '').trim()).filter(Boolean).slice(0, 6);
      put({ up: 'available', version: found.version, date: found.date ?? '', size, notes, checked: Date.now() });
      if (quiet && updates.auto()) void updates.download();
    } catch {
      // no network, GitHub not reachable, no release yet: for a check nobody asked for this is not news
      put(quiet ? { checked: 0 } : { up: 'latest', checked: 0 });
    } finally { busy = false; }
  },

  async download() {
    if (!found || state.up === 'downloading') return;
    let total = state.size, got = 0;
    put({ up: 'downloading', pct: 0 });
    try {
      await found.download((e) => {
        if (e.event === 'Started') total = e.data.contentLength ?? total;
        else if (e.event === 'Progress') { got += e.data.chunkLength; if (total) put({ pct: Math.min(99, Math.round((got / total) * 100)) }); }
      });
      put({ up: 'ready', pct: 100 });
    } catch (e) {
      // the updater refuses a file whose signature is not this app's key's: said apart from a broken download
      put({ up: /signature|verif|minisign|public key/i.test(String(e)) ? 'badsig' : 'failed' });
    }
  },

  // the installer takes over: it closes the app, replaces it and the service, and starts the app again
  async install() {
    if (!found || state.up !== 'ready') return;
    try { await found.install(); } catch { put({ up: 'failed' }); }
  },
  later() { /* stays ready: the button is there the next time Settings is opened */ },
};
