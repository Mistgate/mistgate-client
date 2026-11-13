// Windows notifications, shown by the main window while it runs (in the tray too): only when something needs the
// user's attention. The switches are the window's own (Settings > Notifications); the service knows nothing of them.
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { PROTO, type Sub } from './live';
import { words } from './live-i18n';
import { version } from '../package.json';

// "Update installed": the design's words, with the version this build is
const UPDATED: Record<string, [(v: string) => string, string]> = {
  en: [(v) => `Mistgate updated to ${v}`, 'The new version is installed and already running.'],
  ru: [(v) => `Mistgate обновлён до ${v}`, 'Новая версия установлена и уже работает.'],
  zh: [(v) => `Mistgate 已更新到 ${v}`, '新版本已安装并正在运行。'],
  fa: [(v) => `‏Mistgate به نسخه ${v} به‌روز شد`, 'نسخه جدید نصب شده و در حال اجراست.'],
  tr: [(v) => `Mistgate ${v} sürümüne güncellendi`, 'Yeni sürüm kuruldu ve çalışıyor.'],
};

type Status = { state: string; server_id?: string; protocol?: string };
export type NotifyKey = 'nt' | 'n0' | 'n1' | 'n2' | 'n3' | 'n4';

const get = (key: string) => { try { return localStorage.getItem(key) ?? ''; } catch { return ''; } };
const set = (key: string, value: string) => { try { localStorage.setItem(key, value); } catch { /* lasts this start */ } };
// every switch is on until the user turns it off
export const notifyOn = (key: NotifyKey) => get(key) !== '0';
export const setNotify = (key: NotifyKey, on: boolean) => set(key, on ? '1' : '0');

function show(key: NotifyKey, title: string, body: string) {
  if (notifyOn('nt') && notifyOn(key)) void invoke('notify', { title, body }).catch(() => {});
}

const LOST_AFTER = 30_000;

export function startNotify() {
  // ---- the app itself: this start is the first of a new version
  const before = get('ver');
  set('ver', version);
  if (before && before !== version) { const [title, body] = UPDATED[document.documentElement.lang] ?? UPDATED.en; show('n4', title(version), body); }

  // ---- the connection: lost for over 30 s, and back on another way
  let was: Status | null = null; // the last connected state
  let lostTimer = 0;
  const status = (s: Status) => {
    if (s.state === 'connected') {
      window.clearTimeout(lostTimer);
      lostTimer = 0;
      // the same session came back on another server or protocol: the service moved it
      if (was && (was.server_id !== s.server_id || was.protocol !== s.protocol) && was.server_id && s.server_id) {
        const [title, body] = words().notify.backup;
        show('n1', title, body(PROTO[s.protocol ?? '']?.[2] ?? s.protocol ?? ''));
      }
      was = s;
    } else if (s.state === 'reconnecting') {
      if (was && !lostTimer) lostTimer = window.setTimeout(() => { const [title, body] = words().notify.lost; show('n0', title, body); }, LOST_AFTER);
    } else {
      // off, an error the user sees in the window, or a new connect of their own: not "the same session"
      window.clearTimeout(lostTimer);
      lostTimer = 0;
      was = null;
    }
  };
  void listen<Status>('mg://status', (e) => status(e.payload));
  void invoke<Status>('rpc', { method: 'status', params: {} }).then((s) => { if (s.state === 'connected') was = s; }, () => {});

  // ---- the subscriptions: about to end (once a day each), and this PC removed
  const removed = new Set<string>();
  let first = true;
  const subs = (list: Sub[]) => {
    const w = words(), now = Date.now() / 1000, today = new Date().toDateString();
    for (const u of list) {
      const days = Math.ceil((u.expire_unix - now) / 86400);
      if (u.expire_unix > 0 && days >= 1 && days <= 3 && get('ntf.end.' + u.id) !== today) {
        set('ntf.end.' + u.id, today);
        show('n2', w.notify.ends[0](w.days(days), days), w.notify.ends[1](u.name, w.date(u.expire_unix)));
      }
      const gone = u.error === 'device_removed';
      // not at start: the window already says so, and it happened while nobody watched
      if (gone && !removed.has(u.id) && !first) show('n3', w.notify.removed[0], w.notify.removed[1](u.name));
      if (gone) removed.add(u.id); else removed.delete(u.id);
    }
    first = false;
  };
  void listen<{ subs: Sub[] }>('mg://subs', (e) => subs(e.payload.subs));
  void invoke<{ subs: Sub[] }>('rpc', { method: 'subs.list', params: {} }).then((r) => subs(r.subs), () => { first = false; });
}
