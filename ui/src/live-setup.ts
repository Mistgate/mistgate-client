// The setup program's window: the design's Setup screen, with the real folder, disk space, install and its outcome.
// The design's logic stays as generated; this subclass replaces its sample numbers and its pretend install.
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { DCLogic } from './dc';

type Info = { path: string; need_mb: number; free_mb: number; version: string; open: boolean; used: boolean };
// a folder with somebody else's files is refused too: they would run beside the service
const USED: Record<string, string> = {
  en: 'This folder already has files in it. Choose an empty or a new folder.',
  ru: 'В этой папке уже есть файлы. Выберите пустую или новую папку.',
  zh: '此文件夹中已有文件。请选择空文件夹或新文件夹。',
  fa: 'این پوشه از قبل فایل دارد. یک پوشهٔ خالی یا جدید انتخاب کنید.',
  tr: 'Bu klasörde zaten dosyalar var. Boş veya yeni bir klasör seçin.',
};
// a folder any program could swap for its own is refused (the service in it runs as the system)
const OPEN: Record<string, string> = {
  en: 'Any program can change this folder without administrator rights. Choose another one, for example in Program Files.',
  ru: 'Эту папку может менять любая программа без прав администратора. Выберите другую, например в Program Files.',
  zh: '任何程序无需管理员权限即可更改此文件夹。请选择其他位置，例如 Program Files。',
  fa: 'هر برنامه‌ای می‌تواند بدون دسترسی مدیر این پوشه را تغییر دهد. پوشهٔ دیگری انتخاب کنید، مثلاً در Program Files.',
  tr: 'Bu klasörü her program yönetici izni olmadan değiştirebilir. Başka bir klasör seçin, örneğin Program Files içinde.',
};
type Outcome = { state: 'ok' | 'denied' | 'failed'; code: number };
// the languages as Settings lists them, each by its own name
const LANGS = [['en', 'English', 'ltr'], ['ru', 'Русский', 'ltr'], ['zh', '中文', 'ltr'], ['fa', 'فارسی', 'rtl'], ['tr', 'Türkçe', 'ltr']];

export function liveSetup(Base: typeof DCLogic): typeof DCLogic {
  return class LiveSetup extends (Base as any) {
    info: Info | null = null;
    busy = false;
    code = 0;
    componentDidMount() {
      super.componentDidMount?.();
      document.addEventListener('click', this.onPage, true);
      this.load();
    }
    componentWillUnmount() {
      super.componentWillUnmount?.();
      document.removeEventListener('click', this.onPage, true);
    }
    load(path?: string) {
      void invoke<Info>('setup_info', { path: path ?? null }).then((i) => { this.info = i; this.forceUpdate(); }, () => {});
    }
    opt(): { desk: boolean; boot: boolean } { return { desk: true, boot: true, ...(this.state?.opt ?? {}) }; }
    // The language button: the design draws the button only, so its list is the one Settings has (the same classes),
    // opening upward from the button. Choosing a language starts the page again in it, as in Settings.
    langs(button: Element) {
      const root = button.closest('.su')!, box = root.getBoundingClientRect(), at = button.getBoundingClientRect();
      const pop = document.createElement('div');
      pop.className = 'sx-pop rise mg-langs';
      pop.setAttribute('role', 'listbox');
      pop.style.cssText = `right:auto;left:${Math.min(at.left - box.left, box.width - 232)}px;bottom:${box.bottom - at.top + 6}px`;
      for (const [id, name, dir] of LANGS) {
        const on = id === document.documentElement.lang, item = document.createElement('button');
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', String(on));
        item.className = on ? 'on' : '';
        item.innerHTML = '<span class="nt"></span><span class="en"></span><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 12.5 4 4 8-9"/></svg>';
        item.firstElementChild!.textContent = name;
        item.firstElementChild!.setAttribute('dir', dir);
        item.onclick = () => {
          if (on) return;
          try { localStorage.setItem('lang', id); } catch { /* stays as it is */ }
          location.reload();
        };
        pop.append(item);
      }
      root.append(pop);
    }
    onPage = (e: MouseEvent) => {
      const t = e.target as Element | null;
      const open = document.querySelector('.mg-langs'), lang = t?.closest?.('.su-lang');
      if (open && !t?.closest?.('.mg-langs')) open.remove(); // a click anywhere else closes the list
      if (lang && !open) return this.langs(lang);
      if (t?.closest?.('.su-path .lsb')) { // "Change…"
        void invoke<string>('setup_pick').then((path) => { if (path) this.load(path); }, () => {});
      } else if (t?.closest?.('.su-f a.addb')) { // "Add subscription": the design links its own Home screen
        e.preventDefault();
        e.stopPropagation();
        if (this.info) void invoke('setup_launch', { path: this.info.path });
      }
    };
    // The design's run(1) plays an install and run(-1) a cancel. Here the install is the real one, and it cannot be
    // cancelled half-way (the installer runs with rights this window does not have).
    run(dir: number) {
      const info = this.info;
      if (dir < 0 || this.busy || !info) return;
      this.busy = true;
      clearInterval(this.tm);
      let p = 0;
      this.setState({ step: 'progress', issue: 'none', p, copied: false });
      // ponytail: the installer inside reports no progress: the bar creeps toward 92% and jumps to the end when it
      // is done. Real steps need the installer to write them somewhere this window can read.
      this.tm = setInterval(() => { p += Math.max(0.3, (92 - p) / 25); this.setState({ p: Math.round(Math.min(p, 92)) }); }, 250);
      const opt = this.opt();
      const done = (r: Outcome) => {
        clearInterval(this.tm);
        this.busy = false;
        this.code = r.code;
        if (r.state !== 'ok') return this.setState({ step: 'welcome', issue: r.state, p: undefined });
        void invoke('setup_autostart', { path: info.path, enabled: opt.boot });
        // the app's own switch (Settings) reads these
        try { localStorage.setItem('auto', opt.boot ? '1' : '0'); } catch { /* the Run key is what counts */ }
        this.setState({ step: 'done', issue: 'none', p: 100 });
      };
      void invoke<Outcome>('setup_install', { path: info.path, desktop: opt.desk }).then(done, () => done({ state: 'failed', code: 0 }));
    }
    componentDidUpdate(...a: unknown[]) {
      super.componentDidUpdate?.(...a);
      const i = this.info;
      if (!i) return;
      const put = (el: Element | null | undefined, text: string) => { if (el && el.textContent !== text) el.textContent = text; };
      put(document.querySelector('.su-ver'), 'Mistgate ' + i.version);
      // the design's sample size and failure code
      const size = document.querySelector('.su-facts .g-hard-drive + span');
      if (size?.textContent?.includes('86')) size.textContent = size.textContent.replace('86', String(i.need_mb));
      put(document.querySelector('.su-det .mo'), 'setup · code ' + this.code);
    }
    renderVals() {
      const v = super.renderVals();
      const i = this.info;
      const close = () => { if (!this.busy) void getCurrentWindow().close(); };
      v.close = close;
      v.cancelC = 'dis';
      v.copy = () => { void navigator.clipboard?.writeText('setup · code ' + this.code).catch(() => {}); this.setState({ copied: true }); };
      if (!i) return v;
      const short = i.free_mb < i.need_mb, drive = i.path.slice(0, 2);
      // the design's two sentences about space, with the real numbers in place of its samples
      const sample = (issue: string) => String(Base.prototype.renderVals.call(Object.create(this, { state: { value: { ...this.state, issue } } })).spaceT);
      v.spaceT = short
        ? sample('space').replace('D:', drive).replace('86', String(i.need_mb)).replace('41', String(i.free_mb))
        : sample('none').replace('C:', drive).replace('86', String(i.need_mb)).replace('212', String(Math.floor(i.free_mb / 1024)));
      const why = i.open ? OPEN : i.used ? USED : null;
      if (why) v.spaceT = why[document.documentElement.lang] ?? why.en;
      const no = short || !!why;
      v.path = i.path;
      v.pathC = no ? 'bad' : '';
      v.instC = no ? 'dis' : '';
      // no room, or not a safe place: Install shows where, instead of starting
      v.install = () => (no ? this.setState({ step: 'folder', issue: 'none' }) : this.run(1));
      return v;
    }
  } as unknown as typeof DCLogic;
}
