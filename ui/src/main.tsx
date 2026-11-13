import React from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/onest/400.css';
import '@fontsource/onest/500.css';
import '@fontsource/onest/600.css';
import '@fontsource/onest/700.css';
import '@fontsource/onest/800.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';
import '@fontsource/jetbrains-mono/700.css';
import './shell.css';
import { NavContext } from './dc';
import { LANGS, loadScreens, type Lang } from './screens';

// ?screen=Tray&state=off… opens one screen with the props of the design: the mock mode the screenshots are taken from.
// ?lang=ru picks the language (kept for the next start); English is the default.
const query = Object.fromEntries(new URLSearchParams(location.search));
const { screen: first = 'Main', lang: asked, shell, ...props } = query;
const stored = (() => { try { return localStorage.getItem('lang'); } catch { return null; } })();
const inApp = '__TAURI_INTERNALS__' in window;
const label = inApp ? (window as any).__TAURI_INTERNALS__.metadata?.currentWindow?.label : '';
// the setup program is this same page in its own window. It is the first thing a person sees: with no language
// chosen yet it takes Windows' one, and the app then starts in the same.
const inSetup = label === 'setup';
const wanted = asked ?? stored ?? (inSetup ? navigator.language.slice(0, 2) : '');
const lang = (LANGS as readonly string[]).includes(wanted) ? (wanted as Lang) : 'en';
if (asked || (inSetup && !stored)) try { localStorage.setItem('lang', lang); } catch { /* a private window: the choice lasts this start */ }
// No dir on <html>: the Farsi screens set it on their own root, and their digit conversion walks the first [dir=rtl]
// element — on <html> it would rewrite the digits inside the stylesheets too.
document.documentElement.lang = lang;

if (inApp || shell !== undefined) document.documentElement.classList.add('shell');
// the quick panel is this same app in a second, small window
const inTray = label === 'tray';
if (inTray) document.documentElement.classList.add('shell-tray');
if (inApp && !inTray) void import('./shell').then((m) => m.attachWindow());
// the main window looks for a new version a little after the start, then four times a day; quietly
if (inApp && !inTray && !inSetup) void import('./updates').then(({ updates }) => { setTimeout(() => void updates.check(true), 15000); setInterval(() => void updates.check(true), 6 * 3600 * 1000); });
// In the app window Home talks to the service; in a browser it stays the design's mock.
const live = inApp && !inSetup ? Promise.all([import('./live'), import('./live-settings'), import('./live-tray'), import('./live-diag'), import('./live-routes')]) : null;

// A window nobody looks at draws nothing: its animations stop while it is hidden or out of focus.
// (The quick panel is only on screen while it has the focus: it never rests. Nor does the setup window: its steps
// appear with a motion, and one paused at its start would leave the step blank.)
const rest = () => document.documentElement.classList.toggle('idle', !inTray && !inSetup && (document.hidden || !document.hasFocus()));
for (const ev of ['focus', 'blur']) window.addEventListener(ev, rest);
document.addEventListener('visibilitychange', rest);
rest();

// The engine lets a fresh window pile up about a gigabyte of dropped styles before its first full collection, and
// on a 144 Hz screen the design's motion drops some 10 MB of them a second: a few connections after the start took
// the window past a gigabyte, once to its death. So the window collects by its own hand, 4 s after the first of a run of changes: after
// the start and after every change of the connection. (gc is there because the windows start with --expose-gc.)
let tidy = 0;
const collect = () => { tidy ||= window.setTimeout(() => { tidy = 0; (window as { gc?: () => void }).gc?.(); }, 4000); };
if (inApp && !inSetup) { collect(); void import('@tauri-apps/api/event').then(({ listen }) => listen('mg://status', collect)); }

void Promise.all([loadScreens(lang), live, inSetup ? import('./live-setup') : null]).then(([screens, l, setup]) => {
  if (setup) screens.Setup = setup.liveSetup(screens.Setup);
  if (l) {
    const [home, rest, tray, diag, routes] = l;
    if (inTray) screens.Tray = tray.liveTray(screens.Tray);
    else {
      tray.startTrayIcon(screens.Tray);
      rest.startShell();
    }
    screens.Main = home.liveHome(screens.Main);
    screens.Settings = rest.liveSettings(screens.Settings);
    screens.Routes = routes.liveRoutes(screens.Routes);
    screens.Diag = diag.liveDiag(screens.Diag);
  }
  function App() {
    const [screen, setScreen] = React.useState(first);
    // the theme is the window's, not one screen's: Settings changes it, every screen gets it
    const [theme, setTheme] = React.useState(() => { try { return localStorage.getItem('theme'); } catch { return null; } });
    React.useEffect(() => {
      const on = (e: Event) => setTheme((e as CustomEvent<string>).detail);
      window.addEventListener('mg-theme', on);
      // the tray's panel and menu open the window on a screen
      const nav = (e: Event) => setScreen((e as CustomEvent<string>).detail);
      window.addEventListener('mg-nav', nav);
      return () => { window.removeEventListener('mg-theme', on); window.removeEventListener('mg-nav', nav); };
    }, []);
    const Screen = screens[screen] ?? screens.Main;
    return <NavContext.Provider value={setScreen}><Screen key={screen} {...props} {...(theme ? { theme } : {})} /></NavContext.Provider>;
  }
  createRoot(document.getElementById('root')!).render(<App />);
});
