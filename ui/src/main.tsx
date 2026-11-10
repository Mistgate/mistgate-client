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
const lang = (LANGS as readonly string[]).includes(asked ?? stored ?? '') ? ((asked ?? stored) as Lang) : 'en';
if (asked) try { localStorage.setItem('lang', lang); } catch { /* a private window: the choice lasts this start */ }
// No dir on <html>: the Farsi screens set it on their own root, and their digit conversion walks the first [dir=rtl]
// element — on <html> it would rewrite the digits inside the stylesheets too.
document.documentElement.lang = lang;

const inApp = '__TAURI_INTERNALS__' in window;
if (inApp || shell !== undefined) document.documentElement.classList.add('shell');
if (inApp) void import('./shell').then((m) => m.attachWindow());

// A window nobody looks at draws nothing: its animations stop while it is hidden or out of focus.
const rest = () => document.documentElement.classList.toggle('idle', document.hidden || !document.hasFocus());
for (const ev of ['focus', 'blur']) window.addEventListener(ev, rest);
document.addEventListener('visibilitychange', rest);
rest();

void loadScreens(lang).then((screens) => {
  function App() {
    const [screen, setScreen] = React.useState(first);
    const Screen = screens[screen] ?? screens.Main;
    return <NavContext.Provider value={setScreen}><Screen key={screen} {...props} /></NavContext.Provider>;
  }
  createRoot(document.getElementById('root')!).render(<App />);
});
