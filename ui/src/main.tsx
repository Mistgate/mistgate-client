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
import './design/app.css';
import './shell.css';
import { NavContext } from './dc';
import { screens } from './screens';

// ?screen=Tray&state=off… opens one screen with the props of the design: the mock mode the screenshots are taken from.
const query = Object.fromEntries(new URLSearchParams(location.search));
const { screen: first = 'Main', ...props } = query;
if ('__TAURI_INTERNALS__' in window || 'shell' in query) document.documentElement.classList.add('shell');
if ('__TAURI_INTERNALS__' in window) void import('./shell').then((m) => m.attachWindow());

function App() {
  const [screen, setScreen] = React.useState(first);
  const Screen = screens[screen] ?? screens.Main;
  return <NavContext.Provider value={setScreen}><Screen key={screen} {...props} /></NavContext.Provider>;
}

createRoot(document.getElementById('root')!).render(<App />);
