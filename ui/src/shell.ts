// The frameless window: the title bar of the design drags it, its caption buttons minimize and close it.
// The templates stay as the designer made them; the behaviour is attached here, by their class names.
import { getCurrentWindow } from '@tauri-apps/api/window';

export function attachWindow() {
  const win = getCurrentWindow();
  document.addEventListener('mousedown', (e) => {
    const t = e.target as Element;
    if (e.button !== 0 || !t.closest('.tb, .su-tb') || t.closest('button, a, input')) return;
    void win.startDragging();
  });
  document.addEventListener('click', (e) => {
    const label = (e.target as Element).closest('.cap button')?.getAttribute('aria-label');
    if (label === 'Minimize') void win.minimize();
    if (label === 'Close') void win.close(); // ponytail: closes the window; hide-to-tray comes with the tray
  });
}
