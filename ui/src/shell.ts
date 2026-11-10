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
    // by place, not by label: the labels differ between screens and languages. The middle one (maximize) does
    // nothing: the window has one size.
    const button = (e.target as Element).closest('.cap button');
    if (!button) return;
    const all = [...button.parentElement!.querySelectorAll('button')];
    if (button === all[0]) void win.minimize();
    if (button === all[all.length - 1]) void win.close(); // the shell hides to the tray or quits, by the setting
  });
}
