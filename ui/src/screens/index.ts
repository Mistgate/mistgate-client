import { register } from '../dc';

export const LANGS = ['en', 'ru', 'fa', 'zh', 'tr'] as const;
export type Lang = (typeof LANGS)[number];

const html = import.meta.glob('./*/*.html', { query: '?raw', import: 'default' }) as Record<string, () => Promise<string>>;
const logic = import.meta.glob('./*/*.logic.js', { import: 'default' }) as Record<string, () => Promise<any>>;

// The screens of one language, with its stylesheet and fonts (Farsi is mirrored, Chinese has its own font stack).
export async function loadScreens(lang: Lang) {
  const css = lang === 'fa'
    ? Promise.all([import('../design/app.fa.css'), import('../fonts-fa')])
    : lang === 'zh'
      ? Promise.all([import('../design/app.zh.css'), import('../fonts-zh')])
      : import('../design/app.css');
  const files = Object.keys(html).filter((f) => f.startsWith(`./${lang}/`));
  const [, ...loaded] = await Promise.all([css, ...files.map(async (file) => {
    const name = file.slice(lang.length + 3, -5);
    return [name, register(name, await logic[`./${lang}/${name}.logic.js`](), await html[file]())] as const;
  })]);
  return Object.fromEntries(loaded);
}
