import { register } from '../dc';

const html = import.meta.glob('./*.html', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const logic = import.meta.glob('./*.logic.js', { import: 'default', eager: true }) as Record<string, any>;

export const screens = Object.fromEntries(Object.keys(html).map((file) => {
  const name = file.slice(2, -5);
  return [name, register(name, logic[`./${name}.logic.js`], html[file])];
}));
