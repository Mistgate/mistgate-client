// Flags for the server lists of the window and the tray panel.
import FLAGS from './design/flags.json';

// The design's own flags (and Turkey's, drawn for the region list) for the countries it has; every other country's
// from the country-flag-icons set, square like the design's. A subscription from another provider names any country.
const OTHER = import.meta.glob('../node_modules/country-flag-icons/1x1/*.svg', { query: '?url', import: 'default', eager: true }) as Record<string, string>;
export const FLAG: Record<string, string> = {
  ...Object.fromEntries(Object.entries(OTHER).map(([file, address]) => [file.slice(file.lastIndexOf('/') + 1, -4).toLowerCase(), address])),
  ...(FLAGS as Record<string, string>), tr: '/blob/bc9caa2c3d3cb9a41eee59f9fe3669ed.svg',
};
