// THIRD_PARTY.md at the repository's root: what the released app is built from, and under which licences.
// The service's Go modules (those that are really linked), the window's Rust crates for Windows, the window's npm
// packages, and wintun. Run with `pnpm licences` after a change of dependencies.
// ponytail: a Go module's licence is told from its LICENSE text by a few marks; an unknown text is said to be unknown.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..');
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', maxBuffer: 1 << 28 });

function goLicence(dir) {
  const file = existsSync(dir) && readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f));
  if (!file) return 'not found in the module';
  const t = readFileSync(join(dir, file), 'utf8');
  if (/Mozilla Public License,? [Vv]ersion 2\.0/.test(t)) return 'MPL-2.0';
  if (/Apache License/.test(t) && /Version 2\.0/.test(t)) return 'Apache-2.0';
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/.test(t)) return 'AGPL-3.0';
  if (/GNU LESSER GENERAL PUBLIC LICENSE/.test(t)) return /special exception/i.test(t) ? 'LGPL-3.0 with a linking exception' : 'LGPL';
  if (/GNU GENERAL PUBLIC LICENSE/.test(t)) return /Version 3/.test(t) ? 'GPL-3.0' : 'GPL-2.0';
  if (/Permission is hereby granted, free of charge/.test(t)) return 'MIT';
  if (/Permission to use, copy, modify, and(\/or)? distribute/.test(t)) return 'ISC';
  if (/Redistribution and use in source and binary forms/.test(t)) return /Neither the name|may not be used to endorse/.test(t) ? 'BSD-3-Clause' : 'BSD-2-Clause';
  if (/CC0 1\.0/.test(t)) return 'CC0-1.0';
  return 'see its ' + file;
}

// ---- Go: the modules of the packages the service binary is built from
const core = join(ui, '..', 'core');
const goMods = [...new Set(run('go', ['list', '-deps', '-f', '{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}', './cmd/mistgate-clientd'],
  core).split('\n').filter(Boolean))]
  .map((l) => l.split('\t')).filter(([path]) => !path.startsWith('github.com/mistgate/mistgate-client'))
  .map(([path, version, dir]) => [path, version, goLicence(dir)]).sort((a, b) => a[0].localeCompare(b[0]));

// ---- Rust: the crates the window is built from on Windows (not the ones only tests or other systems use)
const meta = JSON.parse(run('cargo', ['metadata', '--format-version', '1', '--filter-platform', 'x86_64-pc-windows-msvc'], join(ui, 'src-tauri')));
const byId = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const seen = new Set();
const walk = (id) => {
  if (seen.has(id)) return;
  seen.add(id);
  for (const d of nodes.get(id)?.deps ?? []) if (d.dep_kinds.some((k) => k.kind !== 'dev')) walk(d.pkg);
};
walk(meta.resolve.root);
const crates = [...seen].map((id) => byId.get(id)).filter((p) => p.name !== 'mistgate')
  .map((p) => [p.name, p.version, (p.license ?? 'see the crate').replaceAll('/', ' OR ')]).sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));

// ---- npm: what the window ships (its direct dependencies; the fonts are among them)
const pkg = JSON.parse(readFileSync(join(ui, 'package.json'), 'utf8'));
const npm = Object.keys(pkg.dependencies ?? {}).sort().map((name) => {
  const p = JSON.parse(readFileSync(join(ui, 'node_modules', name, 'package.json'), 'utf8'));
  return [name, p.version, typeof p.license === 'string' ? p.license : 'see the package'];
});

const table = (rows) => ['| Name | Version | Licence |', '|:--|:--|:--|', ...rows.map((r) => `| ${r[0]} | ${r[1]} | ${r[2]} |`)].join('\n');
const text = `# Third-party software

Mistgate for Windows is under the [AGPL-3.0](LICENSE). It is built from the software below, each part under its own
licence; the licence texts are in the parts' own sources, which the module and crate names lead to.
This list is made by \`ui/tools/licences.mjs\` (\`pnpm licences\`) from the dependency data, not by hand.

## Shipped as it is

| Name | Version | Licence |
|:--|:--|:--|
| [wintun](https://www.wintun.net/) (\`wintun.dll\`) | 0.14.1 | Its authors' prebuilt binary, under the "Prebuilt Binaries License" published with it |

## The service (Go modules linked into \`mistgate-clientd.exe\`)

${table(goMods)}

The Go standard library and runtime: BSD-3-Clause.

## The window (Rust crates built into \`mistgate.exe\`)

${table(crates)}

## The window's pages (npm packages)

${table(npm)}
`;
writeFileSync(join(ui, '..', 'THIRD_PARTY.md'), text);
console.log('THIRD_PARTY.md:', goMods.length, 'Go modules,', crates.length, 'crates,', npm.length, 'npm packages');
const odd = [...goMods, ...crates, ...npm].filter((r) => /see |not found/.test(r[2]));
if (odd.length) console.log('to look at by hand:', odd.map((r) => r[0] + ' (' + r[2] + ')').join(', '));
