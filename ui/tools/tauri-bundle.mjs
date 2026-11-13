// `tauri build` for the installer. With the update signing key at hand the installer is also signed for the in-app
// updater and `latest.json` (what installed apps read to learn of a new version) is written beside it; without the
// key the build is the same installer, unsigned for updates: anyone can build the app, only the key's holder can
// publish an update that installed apps accept.
// The key: TAURI_SIGNING_PRIVATE_KEY (the key itself or a path), else ~/.mistgate/client-updater.key.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..');
const tauri = join(ui, 'src-tauri');
const { version } = { ...JSON.parse(readFileSync(join(tauri, 'tauri.conf.json'), 'utf8')), ...JSON.parse(process.env.MG_TAURI_CONFIG || '{}') };
const env = { ...process.env };
const local = join(homedir(), '.mistgate', 'client-updater.key');
if (!env.TAURI_SIGNING_PRIVATE_KEY && existsSync(local)) env.TAURI_SIGNING_PRIVATE_KEY = local;
const signed = !!env.TAURI_SIGNING_PRIVATE_KEY;
if (signed && env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD === undefined) env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD = '';

// the build's own additions to tauri.conf.json, as a file: signing for updates, and MG_TAURI_CONFIG (JSON) for a test build
const extra = { ...(signed ? { bundle: { createUpdaterArtifacts: true } } : {}), ...JSON.parse(process.env.MG_TAURI_CONFIG || '{}') };
const args = ['tauri', 'build'];
const file = join(tauri, 'target', 'bundle.conf.json');
rmSync(file, { force: true }); // an earlier build's
if (Object.keys(extra).length) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(extra));
  args.push('--config', '"' + file + '"');
}
execFileSync('pnpm', args, { cwd: ui, stdio: 'inherit', shell: true, env }); // shell: pnpm is a .cmd on Windows

const name = `Mistgate_${version}_x64-setup.exe`;
const installer = join(tauri, 'target', 'release', 'bundle', 'nsis', name);
if (!signed) {
  console.log('no update signing key: the installer is not signed for the in-app updater');
} else {
  const signature = readFileSync(installer + '.sig', 'utf8').trim();
  const notes = process.env.MG_RELEASE_NOTES ?? '';
  const latest = {
    version, notes, pub_date: new Date().toISOString(), size: statSync(installer).size,
    platforms: { 'windows-x86_64': { signature, url: `https://github.com/Mistgate/mistgate-client/releases/download/v${version}/${name}` } },
  };
  writeFileSync(join(dirname(installer), 'latest.json'), JSON.stringify(latest, null, 2) + '\n');
  console.log('signed for updates:', name + '.sig, latest.json');
}
