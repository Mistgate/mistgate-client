// The setup program (the design's installer window): this same app built with the "setup" feature, carrying the
// installer `tauri build` has just made. Run after it (the `bundle` script does all three steps).
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..');
const tauri = join(ui, 'src-tauri');
const release = join(tauri, 'target', 'release');
const { version } = { ...JSON.parse(readFileSync(join(tauri, 'tauri.conf.json'), 'utf8')), ...JSON.parse(process.env.MG_TAURI_CONFIG || '{}') }; // a test build may name its own
const payload = join(release, 'bundle', 'nsis', `Mistgate_${version}_x64-setup.exe`);

// what the install takes on the disk: the app, the service, the driver library
const parts = [join(release, 'mistgate.exe'), join(tauri, 'bin', 'mistgate-clientd.exe'), join(tauri, 'bin', 'wintun.dll')];
const mb = Math.ceil(parts.reduce((sum, file) => sum + statSync(file).size, 0) / 2 ** 20);

// built into its own folder: target/release/mistgate.exe stays the app
const target = join(tauri, 'target', 'setup');
const conf = join(tauri, 'target', 'bundle.conf.json'); // what tauri-bundle.mjs added for this build
execFileSync('pnpm', ['tauri', 'build', '--no-bundle', '--features', 'setup', ...(existsSync(conf) ? ['--config', '"' + conf + '"'] : [])],
  { cwd: ui, stdio: 'inherit', shell: true, env: { ...process.env, CARGO_TARGET_DIR: target, MG_SETUP_PAYLOAD: payload, MG_SETUP_MB: String(mb) } });
const out = join(release, 'bundle', 'setup');
mkdirSync(out, { recursive: true });
const file = join(out, `MistgateSetup_${version}_x64.exe`);
copyFileSync(join(target, 'release', 'mistgate.exe'), file);
console.log('setup program:', file, (statSync(file).size / 2 ** 20).toFixed(1), 'MiB');
