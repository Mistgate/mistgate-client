// What the installer carries besides the window: the service and the wintun driver library, into src-tauri/bin.
// Run before `tauri build` (the `bundle` script does both).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(ui, 'src-tauri', 'bin');
mkdirSync(bin, { recursive: true });

// the service: no symbols, no build paths in the binary
execFileSync('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', join(bin, 'mistgate-clientd.exe'), './cmd/mistgate-clientd'],
  { cwd: join(ui, '..', 'core'), stdio: 'inherit', env: { ...process.env, GOFLAGS: '-mod=mod', CGO_ENABLED: '0' } });

// wintun 0.14.1, amd64, as published by its authors (signed by WireGuard LLC); pinned by its hash
const WINTUN = { url: 'https://www.wintun.net/builds/wintun-0.14.1.zip', inZip: 'wintun/bin/amd64/wintun.dll', sha256: 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce' };
const dll = join(bin, 'wintun.dll');
const sum = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
if (!existsSync(dll) || sum(dll) !== WINTUN.sha256) {
  const zip = join(bin, 'wintun.zip');
  writeFileSync(zip, Buffer.from(await (await fetch(WINTUN.url)).arrayBuffer()));
  execFileSync('tar', ['-xf', zip, '-C', bin, WINTUN.inZip]); // Windows' tar reads zip
  writeFileSync(dll, readFileSync(join(bin, WINTUN.inZip)));
  rmSync(join(bin, 'wintun'), { recursive: true });
  rmSync(zip);
  if (sum(dll) !== WINTUN.sha256) { rmSync(dll); throw new Error('wintun.dll: the downloaded file is not the pinned one'); }
}
console.log('bundle parts ready in', bin);
