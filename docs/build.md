# Building

Needs Go, Rust (MSVC toolchain), Node with pnpm, on Windows x64.

Go: `core/go.mod` asks for 1.27.4 and an older Go fetches it by itself. Never build the service with Go 1.26.0 or
1.26.1: their Windows UDP read writes into freed stack memory (golang/go#78041) and the service dies at random, a few
times an hour in the forwarder modes, without a message of its own.

```
cd ui
pnpm install
pnpm bundle
```

`pnpm bundle` builds the service into `ui/src-tauri/bin/`, puts `wintun.dll` 0.14.1 beside it (downloaded from
wintun.net once and checked against a pinned SHA-256), then builds the window and the installer:
`ui/src-tauri/target/release/bundle/nsis/Mistgate_<version>_x64-setup.exe`.

## What the installer does

- Installs for the machine (asks for elevation once) into `Program Files\Mistgate`: `mistgate.exe` (the window),
  `mistgate-clientd.exe` (the service), `wintun.dll`, the uninstaller, a Start menu shortcut.
- Registers and starts the service (`mistgate-clientd install`: LocalSystem, automatic start). Installing over an
  existing copy stops and removes the old service first, so a VPN connection drops during an update.
- Uninstalling removes the service, the files and the "start with Windows" entry. Subscriptions and settings in
  `ProgramData\Mistgate` stay unless "delete application data" is ticked.
- `/S` installs and uninstalls silently.

The build is not signed yet: Windows SmartScreen warns about the installer, and the service and the window trust
each other by sitting in the same directory (see `docs/ipc.md`), not by a signature.

For development the window's debug binary and a console service are enough: see "Running it by hand" in
`docs/ipc.md`.
