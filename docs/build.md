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

It then builds the setup program, the file to give to people:
`ui/src-tauri/target/release/bundle/setup/MistgateSetup_<version>_x64.exe`. It is this same window program built with
the `setup` feature (`ui/src-tauri/src/setup.rs`, `ui/tools/setup-build.mjs`): it shows the design's Setup screens,
carries the installer above inside and runs it silently, with Windows' permission prompt. Where the WebView2 runtime
is missing it shows that installer as it is.

## The service links Xray

VLESS runs on `github.com/xtls/xray-core` as a library, in the service's own process: no second executable. Only what
a VLESS client needs is imported (`internal/xray`: the vless outbound and the tcp, splithttp, websocket, tls and reality
transports; no routing, DNS, stats, commander or config loaders), which makes the service about 7 MB larger (16.1 MB
to 23.1 MB with the flags above). Xray's releases are tagged `v26.x.y`, which Go cannot take as a module version, so
`go.mod` carries the pseudo-version of the release's commit (`v1.260327.1-0.20261109052709-676eaf66f8f0` is v26.11.9);
to update, `go get github.com/xtls/xray-core@<release commit>`. Xray needs a newer gVisor than the forwarder was written
against (`go.mod` is at the version Xray asks for) and newer `x/net`, `x/sys`, `x/crypto` and uTLS. Xray-core and
`xtls/reality` are MPL-2.0 (a notice of components, if one is shipped, lists them).

## What the installer does

- Installs for the machine (asks for elevation once) into `Program Files\Mistgate`: `mistgate.exe` (the window),
  `mistgate-clientd.exe` (the service), `wintun.dll`, the uninstaller, Start menu and desktop shortcuts.
- Registers and starts the service (`mistgate-clientd install`: LocalSystem, automatic start). Installing over an
  existing copy stops and removes the old service first, so a VPN connection drops during an update.
- Uninstalling removes the service, the files and the "start with Windows" entry. Subscriptions and settings in
  `ProgramData\Mistgate` stay unless "delete application data" is ticked.
- `/S` installs and uninstalls silently.

The build is not signed yet: Windows SmartScreen warns about the installer, and the service and the window trust
each other by sitting in the same directory (see `docs/ipc.md`), not by a signature.

For development the window's debug binary and a console service are enough: see "Running it by hand" in
`docs/ipc.md`.
