<div align="center">

<img src="ui/src-tauri/icons/128x128.png" width="96" height="96" alt="Mistgate logo">

<h1>Mistgate for Windows</h1>

<p>A VPN app that finds a working way on its own and says honestly when something is blocked.<br>
Hysteria2, AmneziaWG and VLESS in one window. For <a href="https://github.com/Mistgate/mistgate">Mistgate</a> panels and for plain subscription links.</p>

<p>
<img alt="Status: beta" src="https://img.shields.io/badge/status-beta-f2c46b">
<a href="https://github.com/Mistgate/mistgate-client/releases/latest"><img alt="Version" src="https://img.shields.io/github/v/release/Mistgate/mistgate-client?sort=semver&color=b8acf2"></a>
<a href="LICENSE"><img alt="Licence: AGPL-3.0" src="https://img.shields.io/github/license/Mistgate/mistgate-client?color=b8acf2"></a>
<a href="https://github.com/Mistgate/mistgate-client/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Mistgate/mistgate-client/actions/workflows/ci.yml/badge.svg?branch=main"></a>
<img alt="Windows 10 and 11, x64" src="https://img.shields.io/badge/Windows-10%20%7C%2011%20x64-8ec8ea">
<a href="core/go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/Mistgate/mistgate-client?filename=core%2Fgo.mod"></a>
<img alt="Tauri 2" src="https://img.shields.io/badge/Tauri-2-7dd3a0">
</p>

<p><a href="https://github.com/Mistgate/mistgate-client/releases/latest"><b>Download</b></a> · <a href="#what-it-does"><b>Features</b></a> · <a href="#protocols"><b>Protocols</b></a> · <a href="#install"><b>Install</b></a> · <a href="docs/build.md"><b>Build</b></a> · <a href="README.ru.md">Русский</a> · <a href="README.zh.md">简体中文</a> · <a href="README.fa.md">فارسی</a> · <a href="README.tr.md">Türkçe</a></p>

<p><sub><b>Beta.</b> Version 0.1, Windows only. Expect changes before 1.0.</sub></p>

</div>

<img alt="The main window: connected, the server list on the right" src="docs/img/home.png" width="100%">

<p align="center"><sub>The pictures on this page are the app's own screens filled with sample data.</sub></p>

## What it does

You add a subscription once. The app keeps the server list up to date, connects with the protocol that works on the
network you are on, and sends through the VPN only what you want there.

- **One switch, three protocols.** Hysteria2, AmneziaWG and VLESS. *Auto* takes the server that answers quickest right
  now; you can also pick the server and the protocol yourself.
- **With a Mistgate panel, and without one.** Paste a subscription link, `hysteria2://` or `vless://` links, a Mihomo
  profile or an AmneziaWG config. On a Mistgate panel the app enrols this PC with its own key, follows the panel's
  servers, and shows the plan, the data used and the devices.
- **Routes.** *Smart* leaves local sites and the home network outside the VPN, *Only selected* sends through it just
  what you pick, *Everything* sends all of it. Rules by ready-made collections, your own lists, sites and programs.
- **Kill switch.** While the tunnel is down nothing leaves the PC: while connected, or always.
- **Network check.** One button shows which servers and which ways to them work from here.
- **Local proxy.** SOCKS5 and HTTP for the programs and the home devices that cannot use the VPN directly.
- **Telegram proxies** from the panel: one press hands a proxy to Telegram.
- **The rest.** A quick panel in the tray, Windows notifications, dark and light themes, five languages: English,
  Russian, Chinese, Persian, Turkish.
- **Updates** from this repository's releases. The app installs only an installer signed with the project's key.

<table>
  <tr>
    <td width="50%"><img src="docs/img/routes.png" alt="Routes: three modes, collections, programs and sites"></td>
    <td width="50%"><img src="docs/img/settings.png" alt="Settings: kill switch, start with Windows, protocol"></td>
  </tr>
  <tr>
    <td align="center"><sub>Routes: what goes through the VPN and what does not</sub></td>
    <td align="center"><sub>Settings</sub></td>
  </tr>
</table>

## Protocols

| Protocol | In the app | What it takes |
|:--|:--|:--|
| Hysteria2 | The official Hysteria2 core, linked in | UDP (QUIC). Salamander obfuscation, port hopping. |
| AmneziaWG | amneziawg-go, linked in | Versions 2.0 and 3.1, a key per device from a Mistgate panel or a `.conf` file. |
| VLESS | Xray-core, linked in | REALITY or TLS; RAW with Vision, XHTTP and WebSocket. |

All three run inside one Windows service and one wintun adapter. Not supported: VMess, Trojan, Shadowsocks, TUIC and
plain WireGuard.

## Install

<img align="right" src="docs/img/setup.png" alt="The setup program" width="360">

Windows 10 or 11, x64.

1. Take `MistgateSetup_<version>_x64.exe` from the
   [latest release](https://github.com/Mistgate/mistgate-client/releases/latest) and run it.
2. Windows asks for administrator rights once: the app adds a background service that owns the tunnel.
3. Paste your subscription link and press the big button.

The installer has no Windows code-signing certificate yet, so SmartScreen may warn about an unknown publisher.
Updates are checked differently, by the project's own signature:
[how updates work](docs/build.md#updates-of-the-installed-app).

<br clear="right">

## How it is built

| Part | What it is |
|:--|:--|
| [`core/`](core) | The service, in Go (`mistgate-clientd`, runs as LocalSystem): the tunnel, the routes, the kill switch, the subscriptions, the network check. |
| [`ui/`](ui) | The window, the tray panel and the setup program: Tauri 2 with a small React shell. It talks to the service over one named pipe that accepts only the installed app. |
| [`design/`](design) | The screens as designed. `ui/src/screens` is generated from them; the `ui/src/live*.ts` layers put the real state in. |
| [`docs/`](docs) | [Building](docs/build.md), [the pipe's protocol](docs/ipc.md), [the panel's client API](docs/client-api.md). |

```
cd ui
pnpm install
pnpm bundle
```

Needs Go, Rust (MSVC) and Node with pnpm. Details, and the Go versions that must not be used, are in
[docs/build.md](docs/build.md).

## Privacy

- Device keys and server credentials live in a store that Windows encrypts for the service's own account.
- The log holds no keys, links, server addresses, names of sites or of programs.
- The app tells the panel nothing about what you open. A debug bundle leaves the PC only when you press send, and the
  app shows it line by line first.

## Status

It is beta and young. Not there yet: a Windows code-signing certificate, an uninstall screen of its own, macOS and
Linux builds. If something does not work, [open an issue](https://github.com/Mistgate/mistgate-client/issues).

## Licence

[AGPL-3.0](LICENSE). The libraries it links keep their own licences, among them Xray-core (MPL-2.0), Hysteria,
amneziawg-go, gVisor and wintun: the whole list is in [THIRD_PARTY.md](THIRD_PARTY.md).
