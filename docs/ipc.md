# The bridge: window ↔ service

The window (`Mistgate.exe`, the user's rights) never touches the network. Everything is done by the service
(`mistgate-clientd.exe`, LocalSystem), and the window asks it over one named pipe.

## Transport

- Pipe `\\.\pipe\mistgate-client`, byte mode, created by the service. Remote clients are rejected.
- DACL: SYSTEM and Administrators full; the interactive user (`IU`) read and write. The DACL is not the gate: the
  caller check below is.
- One JSON object per line (UTF-8, `\n`), at most 1 MiB a line. A longer line closes the connection.

```
→ {"id": 7, "method": "connect", "params": {"server": "auto"}}
← {"id": 7, "result": {...}}            or   ← {"id": 7, "error": {"code": "not_trusted", "message": "…"}}
← {"event": "status", "data": {...}}    pushed at any time, no id
```

Errors are codes (`snake_case`); `message` is for the log, the window words its own text from the code. Unknown
method: `unknown_method`. Bad params: `bad_params`.

## Who may call

On every connection the service takes the client's process id from the pipe (`GetNamedPipeClientProcessId`), opens the
process and reads its image path. The connection is **trusted** when:

- the service binary carries an Authenticode signature: the caller's image is signed by the same certificate
  (same signer thumbprint), and the signature is valid;
- the service binary is unsigned (a development build): the caller's image is `Mistgate.exe` or `mistgate.exe` in the
  service's own directory, or the path in `MISTGATE_DEV_CLIENT` (read only by an unsigned build).

An untrusted connection may call `status` and nothing else: every other method (`hello` too) answers `not_trusted`,
and it gets no events. `subscribe` sends future events only: ask `status` once after it. The 1 MiB cap counts the line
without its `\n`. Signatures are checked offline (no revocation lookups); a catalog-only signature does not count. The result of the check is logged once per connection (pid, image path, verdict), never a token or a key.

## Methods (v0)

| Method | Params | Result |
|---|---|---|
| `hello` | `{"client": "0.0.1"}` | `{"service": "0.0.1", "trusted": true, "api": 0}` |
| `status` | — | Status |
| `connect` | `{"server": "auto" \| "<server id>", "protocol": "auto" \| "hysteria2" \| "awg", "sub": "<subscription id>"}` (all optional) | Status |
| `disconnect` | — | Status |
| `subscribe` | `{"events": ["status", "traffic", "log", "subs", "settings"]}` | `{}`; the events then arrive on this connection |
| `subs.list` | — | `{"subs": [Subscription…]}` |
| `subs.preview` | `{"text": "<URL, links, or AWG config>"}` | Subscription, not saved (`id` is empty) |
| `subs.add` | `{"text": "<URL, links, or AWG config>"}` | Subscription |
| `subs.refresh` | `{"id": "<subscription id>"}` | Subscription |
| `subs.remove` | `{"id": "<subscription id>"}` | `{}` |
| `settings.get` | — | Settings |
| `settings.set` | the settings keys to change | Settings |

Status:

While connecting, `server` and `protocol` reflect the request. Once connected, they hold the profile name and
protocol that are actually in use.

```json
{"state": "off", "step": "", "since_unix": 0, "server": "", "protocol": "", "error": ""}
```

`state`: `off` · `connecting` · `connected` · `reconnecting` · `error` · `blocked`.
`step` while connecting or retrying: `resolve` · `handshake` · `tunnel` · `verify`. `error`: a code such as `no_server_answers`,
`no_subscription`, `offline`, `server_not_found`, `auth_rejected`, `tunnel_failed`, `verify_failed`, `unsupported_os`,
or `kill_switch`.

`reconnecting` means the service detected a dead tunnel and is retrying; whether the network stays closed depends on
`kill_switch`. `error` may contain the most recent failed retry code. `blocked` means a retry failed with
`auth_rejected`, `no_subscription` or `unsupported_os`, or the `always` kill switch is holding the network. Calling
`connect` in `reconnecting` or a failure-blocked state retries immediately; from `blocked` with `kill_switch`, it
starts a normal connect with the network held. Calling `disconnect` stops retries; in `always` it leaves the network
held and reports `blocked` with `kill_switch`, otherwise it opens the network. A first
user-initiated `connect` failure ends in `error` with the network open, except in `always`, where it ends in `blocked`
with the attempt's error code.

Settings are saved as plain JSON in `<data directory>\settings.json`; a missing or broken file starts with defaults.
`kill_switch` is `off`, `while`, or `always` (default `while`); `lan` allows private and link-local addresses through
the kill switch (default `true`); `protocol` is `auto`, `hysteria2`, or `awg` (default `auto`); `game` prefers AWG
when protocol selection is automatic (default `false`). `settings.set` accepts only these keys, updates only the keys
provided, and returns `bad_params` for an unknown key or invalid value. Changes apply immediately to the active
firewall policy and are pushed to subscribers of `settings` as a Settings object. When `connect.protocol` is omitted
or `auto`, automatic selection uses the configured `protocol`; when that is also `auto`, `game: true` prefers AWG if
the selected subscription has one. A concrete server id always uses that server's protocol.

| `kill_switch` | connected | tunnel died / retrying | off or first connect failed | service start |
|---|---|---|---|---|
| `off` | DNS rules only | network open; retries are unheld | open | open |
| `while` | full rules | held | open | open |
| `always` | full rules | held; failed attempt becomes `blocked` | held; `blocked` with failure code or `kill_switch` | held at once |

`off` still denies DNS outside the tunnel's resolvers while connected. `lan: false` removes the local network permits
from full rules, including while held. `always` uses the dynamic WFP session, so its rules start when the service
starts and disappear if the service crashes. The network is open from boot until service startup and after a crash;
persistent firewall rules are not installed. A console run has no service SID, so Windows rejects the rules with
`ERROR_NO_SUCH_GROUP`; it cannot hold the network. It warns once and reports ordinary `off` or `error` status instead
of claiming the network is blocked.

Events: `status` (a Status, on every change), `traffic` (`{"rx_bps": 0, "tx_bps": 0, "rtt_ms": 0}`, once a second while
connected), `log` (`{"t_unix_ms": 0, "level": "info", "msg": "…"}`), `subs` (`{"subs": [Subscription…]}`)
after subscription data changes, and `settings` (a Settings object) after settings change. Subscribe to `subs` or
`settings` to receive those updates.

Subscription errors use `bad_link`, `insecure_link`, `no_servers`, `unsupported_format`, `offline`,
`fetch_failed`, and `unknown_subscription`. `connect` returns `no_subscription` if the selected subscription or
server is no longer present. Removing a subscription does not stop an active tunnel; a later reconnect or connect
must select a server that still exists.

The service stores subscriptions in `<data directory>\subscriptions.bin`. On Windows the JSON state is protected
with DPAPI for the service account, and the data directory has a protected ACL granting access only to SYSTEM and
Administrators. URLs, server links and AWG configs are stored there; IPC subscription objects contain no secrets.

## Running it by hand

For a real connection, run `mistgate-clientd run -data "%ProgramData%\Mistgate"` from an elevated console. Put
`wintun.dll` version 0.14.1 from [wintun.net](https://www.wintun.net/) beside `mistgate-clientd.exe`. The data
directory defaults to `%ProgramData%\Mistgate`. `-verify host:port` overrides the tunnel verification target for
development and the test stand; normally the service tries `1.1.1.1:443` and then `8.8.8.8:443`.

Add a panel URL, pasted links, or an AmneziaWG config through the trusted pipe, for example:

```json
{"id": 1, "method": "subs.add", "params": {"text": "https://panel.example/subscription/<token>"}}
```

The response contains the subscription id and its server ids. Use those ids in `connect`; `sub` can restrict `auto`
selection to one subscription.

The window only talks to a `mistgate-clientd.exe` that sits in its own directory, so for a development run copy the
service beside the window binary (`ui/src-tauri/target/debug/`). `run -fake -data <directory>` uses the fake engine
and does not need `wintun.dll`.

## The kill switch and the Windows service

`mistgate-clientd install [run flags]` (elevated) registers the binary as the LocalSystem service `MistgateClient`
with an unrestricted service SID and starts it; `mistgate-clientd uninstall` stops and removes it.

With `while` or `always`, the firewall (WFP, a dynamic session) lets through only the tunnel adapter, loopback, DHCP
and NDP, optionally the local network (private and link-local ranges; not its DNS), the service's own sockets, and
DNS to the tunnel's resolvers. With `off`, a connected tunnel keeps only its DNS rules. The rules name the service
SID, so a console run cannot install them. The dynamic session ends with the process, so a service crash opens the
network.

## Auto-connect

`settings.set {"autoconnect": true}`: when the service starts it connects to the target of the last `connect` call
(the service keeps it as `last_server` / `last_sub` in the settings). The window's half of "connect when Windows
starts" is its own: it puts itself into the user's Run key.
