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
| `subscribe` | `{"events": ["status", "traffic", "log", "subs", "settings", "diag", "routes"]}` | `{}`; the events then arrive on this connection |
| `subs.list` | — | `{"subs": [Subscription…]}` |
| `subs.preview` | `{"text": "<URL, links, or AWG config>"}` | Subscription, not saved (`id` is empty) |
| `subs.add` | `{"text": "<URL, links, or AWG config>"}` | Subscription |
| `subs.refresh` | `{"id": "<subscription id>"}` | Subscription |
| `subs.remove` | `{"id": "<subscription id>"}` | `{}` |
| `settings.get` | — | Settings |
| `settings.set` | the settings keys to change | Settings |
| `routes.get` | none | Route state, rules, and named collection status |
| `routes.set` | `{"direct": Selection, "vpn": Selection}` (either key may be omitted) | The `routes.get` object |
| `diag.run` | `{"sub": "<subscription id>"}` (optional; empty selects the first subscription) | Diagnostic State |
| `diag.get` | none | Diagnostic State |
| `diag.cancel` | none | Diagnostic State |
| `log.get` | none | `{"entries": [LogEntry...]}`; at most the latest 500 entries |

Status:

While connecting, `server` and `protocol` reflect the request. Once connected, they hold the profile name and
protocol that are actually in use.

```json
{"state": "off", "step": "", "since_unix": 0, "server": "", "protocol": "", "route": "", "error": ""}
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
when protocol selection is automatic (default `false`); `route_mode` is `all`, `smart`, or `selected` (default `all`), and
`route_region` is `auto`, `none`, or a two-letter lower-case country code (default `auto`). `settings.set` accepts only these keys, updates only the keys
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

Routing: `all` sends all connections through the VPN. `smart` sends IPv4 connections to addresses in the selected
region directly over the physical network and sends other addresses through the VPN. `none`, an unavailable region
list, or an unresolved `auto` selection behaves as `all`. Private, loopback, link-local, multicast and port 53 DNS
flows stay out of the direct path. Routing uses addresses only: it does not inspect site names or choose by application,
and it does not route IPv6 directly.

Country lists are fetched from `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/<cc>.list`,
with `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/<cc>.list` as the fallback. Plain cached
files are kept at `<data directory>\geo\<cc>.list` and refreshed after 24 hours over ordinary sockets, so refreshes
use the VPN when it is connected. A stale list remains in use if refresh fails. For `route_region: "auto"`, the
service checks one STUN answer against `ru`, `by`, `kz`, `cn`, `ir` and `tr`. The public address is used only for that
local country lookup, then discarded; it is never stored, logged or returned.

`routes.get` and the `routes` event share this object: `mode` and `region` are the configured settings; `effective`
is the selected country (`none` when auto has no match), `selected` in selected mode, or `none` in all mode;
`available` reports whether the smart-mode region list is cached; `entries` is the number of IPv4 prefixes in that
list; and `updated_unix` is the cached file time, or `0` when no file exists. `rules` has `direct` and `vpn`
selections, each with `collections` and `sites` arrays. `collections` reports each named collection's `id`,
`available` (whether a valid cached list is present), `entries` (the number of valid unique domains), and
`updated_unix`.

In `all`, all public destinations use the VPN. In `smart`, a public destination uses the direct path when its site
matches `rules.direct` or its address is in the selected region; other destinations use the VPN. In `selected`, a
public destination uses the VPN only when its site matches `rules.vpn`; all other destinations use the direct path.
An unknown site is decided by address alone: smart uses the region list, while selected uses the direct path. DNS
to port 53 always uses the VPN. Private, loopback, link-local, multicast, and unspecified destinations always use
the VPN. Existing flows keep their chosen path; rule updates and list refreshes affect new flows immediately.

Each selection accepts at most 200 collections and 500 sites. A collection is `geosite:<name>` (lower-case letters,
digits, `!`, `@`, and `-`, up to 48 characters) or `list:<https URL>` (up to 512 URL characters, HTTPS only, no
credentials). GeoSite collections are fetched from MetaCubeX with a jsDelivr fallback. Lists are limited to 8 MiB,
fetched with a 20-second timeout, cached in `<data directory>\geo\` for 24 hours, and refreshed in the
background; a valid stale cache remains usable while refreshing. A site is a hostname whose labels contain letters,
digits, or hyphens. An HTTPS URL such as `https://Example.com/x` is accepted and stored as `example.com`. Sites
are lower-cased, a trailing dot is removed, and matching includes subdomains. IDNs may be entered as UTF-8 or
punycode and are stored in that form after lower-casing. Invalid route data and over-limit selections return
`bad_params`.

Site list lines may be bare (`example.com`), dot-prefixed (`.example.com`), wildcard-prefixed
(`*.example.com`), or plus-wildcard-prefixed (`+.example.com`). All four forms include the name and its
subdomains; a bare TLD such as `.ua` matches that TLD and its subdomains. Blank lines, `#` and `//` comments, and
invalid lines are skipped. A list with no valid domain is refused.

For TCP to ports 80 and 443, the forwarder reads at most 4 KiB for up to 300 ms when site rules are configured. It
uses an HTTP `Host` header or TLS ClientHello SNI, then replays the bytes to the chosen exit. Other TCP ports, UDP,
and QUIC use names learned from A answers to UDP DNS responses passing through the forwarder; names are retained
for the answer TTL clamped to 60 seconds through 1 hour, in a cache capped at 50,000 addresses. Encrypted DNS is
not visible here; QUIC without a known DNS name cannot be matched; and ECH can hide the actual TLS server name.
Site names, DNS questions, and destination addresses are never logged.

`status.route` is `all`, `smart:<cc>` when a smart region list is available, `smart` when it is not, or `selected`.
Changing route rules or refreshing a list does not reconnect. An AmneziaWG session reconnects with the network held
only when switching between its native path in `all` and its forwarder path in `smart` or `selected`.

Events: `status` (a Status, on every change), `traffic` (`{"rx_bps": 0, "tx_bps": 0, "rtt_ms": 0}`, once a second while
connected), `log` (`{"t_unix_ms": 0, "level": "info", "msg": "…"}`), `subs` (`{"subs": [Subscription…]}`)
after subscription data changes, `settings` (a Settings object) after settings change, and `routes` (the same object
as `routes.get`) after any route state changes. Subscribe to `subs`, `settings` or `routes` to receive those updates.

Subscription errors use `bad_link`, `insecure_link`, `no_servers`, `unsupported_format`, `offline`,
`fetch_failed`, and `unknown_subscription`. `connect` returns `no_subscription` if the selected subscription or
server is no longer present. Removing a subscription does not stop an active tunnel; a later reconnect or connect
must select a server that still exists.

The service stores subscriptions in `<data directory>\subscriptions.bin`. On Windows the JSON state is protected
with DPAPI for the service account, and the data directory has a protected ACL granting access only to SYSTEM and
Administrators. URLs, server links and AWG configs are stored there; IPC subscription objects contain no secrets.

The `diag` event sends the full Diagnostic State after each state or progress change. Log events include `src` in the
same shape returned by `log.get`. `log.get` returns `{"entries": [...]}` with entries shaped as
`{"t_unix_ms": 0, "level": "info", "msg": "...", "src": "ipc"}`.
The log ring is in memory only and holds at most 500 entries. `src` is `ipc`, `session`, `engine`, `diag`, or `subs`.

## Network check

`diag.run {"sub": "<id>"}` checks every profile in that subscription; omit `sub` or pass an empty string to use the
first subscription. A second run while one is active returns the current state. `diag.cancel` stops the active run.
`diag.get` reads the current state and the last successful result. Failed and cancelled runs leave that result in
memory for the next read.

The State shape is:

```json
{"state":"running","step":2,"pct":40,"error":"","result":null}
```

`state` is `idle`, `running`, `done`, or `failed`. While running, `step` is 0 (`servers`) through 4 (`foreign`);
step 1 (`route`) is skipped in this slice. `pct` advances through the check. A failed state has `error` `offline`,
`no_subscription`, or `cancelled`.

A completed `result` has this shape:

```json
{
  "at_unix": 0,
  "sub": "subscription id",
  "network": {"kind": "wifi"},
  "servers": [{"id":"server id","name":"server name","protocol":"hysteria2","verdict":"ok","reason":"","rtt_ms":0}],
  "udp": {"verdict":"ok"},
  "nat": {"verdict":"open"},
  "dns": {"verdict":"ok","checked":8,"replaced":0},
  "foreign": {"verdict":"ok","total":10,"open":10}
}
```

The physical network kind is `wifi`, `ethernet`, `mobile`, or `other`. `servers` contains one entry per profile in
the selected subscription. Server verdicts are `ok`, `blocked`, `down`, `config`, or `app`; reasons are
`udp_no_answer`, `no_answer`, `not_found`, `auth_rejected`, `bad_config`, and `engine_error`. `rtt_ms` is populated
for successful handshakes.

`udp.verdict` is `ok` when STUN or a UDP server answered, `blocked` when neither answered but a TCP check or a server
host check succeeded, and `unknown` otherwise. `nat.verdict` is `open` when both STUN servers report the same mapped
port, `limited` when their ports differ, and `unknown` when fewer than two answer. `dns.verdict` is `ok`, `replaced`,
or `unknown`; `checked` counts names compared with a trusted DoH answer and a local DNS response, and `replaced`
counts names where DoH returns addresses but local DNS gives NXDOMAIN, no A answer, a listed bogon, or the same
single address as another name. Ordinary address differences such as CDN answers do not count as replacement.
`foreign.verdict` is `ok` when at most one TLS check fails, `cut` when at least two
fail and one opens, and `unknown` when none opens. If none of the foreign TLS checks opens, `udp` and `dns` are also
reported as `unknown`.

“Outside the tunnel” means each diagnostic socket selects the physical IPv4 default-route interface, even while a
VPN tunnel is active. AmneziaWG handshake sockets use the same interface. The check does not add tunnel routes; the
service's existing kill-switch allowance for its own sockets lets these probes leave beside the tunnel.

Diagnostic results and logs contain verdicts, counters, and timings only. They do not include authentication values,
keys, subscription links, profile configs, or the machine's public address; the STUN address is discarded after its
mapped port is read. Checks in this slice do not measure route hops, speed, throttling, or Wi-Fi quality.

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

## The route step of the network check

`result.route` is `{verdict: ok|blocked|unknown, hop, total}`: `blocked` means packets to addresses that are certainly
blocked (Russia's references, as in the panel's TSPU probe) die behind hop `hop - 1` while a control address passes
on; `ok` means a blocked reference reached its end in `total` hops; `unknown` when the method does not apply or the
VPN is up (the step is skipped then). The probes are ICMP echoes with a TTL, sent through the system's ICMP
interface.

## Auto-connect

`settings.set {"autoconnect": true}`: when the service starts it connects to the target of the last `connect` call
(the service keeps it as `last_server` / `last_sub` in the settings). The window's half of "connect when Windows
starts" is its own: it puts itself into the user's Run key.
