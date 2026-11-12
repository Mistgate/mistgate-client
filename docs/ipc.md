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

The window checks the other end too. The installed service runs as LocalSystem, and Windows does not let an ordinary
program open such a process to read its path; so the service names LocalSystem the pipe's owner, and the window
trusts a pipe with that owner (a program without those rights that takes the pipe name first cannot be that owner).
A console service (development) runs as the user: there the window reads the server's path and wants
`mistgate-clientd.exe` in its own directory, or the path in `MISTGATE_DEV_SERVICE` (debug builds only).

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
| `subs.preview` | `{"text": "<URL, links, Mihomo profile, or AWG config>"}` | Subscription, not saved (`id` is empty) |
| `subs.add` | `{"text": "<URL, links, Mihomo profile, or AWG config>"}` | Subscription |
| `subs.refresh` | `{"id": "<subscription id>"}` | Subscription |
| `subs.remove` | `{"id": "<subscription id>"}` | `{}` |
| `subs.link` | `{"id": "<subscription id>"}` | `{"url": "<link the user pasted>"}`; `no_link` for a subscription that is not a `url` one |
| `servers.ping` | `{"sub": "<subscription id>", "servers": ["<server id>", …]}` (both optional; empty `sub` selects the first subscription, empty `servers` means all of its servers) | `{"rtt": {"<server id>": <ms>, …}}` |
| `servers.hosts` | `{"sub": "<subscription id>"}` (optional; empty selects the first subscription) | `{"hosts": {"<server id>": {"host": "<name or address>", "ips": ["<address>", ...]}}}`; `ips` are the addresses the name has now (empty for an address or a name that did not resolve in 2 s). For the hint on a server row; never logged |
| `settings.get` | — | Settings |
| `settings.set` | the settings keys to change | Settings |
| `proxy.get` | none | ProxyState (see "The local proxy"); carries the password |
| `proxy.password` | none | ProxyState, after a new password was made and the connections from other machines were cut |
| `routes.get` | none | Route state, rules, and named collection status |
| `routes.update` | none | The `routes.get` object as it is now; the downloads go on in the background and a `routes` event follows when they end |
| `routes.lists` | none | `{"lists": [{"id": "<list id>", "entries": N, "updated_unix": N, "error": "<code>"}], "unique": N, "duplicates": N}` |
| `routes.set` | `{"direct": Selection, "vpn": Selection, "block": Selection}` (any key may be omitted; an omitted one keeps what is stored) | The `routes.get` object |
| `routes.check` | `{"site": "<name>"}`; a host name or an https URL of one, checked like a site entry | `{"route": "direct" \| "vpn" \| "block", "by": "mode" \| "site" \| "collection" \| "region" \| "default", "rule": "<entry or collection id>", "dns": "direct" \| "vpn"}` |
| `routes.dismiss` | `{"route": "direct" \| "vpn", "site": "<name>"}`; `route` is the `suggest` list the site was in | The `routes.get` object |
| `diag.run` | `{"sub": "<subscription id>"}` (optional; empty selects the first subscription) | Diagnostic State |
| `diag.get` | none | Diagnostic State |
| `diag.cancel` | none | Diagnostic State |
| `log.get` | none | `{"entries": [LogEntry...]}`; at most the latest 500 entries |

Status:

`connect` with server `auto` makes one handshake to every server the settings allow and takes the one that answers
soonest (the first of the list when none answers). `server_id` is the id of the server in use while connected: names
repeat, ids do not.

While connecting, `server` and `protocol` reflect the request. Once connected, they hold the profile name and
protocol that are actually in use.

```json
{"state": "off", "step": "", "since_unix": 0, "server": "", "server_id": "", "protocol": "", "route": "", "error": ""}
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

With `on_server_down: "reconnect"` (default) every retry targets the same server. With `"next"`, a `reconnecting`
session that fails two attempts in a row on one server sends its next attempt to the next server of the same
subscription (the order of the subscription's list, wrapping around), and again after every two failures; `status.server`
shows the server being tried. Servers the `protocol` setting rules out are skipped; the server the user chose is always in
the round, so after every server has had its two attempts the round starts again from it. The backoff keeps growing
across switches. `auto` stands for the server automatic selection picks (the first match of the subscription and
protocol), so it moves on from there too. A single server has no next one and is retried.

With `"fastest"` the trigger is the same (two failed attempts in a row on one server), but the third attempt first
sends a handshake to every other server of the round (the same set `"next"` walks, outside the tunnel, all at once,
3 s each) and goes to the one that answered with the smallest round trip. If none answers, it goes to the next server in
list order, as `"next"` does. `status.server` shows the new server once that attempt has finished (the pick itself takes
up to 3 s). Everything else in the paragraph above holds. This applies only to retries
of a session that was connected or is reconnecting, never to the first `connect`, and it does not change the user's choice:
`last_server` stays, and a `connect` call goes to the server it names (an omitted or `auto` server in `reconnecting`
means the user's original choice, not the one the retries moved to).

Settings are saved as plain JSON in `<data directory>\settings.json`; a missing or broken file starts with defaults.
`kill_switch` is `off`, `while`, or `always` (default `while`); `lan` allows private and link-local addresses through
the kill switch (default `true`); `protocol` is `auto`, `hysteria2`, or `awg` (default `auto`); `game` prefers AWG
when protocol selection is automatic (default `false`); `route_mode` is `all`, `smart`, or `selected` (default `all`), and
`route_region` is `auto`, `none`, or a two-letter lower-case country code (default `auto`). `settings.set` accepts only these keys, updates only the keys
provided, and returns `bad_params` for an unknown key or invalid value. Changes apply immediately to the active
firewall policy and are pushed to subscribers of `settings` as a Settings object. When `connect.protocol` is omitted
or `auto`, automatic selection uses the configured `protocol`; when that is also `auto`, `game: true` prefers AWG if
the selected subscription has one. A concrete server id always uses that server's protocol.

Connection settings added after the first ones (all keys of `settings.get` / `settings.set`):

| Key | Values | Default | Meaning |
|---|---|---|---|
| `on_server_down` | `reconnect`, `next`, `fastest` | `reconnect` | What the retries do when the server stays down: keep trying the same server, move to the next server of the subscription, or move to the one that answers soonest (see the reconnect text above) |
| `restore` | `true`, `false` | `false` | Bring the VPN back when the service starts if it was on when the service stopped (see Auto-connect) |
| `dns` | `auto`, or one or two IP addresses joined with a comma | `auto` | The tunnel's DNS servers. `auto` takes the first that exists of: the profile's own (AmneziaWG), the panel's (managed subscriptions, see "The panel's DNS"), `1.1.1.1` and `1.0.0.1` |
| `mtu` | `0`, or `1280` to `1500` | `0` | The tunnel adapter's MTU. `0` is automatic |
| `proxy` | `true`, `false` | `false` | The local proxy (SOCKS5 on 1080, HTTP on 8080, this machine only); see "The local proxy" |
| `proxy_lan` | `true`, `false` | `false` | Let the devices of the home network use the proxy too; does nothing while `proxy` is off |

`dns` takes one or two valid IPv4 or IPv6 addresses (no port, not unspecified, not loopback); a value is stored
normalised (`netip.Addr` text, joined with `,`), and anything else is `bad_params`. The servers are reached through the
tunnel like any other destination, in both protocols and every route mode; they are the adapter's DNS and the only DNS
the kill switch lets out. `mtu` replaces the adapter's value in both protocols (Hysteria2 otherwise uses 1500). For
AmneziaWG the adapter gets the smaller of `mtu` and the profile's own MTU (1280 when the profile has none), because
a size above the one the server expects only breaks packets. Changing `dns` or `mtu` while connecting, connected or
reconnecting restarts the attempt with the network held, like a change of the AmneziaWG path (the status goes
`reconnecting`); with no tunnel it applies to the next connect.

`last_server`, `last_sub` and `last_on` are kept by the service for Auto-connect and `restore`: `connect` sets
`last_on: true` and `disconnect` sets it `false`. They are ordinary keys of `settings.set` too, but the window has no reason
to write them.

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
list; and `updated_unix` is the cached file time, or `0` when no file exists. `rules` has `direct`, `vpn` and `block`
selections, each with `collections` and `sites` arrays. `collections` reports each named collection's `id`,
`available` (whether a valid cached list is present), `entries` (the number of valid unique domains), and
`updated_unix`, for the collections of all three selections. `block_active` is `true` in `smart` and `selected` and
`false` in `all`: the block lists work only where the forwarder runs (see "Blocking by name").

`routes.update` downloads again, whatever their age, the region list of the effective region (when it is a country) and
every collection that `rules.direct`, `rules.vpn` and `rules.block` name, all at once and within 60 seconds in all. A list
that fails does not stop the others: it keeps its old copy in use and its error (below). A call made while another runs
waits for it and downloads nothing. The call does not wait for the downloads: the answer is the `routes.get` object as it
is, and the `routes` event fires when they end, as after any list refresh. `routes.lists` downloads nothing: `lists` has one row per list in use, `region:<cc>` for the region list of the
last `routes` state (`entries` is its number of IPv4 prefixes) and the collection ids as in the rules (`geosite:<name>`,
`list:<url>`; `entries` is the number of domains). `updated_unix` is the time of the last good download (the cached file's
time; `0` when there is none). `error` is the code of the last failed download, empty when the last one worked:
`fetch_failed` (no answer, or not `200`, or too large), `bad_list` (an answer that is not a valid list) or
`write_failed`; it never holds a URL or server text. `unique` is the number of distinct domains over all the collections
together (the region list is not counted) and `duplicates` is the sum of their `entries` minus `unique`.

`suggest` is the "Doesn't open?" part of the same object: `{"vpn": [{"site": "example.com", "count": 3}], "direct": [...]}`.
`vpn` lists sites that failed on the direct path and could go through the VPN; `direct` lists sites that failed
through the VPN and could go direct. Both are arrays (empty, never `null`), at most 10 sites each, most failures first,
and always empty in `all`. `site` is the registrable domain (public-suffix list), lower case. A failure is a TCP flow to
port 443 with a TLS server name that (a) could not be dialed on its exit (not because the app closed), (b) was closed
or reset by the site before one byte came back, or (c) got nothing back for 10 seconds (the flow is left alone). A flow
that gets a byte is a success: it clears that site's failures on that exit. A failure counts only if the same exit
answered another flow within the 60 seconds before it or the 15 seconds after it, so a dead network or a dead VPN
produces nothing. A site is offered with 3 or more counted failures in 24 hours and no success on that exit since the
first of them. It is not offered when `rules.direct.sites` or `rules.vpn.sites` already lists it (or a name under or
above it), or when a list of the side it would move to already matches it; a collection on the other side may be
overridden. Adding the site with `routes.set` therefore removes it from `suggest`. `routes.dismiss` forgets the site and
keeps it out of that list until the service stops; an invalid `route` or `site` returns `bad_params`. At most 200 sites
are tracked (the oldest are dropped). The `routes` event also fires when `suggest` changes, at most once every 5
seconds.

Privacy: the names of failed sites live only in the service's memory, in one small structure. They are never logged,
never written to disk and never put into errors or the log; they leave only in `suggest`, to a trusted caller, and are
gone when the service stops. Successful flows keep one time stamp per exit and no name. To read the TLS name, port 443
flows are read first (as for port 80) in `smart` and `selected` even without site rules.

In `all`, all public destinations use the VPN. In `smart`, a public destination uses the direct path when its site
matches `rules.direct` or its address is in the selected region; other destinations use the VPN. In `selected`, a
public destination uses the VPN only when its site matches `rules.vpn`; all other destinations use the direct path.
An unknown site is decided by address alone: smart uses the region list, while selected uses the direct path. DNS
to port 53 uses the VPN, except the questions of regional DNS below. Private, loopback, link-local, multicast, and
unspecified destinations always use the VPN. Existing flows keep their chosen path; rule updates and list refreshes
affect new flows immediately.

### Regional DNS

In `smart` and `selected` the forwarder reads every UDP DNS question (port 53) once: one question, class IN, type A,
AAAA or HTTPS, no answer records, a name of letters, digits and hyphens. Any other packet (other types, TCP, a name
with `_`, junk) travels as before. A question whose name *goes direct* is sent outside the tunnel to a resolver of the
region instead of the address the app asked, so that a site of the user's own region gets an address chosen for the
user's own network and not for the VPN's exit country. The answer returns to the app on the same flow, as if from
the address it asked, and is remembered like any other answer (the names learned from DNS for QUIC and other ports).

A name goes direct when: in `smart`, it matches `rules.direct`, or the effective region has its own top-level domains
and the name is under one; in `selected`, it does not match `rules.vpn`. Block wins over both (below). The
decision is the same code that routes flows (`rules` by name), with no address.

Regions: `ru` (resolvers `77.88.8.8`, `77.88.8.1`; top-level domains `ru`, `su`, `рф`, `москва`, `дети`), `by`
(the `ru` resolvers; `by`, `бел`), `cn` (`223.5.5.5`, `119.29.29.29`; `cn`, `中国`), `ir` (no resolver; `ir`).
A resolver given by the panel for the region replaces the table's. Without a resolver for the region (`none`, an
unknown region, `ir`, `auto` not yet detected, a `selected` mode whose `route_region` is `auto`), and with `all`,
nothing changes: the question goes through the VPN. In `selected` the region is the configured `route_region` (or the
detected one), used only to pick the resolver.

If the resolver does not answer within 2 seconds, the same question is sent through the VPN, so the app never loses
DNS to a resolver that is blocked on this network; after one such silence, or a failed send, regional resolvers rest for 30
seconds and every question goes through the VPN. An answer counts only with the same id and the same question; a late
answer after the fallback is dropped. The kill switch limits DNS to the tunnel's resolvers for other programs; the service's own
sockets are exempt in every kill switch mode, and in a console run there is no firewall.

Privacy: questions and names are not logged, not stored and not put into errors.

### Blocking by name

`rules.block` (a selection like the other two, saved in `routes.json`; an older file without it loads as empty)
lists names to block, ads for instance. In `smart` and `selected` a DNS question handled as above whose name
matches (the name or a subdomain, as for the other lists) is answered by the service itself with the unspecified address (`0.0.0.0` for A, `::` for AAAA, TTL 60 s; no data for
HTTPS) and goes nowhere, whether or not the name would go direct. It is not `NXDOMAIN`: Windows then walks its suffix
search list over every adapter and the app waits for seconds. A name that goes direct gets no AAAA answer (no data)
when the machine has no IPv6 route beside the tunnel, and a direct decision for an IPv6 address then falls to the VPN:
the app would otherwise connect to an address the flow cannot reach, and would not fall back to IPv4.
A TCP flow to port 80 or 443 whose sniffed name matches is closed without a dial. Block wins over `direct` and `vpn`.
Flows that never show a name (other ports, QUIC) are not blocked by name. In `all` there is no forwarder:
block does nothing (`block_active` is `false`).

### Where a site goes

`routes.check {"site": "example.com"}` answers what the forwarder would do with that name now, by the same code
as a flow (no lookup, no network): `route` is `direct`, `vpn` or `block`; `by` is `mode` (the `all` mode; always
`vpn`), `site` (an entry of the matching selection, named in `rule`), `collection` (the collection id in `rule`),
`region` (the name is under the effective region's own top-level domain; `rule` is empty) or `default`; `dns` says
where the question goes: `direct` when `route` is `direct` and a regional resolver is known, otherwise `vpn` (a
blocked name's question is answered by the service and reported as `vpn`). In `smart`, `vpn` with `default`
means that no rule names the site: the address of the flow still decides, so it may go direct. A name under a
region's top-level domain is `direct` by `region` here because its question goes direct; the flow itself still follows
the address list. `selected` reports `direct` with `default` for names that match no `rules.vpn`. A bad name is `bad_params`.
The answer is not logged.

### The panel's DNS

For a managed subscription each `sync` carries a `dns` object (`docs/client-api.md`). The service keeps, with the
subscription, the plain resolvers only: from `dns.servers` the entries with transport `plain` (the `address` when it is
an IP, or an IP with port 53, else the entry's `ips`), at most two, and, when `split_direct` is true, for every entry of
`dns.split` its `geo` codes and its plain resolvers (at most two). DoT and DoH entries and other ports are skipped. A
sync without `dns`, or with a status other than `active`, clears them. They are not part of the `Subscription` object.
The tunnel's DNS is the first that exists of: the user's `dns` setting, the profile's own servers (AmneziaWG), the panel's
`dns.servers`, `1.1.1.1` and `1.0.0.1`. A split entry whose `geo` contains the effective region gives that region's
resolver in place of the table's. Both are read when the tunnel starts (a new `sync` applies to the next connect).

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

For TCP to ports 80 and 443, the forwarder reads at most 4 KiB for up to 300 ms when site rules are configured (port 443 also in `smart` and `selected` without them, for `suggest`). It
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

`subs.link` returns the link of a `url` subscription, so the window can open its page or copy the link. The link holds the
subscription token: the service never logs it, and the other kinds (pasted server links, AmneziaWG configs) answer
`no_link`. `servers.ping` makes one handshake to each server outside the tunnel, at most 8 at a time, and gives the round
trip in whole milliseconds (at least 1). A server that does not answer within 3 seconds, or is not in the subscription,
is left out of `rtt`; the whole call stops after 20 seconds. An unknown `sub` answers `unknown_subscription`.

Subscription errors use `bad_link`, `insecure_link`, `no_servers`, `unsupported_format`, `refused`, `offline`,
`fetch_failed`, `unknown_subscription`, and `no_link` (`subs.link` only); managed subscriptions add the codes below. `connect` returns `no_subscription` if the selected subscription or
server is no longer present. Removing a subscription does not stop an active tunnel; a later reconnect or connect
must select a server that still exists.

The service stores subscriptions in `<data directory>\subscriptions.bin`. On Windows the JSON state is protected
with DPAPI for the service account, and the data directory has a protected ACL granting access only to SYSTEM and
Administrators. URLs, server links, profile proxies and AWG configs are stored there; IPC subscription objects contain
no secrets. URL fetches send `User-Agent: mihomo/1.19.33 Mistgate/0.0.1 (Windows)` with `x-hwid` and `x-device-os` so
panels that recognize Mihomo return their full client profile. A URL body may be the usual plain or base64 link list,
or a Mihomo YAML profile with a top-level `proxies` list. Only `proxies` is used; groups, rules and DNS are ignored
because Mistgate applies its own routing. Supported proxies are Hysteria2 and WireGuard with or without
`amnezia-wg-option`; other types are counted as unsupported.

A server of a panel's client API also carries its place in the panel's structure: `node` (the paths of one node share
it), `country` (code), `city`, `via` (`direct`, `relay` or `warp`), `ipv6`, `load` (`low`, `medium`, `high`, or absent) and, for AmneziaWG, `version`
(`2.0`, `3.1`). The window draws one row per node and
lists the node's paths as its protocols. Other subscriptions have only `id`, `name` and `protocol`; the window then
groups by the first part of the name, which is a guess.

Subscriptions expose `notice` (empty when the panel sent no message), the panel's `Announce` response header decoded
from plain text or `base64:<value>`.
Port hopping is accepted from Hysteria2 `ports: "from-to"` profiles and the `mport` or `host:from-to` link forms;
`hop-interval` is in seconds. If every profile proxy uses a refusal endpoint (`0.0.0.0`, `127.0.0.1`, `::`, or port
0/1), the refresh fails with `refused`, its first proxy name becomes `notice`, and existing servers are kept. A first
add also fails with `refused`; the RPC error message carries the notice.

**Managed subscriptions** (`docs/client-api.md`). Every URL fetch also sends `X-Mistgate-Caps`. When the plain answer
carries `Mistgate-Client-Api: 1`, `subs.add` and `subs.refresh` enrol this device (`POST <link>/client/enrol`, with a
device key the service makes and saves first) and take the servers from `sync`; the subscription then has
`managed: true` and refreshes only through `sync`, on the panel's interval (at least 10 minutes, plus up to 10%
random wait) and after `Retry-After`. `subs.preview` never enrols. Servers are one per path; their `id` is the path's
id and their name is the city (else the country) plus ` · relay`, ` · warp` or ` · IPv6`. `subs.remove` of a managed
subscription calls `leave` first (5 s; whatever it answers, the subscription is removed). The hwid sent as `X-HWID` and
in `enrol` is per origin of the link once the origin has been enrolled; other origins keep the install id. Secrets
(device key, base URL, paths with their credentials) are kept only in the protected store; `Subscription` carries
`managed` and nothing else new.

A managed subscription reports its state in `error`; `subs.refresh` also returns it as the RPC error, except
`inactive` and the enrol codes. What the window should say:

| `error` | `managed` | Servers | Automatic refresh | The window says |
|---|---|---|---|---|
| `offline`, `fetch_failed` | any | kept | goes on | Cannot reach the panel; the saved servers still work |
| `unsupported_format` | true | kept | goes on | This panel is newer than the app; update the app |
| `inactive` | true | none | goes on | The subscription is not active; `notice` is the panel's text or the status (`disabled`, `expired`, `limited`) |
| `app_disabled` | true | none | goes on | The owner switched the app off for this person; the device stays, and the servers return by themselves when it is switched on |
| `link_changed` | true | kept | stopped | The panel's link has changed; add the new link (same panel) to keep this one |
| `device_blocked` | true | none | stopped | This device is blocked by the owner |
| `device_removed` | false | none | stopped | This device was removed; refresh to enrol again |
| `device_exists`, `device_limit`, `device_blocked`, `user_inactive`, `app_disabled`, `client_api_off` | false | the plain ones | stopped | The panel did not accept this device (the code says why); refresh by hand to try again |

The last row is an enrol that the panel refused: the subscription stays in basic mode with the servers of the plain
answer. Any other enrol or first-sync failure also leaves basic mode with `fetch_failed` or `offline` in `error`, and
is repeated with the same device key at the next refresh. Adding a link of the same panel while a subscription is in
`link_changed` moves that subscription to the new link (one subscription, not two). Adding a link that is already
managed refreshes it. `unreachable` in the contract is `offline` or `fetch_failed` here.

The `diag` event sends the full Diagnostic State after each state or progress change. Log events include `src` in the
same shape returned by `log.get`. `log.get` returns `{"entries": [...]}` with entries shaped as
`{"t_unix_ms": 0, "level": "info", "msg": "...", "src": "ipc"}`.
The log ring is in memory only and holds at most 500 entries. `src` is `ipc`, `session`, `engine`, `diag`, or `subs`.

## Link guard, sleep, and adapter DNS

While connected, the service probes the tunnel every 10 seconds. After a failed probe it tries again 5 seconds after
that probe ends, continuing at that interval until a probe succeeds or the link is declared dead. A failed streak
starts with its first failed probe; the service reconnects after 20 seconds only if fewer than 1 KiB arrived through
the tunnel since that failure. Receiving at least 1 KiB means the server is alive and restarts the failure streak.
A successful probe also ends the streak. "Arrived through the tunnel" is the adapter's receive counter with AmneziaWG
in `all`, and the bytes read from the VPN side of the forwarder otherwise (the adapter there also carries the answers
of direct flows). The probe's own address always goes through the VPN, whatever the routes say.

When the service process dies, the runtime's last output (the panic and the goroutine stacks) is kept in `crash.log`
in the data directory; the file is started again once it is over 256 KiB.

A default-route or IPv4-gateway interface change triggers a probe immediately. Interface notifications are collapsed
into one change after 1 second without another notification. For 30 seconds after a network change or wake-up, two
consecutive failed probes are enough to reconnect. On resume, the service waits 5 seconds for Windows networking.
If sleep lasted at least 120 seconds, or its duration is unknown, the service reconnects immediately (the network is
held as the kill switch setting says); a shorter sleep uses the network-change probe behavior.

The tunnel adapter's DNS suffix search list is set to `.`. Windows DNS registration, adapter-name registration,
LLMNR, and adapter-name queries are disabled on that adapter. A failure to apply these DNS behaviors is logged once
and does not fail the connection; each new tunnel session reapplies them.

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
  "foreign": {"verdict":"ok","total":10,"open":10},
  "freeze": {"verdict":"ok","targets":[{"name":"cloudflare","bytes":131072,"verdict":"ok"}]},
  "speed": {"verdict":"ok","down_mbps":42.5,"up_mbps":18.3,"first_mbps":44.1,"last_mbps":41.0,"server":"server name"},
  "neighbours": [{"kind":"process","name":"zapret"},{"kind":"driver","name":"WinDivert"},{"kind":"adapter","name":"WireGuard"}]
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

`freeze` is a download test: the first 131072 bytes of a file from each foreign host in `targets` (`name` is a short
label, never an address; `bytes` is how many arrived), next to the same download from a control host that no network
is expected to throttle. Per-target verdicts: `ok` (the whole download arrived), `freeze` (it stalled for 6 s after
1 to 65535 bytes: a device on the way lets the connection start and then stops delivering it, which a reachability
check does not see), `blocked` (nothing arrived and the host never replied: connect, handshake or request refused or
timed out), `unknown` (anything else). The top-level `verdict` is `freeze` if any target froze, else `blocked` if any
was blocked, else `ok` if any completed, else `unknown`. If the control download does not complete, every verdict is
`unknown`: a slow or broken network is not a freeze. The test runs in step 4 beside the foreign check and takes at
most 15 s.

`speed` is the speed of the connection the user actually has, measured through the tunnel with ordinary sockets, so
it runs only while the VPN is up; with the VPN down `verdict` is `skipped` and the numbers are 0. It uses the user's
traffic: a download of up to 8 MiB (stops at 6 s or 8 MiB) and an upload of up to 4 MiB of zeros (stops at 3 s or
4 MiB), about 12 MiB at most, and the stage takes at most 12 s. It runs in step 4, after the freeze test has finished, so
the two do not share the link. `down_mbps` is the download's average in Mbit/s without its first 500 ms (ramp-up),
`first_mbps` and `last_mbps` are the averages of its first and last 2 s, `up_mbps` is the upload's (0 if the host
refused it or the download failed, which skips the upload). All are rounded to one decimal. `server` is what the session
status calls the connected server (the profile's name, or its id when it has no name); empty if unknown. Verdicts:
`ok`; `throttled` (at least 4 s were measured, `first_mbps` is 2 or more and `last_mbps` fell below 0.4 times
`first_mbps`: the speed drops after the first megabytes, as a shaper does it); `failed` (under 64 KiB arrived);
`skipped`. A download that ends early at 8 MiB on a fast link is `ok`: there is nothing to compare. The log line holds
the verdict and the five numbers only.

`neighbours` lists other software on this machine that competes with a VPN client for the same traffic: `kind`
`process` (a known DPI-bypass tool, VPN or proxy core is running), `driver` (the WinDivert packet-interception driver
is running) or `adapter` (another VPN's tunnel adapter, such as WireGuard, Wintun or TAP, is up). `name` is the
product's name as a user knows it; a product appears once, at most 10 entries, the list is empty when nothing is
found and on non-Windows builds. It carries no paths, process ids or command lines. It is read when the run starts.

“Outside the tunnel” means each diagnostic socket selects the physical IPv4 default-route interface, even while a
VPN tunnel is active. AmneziaWG handshake sockets use the same interface. The check does not add tunnel routes; the
service's existing kill-switch allowance for its own sockets lets these probes leave beside the tunnel.

Diagnostic results and logs contain verdicts, counters, and timings only. They do not include authentication values,
keys, subscription links, profile configs, or the machine's public address; the STUN address is discarded after its
mapped port is read. The freeze test counts bytes only; the speed test measures through the tunnel only; no check here measures Wi-Fi quality. The neighbour list holds
product names only.

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

## The local proxy

`settings.set {"proxy": true}` starts a SOCKS5 proxy (port 1080) and an HTTP proxy (port 8080) in the service. Programs
on this PC (or, with `proxy_lan: true`, devices of the home network: a TV, a set-top box, another PC) set them as their
proxy and their TCP traffic goes through the VPN tunnel that is up. `settings.set` answers after the listeners have been
changed, so a `proxy.get` right after it shows the result; the service also follows the settings itself.

`proxy.get` and `proxy.password` answer with the same object (trusted callers only; the password is in it, so it is
never logged and never in a `settings` event):

```json
{"on": true, "lan": false, "host": "192.168.1.5", "socks_port": 1080, "http_port": 8080, "user": "mistgate",
 "password": "k7Hq2mWpXe9RtZ4v", "error": "", "error_port": 0, "clients": 3}
```

`on` and `lan` are the settings in force (`lan` is `proxy_lan` and `proxy`). `host` is this machine's IPv4 address on the
interface the internet is reached through outside the tunnel, when it is a private one (empty otherwise): what to type
into the TV. `password` is empty until the proxy has been switched on once. `error` is empty, or `port_busy` when
another program holds a port (`error_port` says which; the proxy is then not listening at all, and the next
`settings.set` or service start tries again). `clients` is the number of open connections. `proxy.password` makes a
new 16-character password (no `0`, `O`, `1`, `l`, `I`) and closes every connection that did not come from this machine.

Who may connect. By default only `127.0.0.1`. With `proxy_lan` the listeners are on every IPv4 address of the machine,
and a connection is served only from loopback or from a private or link-local address (10/8, 172.16/12, 192.168/16,
169.254/16); any other source is closed at once, without an answer. From this machine no login is needed, but one that
is sent is checked and refused if wrong. From any other address a login is required: user `mistgate` and the password,
as SOCKS5 username/password (RFC 1929) or HTTP `Proxy-Authorization: Basic` (answer 407). A wrong login is answered after
a second; five wrong logins in a minute from one address close its connections without an answer for the rest of
the minute. The password is kept in `<data directory>\proxy.json` (`{"password": "..."}`), next to the settings and in
the directory that only SYSTEM and administrators may open; it is not in `settings.json`. At most 512 connections in all,
64 from one address (256 from this machine), 10 s for the handshake, 15 s to reach the target, and a tunnel with no
data in either direction for 5 minutes is closed.

Where the traffic goes. Only through the tunnel that is up: with no VPN (not connected, still connecting, held) a
request is refused (SOCKS5 reply `0x03`, HTTP `503`), and nothing is ever sent directly. A connection ends with its
tunnel. Names are resolved on the tunnel's side, never by this machine's DNS. Destinations that are loopback,
unspecified, multicast, link-local, private, carrier-grade NAT (100.64/10) or other reserved addresses are refused
(SOCKS5 `0x02`, HTTP `403`), and so is a name that cannot be a public one (no dot, `.local`, `.lan`, `.internal`, a
numeric spelling of an address and the like). A name's addresses are checked after it resolves for AmneziaWG; over
Hysteria2 the server resolves it and the check is the name's shape only.

What it does. SOCKS5: the CONNECT command with IPv4, IPv6 and name addresses; UDP ASSOCIATE and BIND are answered
"command not supported". HTTP: `CONNECT host:port` (a tunnel) and requests with an absolute `http://` URL, forwarded
with the hop-by-hop headers and `Proxy-Authorization` removed; any other request (to the proxy as a web server) gets
`400`. What it does not do: UDP (no console games, no QUIC; browsers fall back to TCP), and the route rules: the smart
and selected modes and the blocked names do not apply to the proxy, everything goes through the VPN.

The Windows Firewall blocks inbound connections by default, so while `proxy` and `proxy_lan` are both on the service adds
the rule `MistgateLocalProxy` (inbound TCP 1080 and 8080, this program only, private and domain profiles, local subnet
only; `netsh advfirewall firewall`), and removes it when either is switched off, when the service stops and in
`uninstall`. The kill switch's own filters let the home network in through the `lan` setting (see above); with `lan:
false` and the kill switch active the devices of the home network cannot reach the proxy.

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

`settings.set {"restore": true}`: when the service starts it connects to the same target if the VPN was on when it
stopped, that is, the last call to `connect` was not followed by `disconnect` (`last_on`). A service stop, a crash
or a shutdown does not clear `last_on`. At start the service connects when `autoconnect`, or `restore` with `last_on`,
and there is a `last_server`.
