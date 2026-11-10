# Mistgate Client API, v1 (DRAFT, not implemented)

How the client and a Mistgate panel talk once the client knows the user's subscription link. It is meant to be
open: another panel may implement it and get the same client. Until a panel answers it, the client works in basic
mode (the plain subscription a link gives to any app, see `docs/ipc.md`).

Status: a proposal from the client side, to be agreed with the panel before either side is built. Open questions
are marked **Q**.

## Principles

- The panel is not on the traffic's path. It hands out configuration and takes reports; when it cannot be reached
  the client keeps working on what it has.
- The subscription link is enough to enrol (as it is enough to download a subscription in any app). Everything after
  enrolment is authorised by a **device key** the panel gives once.
- Private keys never leave the device. For AmneziaWG the client makes the key pair and sends the public half.
- The client never calls the subscription page's own self-service (`<link>/devices` and friends): that is guarded by
  the page password and stays so.
- An unknown token or device key gets what the panel answers to any stranger today (the decoy). There is no
  error that tells a prober the path exists.
- Every request carries `X-Mistgate-Caps` and `User-Agent: Mistgate/<version> (<os>)`.

## Capabilities

`X-Mistgate-Caps: v=1; hysteria2=2; awg=3.1; routes=1; probe=2; debug=1`

A list of `name=version`. The panel does not hand out what is not listed, so a new protocol or feature appears
without a new format version. `v` is this API's version.

## Calls

`<link>` is the subscription link as the user has it. `<base>` is `<link>` with the path the panel chooses for
device calls: **Q** is it `<link>/client/...` for all of them (simplest), or a prefix returned by `enrol`?

| Call | Authorised by | Purpose |
|---|---|---|
| `POST <link>/client/enrol` | the token in the link, the device limit | makes this device |
| `GET <base>/client/sync` | device key | the subscription in the `mistgate` format; `If-None-Match` -> `304` |
| `POST <base>/client/probe` | device key | a detectors' report (v2) |
| `POST <base>/client/debug` | device key | a debug report -> a short code |
| `POST <base>/client/leave` | device key | this device removes itself |

The device key travels as `Authorization: Bearer <device key>`. Bodies and answers are JSON, UTF-8.

### enrol

```json
{
  "hwid": "5f0c…",            // random per install, not derived from hardware (the same value basic mode sends as x-hwid)
  "os": "windows", "os_version": "11 24H2", "model": "", "app_version": "0.1.0",
  "name": "",                 // what the user sees in the device list; empty: the panel names it
  "awg_public_key": "base64"  // omitted when the client has no awg in its caps
}
```
```json
{ "device_id": "d_…", "device_key": "…", "sync_every_s": 600 }
```
- Enrolling again with the same `hwid` returns the same device (a new key replaces the old one): reinstalling must
  not burn a second slot. **Q** is that acceptable, or should `hwid` reuse need the old key?
- Errors (HTTP 4xx with `{"error": "<code>"}`): `device_limit` (all slots used), `expired`, `disabled`.
  Everything else a stranger could cause: the decoy.
- The device counts against the device limit and shows on the subscription page like any other.

### sync

`200` with the body below and an `ETag`; `304` when nothing changed; `401 {"error": "device_removed"}` when the
device was removed (the client then says so and stops; it does not enrol again by itself).

```json
{
  "format": 1,
  "sync_every_s": 600,
  "brand": { "name": "…", "logo_url": "https://…", "accent": "#7c6cff", "support_url": "https://…", "page_url": "https://…" },
  "plan":  { "status": "active", "expire_unix": 0, "used_bytes": 0, "total_bytes": 0,
             "devices_used": 2, "devices_limit": 5, "this_device": "d_…" },
  "notice": { "id": "n1", "text": "…", "url": "" },
  "dns": ["1.1.1.1", "1.0.0.1"],
  "servers": [
    { "id": "s_de1", "name": "🇩🇪 Germany", "country": "de", "city": "", "load": 0.31, "via": "",
      "paths": [
        { "id": "p1", "protocol": "hysteria2", "exit": "direct", "settings": { /* built by the panel's hysteria2 plugin */ } },
        { "id": "p2", "protocol": "awg", "exit": "direct", "settings": { /* no private key: it is the client's */ } }
      ] }
  ],
  "tactics": { "order": ["p2", "p1"] },
  "telegram": [ { "name": "…", "link": "tg://proxy?…" } ],
  "mirrors": []
}
```
- A `format` the client does not know is refused loudly, not guessed at.
- `settings` per protocol, as the client needs them (**Q** the panel's plugins may prefer their own shapes; these are
  what the client's engines take today):
  - `hysteria2`: `{ "server": "host:port", "auth": "…", "sni": "…", "pin_sha256": "hex", "obfs": "none|salamander|gecko", "obfs_password": "…" }`
  - `awg`: `{ "endpoint": "host:port", "server_public_key": "base64", "preshared_key": "base64", "addresses": ["10.x.x.x/32"],
    "allowed_ips": ["0.0.0.0/0", "::/0"], "mtu": 1280, "keepalive": 25, "params": { "jc": 4, "jmin": 27, "jmax": 84, "s1": 32, …, "i1": "…" } }`
    (`params` are the AmneziaWG 3.1 interface values the panel already renders into a config).
- `tactics` is where the panel's ranking for this user's network lands later (the learning loop); empty means the
  client decides.
- The active tunnel is rebuilt only when its own path changed.

### probe (v2)

What the detectors found, anonymous: stored without the device, as v1 is. The panel looks up the ASN of the request's
address in process and keeps only the ASN.

```json
{
  "v": 2, "at_unix": 0, "app_version": "0.1.0", "network": "wifi|ethernet|mobile|other",
  "paths": [ { "server": "s_de1", "path": "p1", "verdict": "ok|blocked|down|config|app|slow|freeze", "reason": "udp_no_answer", "rtt_ms": 38 } ],
  "route":   { "verdict": "ok|blocked|unknown", "hop": 0, "total": 0 },
  "udp":     { "verdict": "ok|blocked|unknown" },
  "nat":     { "verdict": "open|limited|unknown" },
  "dns":     { "verdict": "ok|replaced|unknown", "checked": 0, "replaced": 0 },
  "foreign": { "verdict": "ok|cut|unknown", "total": 0, "open": 0 }
}
```
This is the result of the client's network check (`diag.run` in `docs/ipc.md`) with server ids from `sync`. Sent only
when the user turned "help find blocks" on. Answer: `204`.

### debug

A debug report the user chose to send: `multipart/form-data` with `meta` (JSON: app and OS versions, which parts
are inside) and `bundle` (a zip, at most 2 MiB; keys, tokens, the public address and site names are removed by the
client before it leaves). Answer: `{ "code": "MG-7K3F" }`, the code the user gives to support.
`403 {"error": "intake_off"}` when the operator does not accept reports: the client then offers "save as file".
**Q** how the panel says in `sync` whether intake is on, and whether an admin's request for a report rides in `sync`
(`"debug_requested": true`).

### leave

Removes this device and its AmneziaWG peer. `204`. The client forgets the device key and the subscription.

## What the client does with it

- Enrols when a link turns out to answer `enrol` (**Q** how a client tells a Mistgate panel from any other before it
  spends a slot: a `HEAD <link>/client/enrol`, a header on the plain subscription answer such as
  `x-mistgate-client-api: 1`, or the `mistgate://add?url=…` button on the subscription page only?). Otherwise: basic
  mode.
- Keeps the device key and the AmneziaWG private key in its protected store (DPAPI, the service's account).
- Syncs every `sync_every_s` and after the network comes back, through the tunnel when it is up.
- Reports go outside the tunnel when possible (that is the network they describe).

## Not in v1

Managing other devices of the user from the client (that needs the page password, not only a device key), mirrors
of the panel's address, per-ASN tactics, an admin's request for a debug report.
