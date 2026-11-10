# Mistgate Client API, v1 (DRAFT 2, not implemented)

How the client and a Mistgate panel talk once the client knows the user's subscription link. It is meant to be
open: another panel may implement it and get the same client. Until a panel answers it, the client works in basic
mode (the plain subscription a link gives to any app, see `docs/ipc.md`).

Status: draft 2, revised after the panel's review of draft 1. Nothing is built on either side. Points the owner
still has to rule on are marked **OWNER**.

## Principles

- The panel is not on the traffic's path. It hands out configuration and takes reports; when it cannot be reached
  the client keeps working on what it has.
- The subscription link is enough to enrol. Everything after enrolment is authorised by a **device key** the panel
  gives once: 32 random bytes, sent as `Authorization: Bearer <key>` over TLS; the panel stores only its SHA-256.
  No signatures, timestamps or clocks.
- The client never calls the subscription page's own self-service (`<link>/devices` and friends): that is guarded by
  the page password and stays so.
- An unknown or malformed token or key gets what the panel answers to any stranger today (the decoy), and counts as
  a miss (the panel rate-limits misses per client network). **Any answer that is not the expected JSON means
  "unreachable", never "removed".**
- Every request carries `X-Mistgate-Caps` and `User-Agent: Mistgate/<version> (<os>)` (the panel takes the app
  version from the first User-Agent token).
- The panel's parsers reject unknown body fields: a new field needs a caps or version bump first.

## Capabilities

`X-Mistgate-Caps: v=1; hysteria2=2; gecko=1; awg=2.0,3.1; probe=1`

A list of `name=version`. The panel does not hand out what is not listed (Gecko obfuscation only to clients that
announce it, the AmneziaWG version by what is listed), so a new protocol or feature appears without a new format
version. `v` is this API's version.

## Discovery

The plain subscription answer carries `Mistgate-Client-Api: 1` only when the token is valid AND the request carried
`X-Mistgate-Caps` AND the operator's client-API switch is on. Strangers get the decoy before any header; other apps
never see it. The `mistgate://add?url=…` button on the subscription page stays as a convenience.
A basic fetch with `X-HWID` already makes a device in the panel; enrolling replaces it in the same slot.

## Calls

| Call | Authorised by | Purpose |
|---|---|---|
| `POST <link>/client/enrol` | the token in the link; the old device key when re-enrolling | makes this device, returns `base` |
| `GET <base>/sync` | device key | the subscription in the `mistgate` format; `If-None-Match` -> `304` |
| `POST <base>/leave` | device key | this device removes itself |
| `POST <link>/probe` | the token (as today) | the detectors' report, v1, announced by `Probe-Report: 1` |
| `POST <base>/debug` | device key | a debug report (later; VPS edition only) |

`base` is an absolute URL the panel returns from `enrol` (v1: `<subscription prefix>/client`, no token in it). The
client never builds it. Reasons: rotating the link replaces the token but keeps devices; per-token fetch budgets are
shared by all of a person's apps; a token in a path ends up in proxy logs.

### enrol

```json
{ "hwid": "…", "platform": "windows", "os_version": "11 24H2", "name": "" }
```
- `hwid`: `[A-Za-z0-9=-]{10,64}`, random per install and per operator's panel, not derived from hardware; the same
  value basic mode sends as `X-HWID`. The client keeps it, with the device key, where a reinstall does not erase it.
- `platform`: `ios | android | windows | macos | linux | other`. `name` and the model are one field in the panel.
```json
{ "device_id": "…", "device_key": "…", "base": "https://…/client", "sync_every_s": 3600 }
```
Re-enrolling (a new key never silently replaces an old one: the link is shared and `hwid` is not a secret):
1. `hwid` matches a basic-mode device without a key: replaced in the same slot, its old credentials revoked.
2. `hwid` matches an enrolled device: the request must carry the old key as Bearer; then the same device, a new key,
   the same credentials. Without it: `409 device_exists` (the way out: remove the device on the page or by the
   admin; a device silent for 30 days is evicted in the enforcing limit modes).
3. `hwid` of a revoked device: a new device. 4. A blocked `hwid`: `403 device_blocked`.

Errors, HTTP 4xx with `{"error": "<code>"}`: `user_inactive`, `device_limit` (in the counting-only limit mode at
twice the limit; in the enforcing modes at the limit, after evicting a 30-day-silent device), `device_blocked`,
`device_exists`, `client_api_off`, `too_many_requests` (429 with `Retry-After`), `bad_request`, `too_large`,
`unsupported_media_type`, `cross_origin`.

### sync

`sync_every_s` is the panel's choice (expect about an hour). Sync through the tunnel puts all users of a node behind
one exit address: the client adds jitter and honours `Retry-After`. What it answers:
- `200` + body + `ETag`; `304` when nothing changed;
- user disabled, expired or over quota: `200` with that status and no servers;
- `401 device_removed` (removed on the page, by the admin, or by `leave`): the client says so and stops;
- `401 device_blocked`;
- `401 link_changed` (the link was rotated since enrolment): enrolling again with the new link and the old key
  keeps the device;
- user deleted, or an unknown key: the decoy.

```json
{
  "format": 1,
  "sync_every_s": 3600,
  "brand": { "name": "…", "accent": "#7c6cff", "logo_svg": "<svg…>", "support_url": "https://…" },
  "plan":  { "status": "active|disabled|expired|limited", "expire_unix": 0, "used_bytes": 0, "total_bytes": 0,
             "quota_reset": "none|daily|weekly|monthly", "next_reset_unix": 0,
             "devices_used": 2, "devices_limit": 5, "this_device": "…" },
  "notice": "…",
  "debug": { "intake": false },
  "probe": { "intake": true, "v": 1 },
  "servers": [
    { "id": "…", "country": "de", "city": "", "load": "low|medium|high",
      "paths": [
        { "id": "…", "protocol": "hysteria2", "via": "", "dns": ["…", "…"], "settings": { } },
        { "id": "…", "protocol": "awg", "via": "relay", "dns": ["…", "…"], "settings": { } }
      ] }
  ],
  "telegram": [ { "name": "…", "link": "tg://proxy?…" } ]
}
```
- A `format` the client does not know is refused loudly.
- `brand.logo_svg` is inline and sanitised by the panel; the client draws it only as an image. There is no page URL
  in `sync`: the page is the subscription link the user gave, and a rotated link must cut the old one off.
- Server names are country and city (the client adds flags); path ids are opaque and stable, never node names.
  `via` belongs to a path (a relay or an IPv6 copy is one more path of the same exit). DNS is per path.
- `debug.request: {"id", "until_unix"}` is reserved for an admin's request aimed at this device: the client asks the
  user and sends with that id, never on its own.
- The active tunnel is rebuilt only when its own path changed.

`settings`, a Mistgate JSON shape per protocol rendered by the panel's plugins (no existing format carries
everything: links drop Gecko and port ranges, others cannot carry AmneziaWG):
- `hysteria2`: `{ "server": "host", "port": 443, "ports": "20000-40000", "hop_interval_s": 30, "auth": "…",
  "tls": "ca|pin", "pin_sha256": "hex", "sni": "…", "alpn": ["h3"], "obfs": "none|salamander|gecko",
  "obfs_password": "…" }`. `tls: "pin"` only for self-signed nodes, and then the pin is the only check; there is no
  "insecure". `sni` is absent for nodes known by address only. `ports` + `hop_interval_s` when the node hops ports.
- `awg`: `{ "version": "2.0|3.1", "endpoint": "host:port", "private_key": "base64", "server_public_key": "base64",
  "preshared_key": "base64", "addresses": ["…/32"], "allowed_ips": ["0.0.0.0/0"], "mtu": 1280, "keepalive": 25,
  "jc": 4, "jmin": 27, "jmax": 84, "s1": 32, "s2": 32, "s3": 32, "s4": 32, "h1": "1", "h2": "2-5", "h3": "…", "h4": "…",
  "i1": "…", … "i5": "…" }` plus, for 3.1, the header-protection key and the padding, rekey, keepalive-timeout,
  handshake, trailers and cookies fields. `h1`-`h4` are strings and may be ranges; `i1`-`i5` are per device; an IPv6
  address only if the profile has IPv6.

**AmneziaWG keys (OWNER).** v1: the panel generates the device's key pairs and delivers them in `sync`, as it does
for app devices today. A key the client makes itself does not fit the panel as it is (one peer per profile per
device, direct and relay paths are separate peers, rotation is server-side, the panel already holds the pre-shared
and header-protection keys). If private keys must stay on the device, that is a later capability `awg-keys=1`:
`sync` marks a path `"key": "needed"` and the client posts one public key per profile.

### leave

Removes this device and its peers. `204`. The client forgets the device key and the subscription.

### probe: v1, as the panel takes it today

`POST <link>/probe`, announced by the `Probe-Report: 1` header on the subscription answer, only with the user's
consent. The report never relies on the request's address: the app states the ASN itself and says whether the
check ran through the VPN (`vpn`, `direct_checked`). Verdicts are v1's: `ok`, `freeze`, `tcp_blocked`,
`handshake_failed`, `no_answer`. The operator has its own switch for app reports (off by default; kept 7 days).

A v2 with the client's wider check (route hops, UDP and NAT, DNS, foreign sites, the client's verdict names) is
**deferred**: the panel has no storage or admin view for it.

### debug (later)

Not a zip: NDJSON lines with a fixed schema, about 1 MiB at most, so the panel can scrub them again on intake.
Offered only when `sync` says `debug.intake: true`; otherwise the client offers "save as file". The edge edition of
the panel does not take debug reports.

## What changes in the client meanwhile

- Basic mode against a Mistgate panel: `User-Agent: Mistgate/x` matches no rule there and gets the plain link list
  (Hysteria2 only, no AmneziaWG, no Gecko, one hop port). Until this API exists the client gets no AmneziaWG from a
  Mistgate subscription. (kl!ck announces itself as a Mihomo client to get the Mihomo profile; this client does not
  read that format.) **OWNER**: live with that until the API, or teach the client the Mihomo profile as a stopgap.
- `hwid` must become per operator's panel and survive a reinstall (today it is one per install).
- The client's own network check does not map to report v1 yet: v1 wants the ASN from the app and has other
  verdict names.

## Not in v1

Client-held AmneziaWG keys, report v2, debug intake on the edge edition, managing the user's other devices from the
client (that needs the page password), mirrors of the panel's address, per-network tactics.
