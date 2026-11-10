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
| `connect` | `{"server": "auto" \| "<server id>", "protocol": "auto" \| "hysteria2" \| "awg"}` (both optional) | Status |
| `disconnect` | — | Status |
| `subscribe` | `{"events": ["status", "traffic", "log"]}` | `{}`; the events then arrive on this connection |

Status:

While connecting, `server` and `protocol` reflect the request. Once connected, they hold the profile name and
protocol that are actually in use.

```json
{"state": "off", "step": "", "since_unix": 0, "server": "", "protocol": "", "error": ""}
```

`state`: `off` · `connecting` · `connected` · `reconnecting` · `error` · `blocked` (the kill switch holds the internet).
`step` while connecting: `resolve` · `handshake` · `tunnel` · `verify`. `error`: a code such as `no_server_answers`,
`no_subscription`, `offline`, `server_not_found`, `auth_rejected`, `tunnel_failed`, `verify_failed`, `unsupported_os`.

Events: `status` (a Status, on every change), `traffic` (`{"rx_bps": 0, "tx_bps": 0, "rtt_ms": 0}`, once a second while
connected), `log` (`{"t_unix_ms": 0, "level": "info", "msg": "…"}`).

Subscriptions, servers, settings, diagnostics and reports come with the steps that build them; each adds its methods
here first.

## Running it by hand

For a real connection, run `mistgate-clientd run -profiles profiles.json` from an elevated console. Put
`wintun.dll` version 0.14.1 from [wintun.net](https://www.wintun.net/) beside `mistgate-clientd.exe`. The profiles
file is JSON with a `servers` array; Hysteria2 entries use `uri`, and AmneziaWG entries use `conf` containing the
wg-quick text. `verify` is optional and defaults to `1.1.1.1:443`.

```json
{
  "servers": [
    {"id": "de1-hy2", "name": "Germany", "protocol": "hysteria2", "uri": "hysteria2://token@server.example:443"},
    {"id": "de1-awg", "name": "Germany", "protocol": "awg", "conf": "[Interface]\nAddress = 10.66.4.3/32\nPrivateKey = <key>\n[Peer]\nPublicKey = <key>\nAllowedIPs = 0.0.0.0/0\nEndpoint = server.example:51820"}
  ]
}
```
