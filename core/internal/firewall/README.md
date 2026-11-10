# firewall

The kill switch's rules. This is `tunnel/firewall` from WireGuard for Windows v1.1.1
(golang.zx2c4.com/wireguard/windows, MIT, see COPYING), copied because its rule helpers are not exported.

Ours: `lan.go` (the local network stays reachable), its optional call in `blocker.go`, replacing an existing dynamic
session only after the new session commits, installing DNS rules independently of full restrictions (and DNS deny
filters when the allowed server list is empty), and the "Mistgate" display names. `EnableFirewall` takes `allowLAN`;
when `doNotRestrict` is true it installs only DNS rules, if resolvers were supplied.
Everything else is upstream, unchanged: take fixes from there.
