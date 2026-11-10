# firewall

The kill switch's rules. This is `tunnel/firewall` from WireGuard for Windows v1.1.1
(golang.zx2c4.com/wireguard/windows, MIT, see COPYING), copied because its rule helpers are not exported.

Ours: `lan.go` (the local network stays reachable), its call in `blocker.go`, the "Mistgate" display names.
Everything else is upstream, unchanged: take fixes from there.
