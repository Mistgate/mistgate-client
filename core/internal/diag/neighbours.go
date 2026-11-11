package diag

import "strings"

// Other software on this machine that fights with a VPN client for the same traffic: a packet-interception driver,
// another VPN's tunnel adapter that is up, a known DPI-bypass tool or VPN that is running.
type Neighbour struct {
	Kind string `json:"kind"` // process, driver or adapter
	Name string `json:"name"` // the product's name as a user knows it
}

const maxNeighbours = 10

// neighbourProcesses: executable name (lower case) to product.
var neighbourProcesses = map[string]string{
	"winws.exe": "zapret", "goodbyedpi.exe": "GoodbyeDPI", "ciadpi.exe": "ByeDPI", "byedpi.exe": "ByeDPI",
	"wireguard.exe": "WireGuard", "openvpn.exe": "OpenVPN", "amneziavpn.exe": "AmneziaVPN",
	"amneziavpn-service.exe": "AmneziaVPN", "outline.exe": "Outline", "sing-box.exe": "sing-box", "xray.exe": "Xray",
	"v2rayn.exe": "v2rayN", "nekoray.exe": "NekoRay", "nekobox.exe": "NekoBox", "hiddify.exe": "Hiddify",
	"clash-verge.exe": "Clash Verge", "happ.exe": "Happ", "mihomo.exe": "Mihomo",
}

// neighbourAdapters: a piece of the adapter description (lower case) to product, first match wins. "tunnel" is
// the catch-all for a VPN adapter whose product is not known.
var neighbourAdapters = []struct{ part, product string }{
	{"teredo", ""}, // Windows' own
	{"wireguard", "WireGuard"}, {"amnezia", "AmneziaVPN"}, {"openvpn", "OpenVPN"}, {"tap-windows", "TAP-Windows"},
	{"sing-tun", "sing-box"}, {"wintun", "Wintun"}, {"tap-", "TAP-Windows"}, {"tunnel", "VPN adapter"},
}

func processProduct(exe string) string {
	exe = strings.ToLower(exe)
	if product, ok := neighbourProcesses[exe]; ok {
		return product
	}
	if strings.HasPrefix(exe, "clash") { // clash.exe, clash-win64.exe, ...
		return "Clash"
	}
	return ""
}

func adapterProduct(description string) string {
	description = strings.ToLower(description)
	for _, a := range neighbourAdapters {
		if strings.Contains(description, a.part) {
			return a.product
		}
	}
	return ""
}

// neighbours turns what the machine has (executable names, products of running drivers, descriptions of tunnel
// adapters that are up and not ours) into the list: one entry per product, the first kind that found it, at most maxNeighbours.
func neighbours(processes, drivers, adapters []string) []Neighbour {
	found := []Neighbour{}
	add := func(kind, product string) {
		if product == "" || len(found) >= maxNeighbours {
			return
		}
		for _, n := range found {
			if n.Name == product {
				return
			}
		}
		found = append(found, Neighbour{kind, product})
	}
	for _, exe := range processes {
		add("process", processProduct(exe))
	}
	for _, name := range drivers {
		add("driver", name)
	}
	for _, description := range adapters {
		add("adapter", adapterProduct(description))
	}
	return found
}
