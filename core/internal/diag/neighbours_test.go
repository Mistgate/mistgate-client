package diag

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

func TestProductMatching(t *testing.T) {
	for exe, want := range map[string]string{
		"winws.exe": "zapret", "GoodbyeDPI.EXE": "GoodbyeDPI", "ciadpi.exe": "ByeDPI", "byedpi.exe": "ByeDPI",
		"mihomo.exe": "Mihomo", "clash-win64.exe": "Clash", "chrome.exe": "", "svchost.exe": "",
	} {
		if got := processProduct(exe); got != want {
			t.Errorf("process %q = %q, want %q", exe, got, want)
		}
	}
	for description, want := range map[string]string{
		"WireGuard Tunnel":                  "WireGuard",
		"Wintun Userspace Tunnel":           "Wintun",
		"TAP-Windows Adapter V9":            "TAP-Windows",
		"sing-tun Tunnel":                   "sing-box",
		"AmneziaWG Tunnel":                  "AmneziaVPN",
		"Mullvad Tunnel":                    "VPN adapter",
		"Teredo Tunneling Pseudo-Interface": "",
		"Intel(R) Ethernet Connection":      "",
	} {
		if got := adapterProduct(description); got != want {
			t.Errorf("adapter %q = %q, want %q", description, got, want)
		}
	}
}

func TestNeighboursDedupeByProductAndCap(t *testing.T) {
	got := neighbours(
		[]string{"explorer.exe", "wireguard.exe", "winws.exe", "WINWS.EXE"},
		[]string{"WinDivert"},
		[]string{"WireGuard Tunnel", "Intel(R) Ethernet", "Wintun Userspace Tunnel"},
	)
	want := []Neighbour{{"process", "WireGuard"}, {"process", "zapret"}, {"driver", "WinDivert"}, {"adapter", "Wintun"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, "WireGuard Tunnel #"+strconv.Itoa(i))
	}
	if got := neighbours(nil, nil, many); len(got) != 1 {
		t.Errorf("one product listed %d times", len(got))
	}
	exes := []string{"winws.exe", "goodbyedpi.exe", "ciadpi.exe", "wireguard.exe", "openvpn.exe", "amneziavpn.exe", "outline.exe",
		"sing-box.exe", "xray.exe", "v2rayn.exe", "nekoray.exe", "nekobox.exe", "hiddify.exe"}
	if got := neighbours(exes, nil, nil); len(got) != maxNeighbours {
		t.Errorf("cap: %d entries", len(got))
	}
	empty, _ := json.Marshal(neighbours(nil, nil, nil))
	if string(empty) != "[]" {
		t.Errorf("empty list serialises as %s", empty)
	}
}
