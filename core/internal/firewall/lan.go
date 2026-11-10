/* SPDX-License-Identifier: MIT
 *
 * Mistgate's addition to the WireGuard for Windows firewall package (see README.md here).
 */

package firewall

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The local network: private and link-local ranges, and the multicast and broadcast that printers, casting and file
// sharing find each other with. DNS to these addresses stays closed: the DNS rules sit above this one.
var lanPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff02::/16"),
}

func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	// conditions on the same field are alternatives; the values must stay alive until the filters are added
	var v4 []wtFwpmFilterCondition0
	var v6 []wtFwpmFilterCondition0
	var keep4 []*wtFwpV4AddrAndMask
	var keep6 []*wtFwpV6AddrAndMask
	for _, prefix := range lanPrefixes {
		condition := wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL}
		if prefix.Addr().Is4() {
			bytes := prefix.Addr().As4()
			value := &wtFwpV4AddrAndMask{addr: binary.BigEndian.Uint32(bytes[:]), mask: ^uint32(0) << (32 - prefix.Bits())}
			keep4 = append(keep4, value)
			condition.conditionValue = wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(value))}
			v4 = append(v4, condition)
		} else {
			value := &wtFwpV6AddrAndMask{addr: prefix.Addr().As16(), prefixLength: uint8(prefix.Bits())}
			keep6 = append(keep6, value)
			condition.conditionValue = wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(value))}
			v6 = append(v6, condition)
		}
	}
	for _, rule := range []struct {
		name       string
		layer      windows.GUID
		conditions []wtFwpmFilterCondition0
	}{
		{"Permit outbound IPv4 to the local network", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, v4},
		{"Permit inbound IPv4 from the local network", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, v4},
		{"Permit outbound IPv6 to the local network", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, v6},
		{"Permit inbound IPv6 from the local network", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, v6},
	} {
		displayData, err := createWtFwpmDisplayData0(rule.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            rule.layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(rule.conditions)),
			filterCondition:     &rule.conditions[0],
			action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
		}
		filterID := uint64(0)
		if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
			return wrapErr(err)
		}
	}
	_, _ = keep4, keep6
	return nil
}
