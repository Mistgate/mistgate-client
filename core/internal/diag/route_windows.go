//go:build windows

package diag

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

const (
	ipSuccess           = 0
	ipTTLExpiredTransit = 11013
)

// ipOptionInformation is IP_OPTION_INFORMATION; icmpEchoReply is ICMP_ECHO_REPLY (64-bit layout).
type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// icmpEcho sends one echo with the given TTL through the system's ICMP interface (no raw socket, no privilege) and
// says who answered. The call blocks for at most wait; a cancelled ctx is seen between calls.
func icmpEcho(ctx context.Context, target netip.Addr, ttl int, wait time.Duration) hopAnswer {
	if ctx.Err() != nil || !target.Is4() {
		return hopSilent
	}
	handle, _, _ := procIcmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return hopSilent
	}
	defer procIcmpCloseHandle.Call(handle)
	destination := target.As4()
	payload := [8]byte{'m', 'i', 's', 't', 'g', 'a', 't', 'e'}
	options := ipOptionInformation{TTL: uint8(ttl)}
	reply := make([]byte, unsafe.Sizeof(icmpEchoReply{})+uintptr(len(payload))+8+64)
	count, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(binary.LittleEndian.Uint32(destination[:])), // the address as it lies in memory
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
		uintptr(wait.Milliseconds()),
	)
	if count == 0 {
		return hopSilent
	}
	switch (*icmpEchoReply)(unsafe.Pointer(&reply[0])).Status {
	case ipSuccess:
		return hopReached
	case ipTTLExpiredTransit:
		return hopRouter
	}
	return hopSilent
}
