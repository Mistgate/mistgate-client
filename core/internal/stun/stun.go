package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

type Mapping struct {
	Address netip.Addr
	Port    uint16
}

func MakeRequest() ([]byte, error) {
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], 0x2112A442)
	if _, err := rand.Read(request[8:20]); err != nil {
		return nil, err
	}
	return request, nil
}

func ParseResponse(request, response []byte) (Mapping, bool) {
	if len(request) < 20 || len(response) < 20 || binary.BigEndian.Uint16(response[:2]) != 0x0101 ||
		binary.BigEndian.Uint32(response[4:8]) != 0x2112A442 || !equalBytes(request[8:20], response[8:20]) {
		return Mapping{}, false
	}
	messageLen := int(binary.BigEndian.Uint16(response[2:4]))
	if messageLen > len(response)-20 {
		return Mapping{}, false
	}
	for offset := 20; offset+4 <= 20+messageLen; {
		attribute := binary.BigEndian.Uint16(response[offset : offset+2])
		length := int(binary.BigEndian.Uint16(response[offset+2 : offset+4]))
		start, end := offset+4, offset+4+length
		if end > 20+messageLen {
			return Mapping{}, false
		}
		if attribute == 0x0020 && length >= 4 {
			value := response[start:end]
			port := binary.BigEndian.Uint16(value[2:4]) ^ 0x2112
			switch value[1] {
			case 1:
				if length != 8 {
					return Mapping{}, false
				}
				cookie := []byte{0x21, 0x12, 0xa4, 0x42}
				var raw [4]byte
				for i := range raw {
					raw[i] = value[4+i] ^ cookie[i]
				}
				return Mapping{Address: netip.AddrFrom4(raw), Port: port}, true
			case 2:
				if length != 20 {
					return Mapping{}, false
				}
				mask := append([]byte{0x21, 0x12, 0xa4, 0x42}, request[8:20]...)
				var raw [16]byte
				for i := range raw {
					raw[i] = value[4+i] ^ mask[i]
				}
				return Mapping{Address: netip.AddrFrom16(raw), Port: port}, true
			default:
				return Mapping{}, false
			}
		}
		offset = start + ((length + 3) &^ 3)
	}
	return Mapping{}, false
}

func Query(ctx context.Context, conn net.PacketConn, server netip.AddrPort, timeout time.Duration) (netip.Addr, error) {
	request, err := MakeRequest()
	if err != nil {
		return netip.Addr{}, err
	}
	remote := &net.UDPAddr{IP: net.IP(server.Addr().AsSlice()), Port: int(server.Port())}
	if _, err := conn.WriteTo(request, remote); err != nil {
		return netip.Addr{}, err
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		buffer := make([]byte, 2048)
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return netip.Addr{}, ctx.Err()
			}
			return netip.Addr{}, err
		}
		udpSource, ok := source.(*net.UDPAddr)
		if !ok || udpSource.AddrPort() != server {
			continue
		}
		if mapping, ok := ParseResponse(request, buffer[:n]); ok {
			return mapping.Address, nil
		}
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}
