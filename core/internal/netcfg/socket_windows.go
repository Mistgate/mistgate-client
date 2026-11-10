//go:build windows

package netcfg

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const ipUnicastIf = 31

func SocketControl(index uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(int32(reverseBytes32(index))))
		}); err != nil {
			return err
		}
		return optionErr
	}
}

func reverseBytes32(value uint32) uint32 {
	return value>>24 | value>>8&0x0000ff00 | value<<8&0x00ff0000 | value<<24
}
