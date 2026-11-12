//go:build windows

package debugsend

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// osBuild is the Windows build number ("26100").
func osBuild() string { return strconv.FormatUint(uint64(windows.RtlGetVersion().BuildNumber), 10) }
