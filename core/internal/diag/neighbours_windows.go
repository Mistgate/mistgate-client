//go:build windows

package diag

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// scanLocal reads the process list, the WinDivert driver's service state and the adapter list. It keeps only names:
// no paths, no PIDs.
func scanLocal() (processes, drivers, adapters []string) {
	if snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0); err == nil {
		defer windows.CloseHandle(snapshot)
		entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
		for err := windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
			processes = append(processes, windows.UTF16ToString(entry.ExeFile[:]))
		}
	}
	if windivertRunning() {
		drivers = []string{"WinDivert"}
	}
	if list, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault); err == nil {
		for _, adapter := range list {
			// ponytail: ours is told by its name (netcfg creates it as "Mistgate"); upgrade = export the GUID from netcfg
			if adapter.OperStatus == winipcfg.IfOperStatusUp && !strings.EqualFold(adapter.FriendlyName(), "Mistgate") {
				adapters = append(adapters, adapter.Description())
			}
		}
	}
	return processes, drivers, adapters
}

// windivertRunning: the packet-interception driver registers as a service under one of these names (1.x and 2.x).
func windivertRunning() bool {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(manager)
	for _, name := range []string{"WinDivert", "WinDivert14", "WinDivert1.4"} {
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		service, err := windows.OpenService(manager, pointer, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		var status windows.SERVICE_STATUS
		err = windows.QueryServiceStatus(service, &status)
		windows.CloseServiceHandle(service)
		if err == nil && status.CurrentState == windows.SERVICE_RUNNING {
			return true
		}
	}
	return false
}
