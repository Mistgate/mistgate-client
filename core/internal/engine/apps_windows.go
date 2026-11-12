//go:build windows

package engine

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	appScanGap     = 2 * time.Second
	maxAppNames    = 2048
	maxAppNameSize = 128 // bytes; the description comes from a file that is not ours
	maxAppPathSize = 512 // what the rules accept
)

var scanned struct {
	mu   sync.Mutex // one scan at a time; callers within appScanGap share its result
	at   time.Time
	apps []AppInfo
}

// ListApps is the window's list of programs (apps.list): those running in a user's session, and the ones the rules
// already name (named), whether running or not. Ok to call often: a scan is reused for 2 s.
// ponytail: installed but not running programs (Start menu shortcuts) are not listed; the user starts the program or adds
// its exe by hand. Upgrade = read the Start menu folders and the App Paths registry key.
func ListApps(named []string) []AppInfo {
	return mergeApps(runningApps(), named, appName)
}

func runningApps() []AppInfo {
	scanned.mu.Lock()
	defer scanned.mu.Unlock()
	if scanned.apps != nil && time.Since(scanned.at) < appScanGap {
		return scanned.apps
	}
	apps := scanApps()
	scanned.at, scanned.apps = time.Now(), apps
	return apps
}

// scanApps lists the programs of the user sessions (not session 0, where the services run) outside the Windows
// directory and outside the client's own folder.
func scanApps() []AppInfo {
	apps := []AppInfo{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return apps
	}
	defer windows.CloseHandle(snap)
	windir, _ := windows.GetSystemWindowsDirectory()
	windir = strings.ToLower(windir) + `\`
	ownDir := ""
	if exe, err := os.Executable(); err == nil {
		ownDir = strings.ToLower(exe)
		ownDir = ownDir[:strings.LastIndex(ownDir, `\`)+1]
	}
	self := windows.GetCurrentProcessId()
	seen := make(map[string]struct{})
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		pid := entry.ProcessID
		var session uint32
		if pid <= 4 || pid == self || windows.ProcessIdToSessionId(pid, &session) != nil || session == 0 {
			continue
		}
		path := processPath(pid)
		if len(path) < len(`c:\a.exe`) || len(path) > maxAppPathSize || path[1] != ':' || !strings.HasSuffix(path, ".exe") ||
			strings.HasPrefix(path, windir) || ownDir != "" && strings.HasPrefix(path, ownDir) {
			continue
		}
		if _, dup := seen[path]; !dup {
			seen[path] = struct{}{}
			apps = append(apps, AppInfo{Path: path, Name: appName(path), Running: true})
		}
	}
	return apps
}

var appNames = struct {
	sync.Mutex
	m map[string]string
}{m: make(map[string]string)}

// appName is the file description of the exe, or its file name without the extension.
// ponytail: names are kept until the service stops (2048 at most), so a program updated meanwhile shows its old name.
func appName(path string) string {
	appNames.Lock()
	name, ok := appNames.m[path]
	appNames.Unlock()
	if ok {
		return name
	}
	if name = fileDescription(path); name == "" {
		name = baseName(path)
	}
	appNames.Lock()
	if len(appNames.m) >= maxAppNames {
		clear(appNames.m)
	}
	appNames.m[path] = name
	appNames.Unlock()
	return name
}

// fileDescription reads FileDescription from the version resource: in the languages the file declares, then in the usual ones.
func fileDescription(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	data := make([]byte, size)
	block := unsafe.Pointer(&data[0])
	if windows.GetFileVersionInfo(path, 0, size, block) != nil {
		return ""
	}
	var langs []string
	var pairs unsafe.Pointer
	var length uint32
	if windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&pairs), &length) == nil && length >= 4 {
		for _, pair := range unsafe.Slice((*[2]uint16)(pairs), min(length/4, 8)) {
			langs = append(langs, fmt.Sprintf("%04x%04x", pair[0], pair[1]))
		}
	}
	langs = append(langs, "040904b0", "040904e4", "000004b0")
	for _, lang := range langs {
		var text unsafe.Pointer
		if windows.VerQueryValue(block, `\StringFileInfo\`+lang+`\FileDescription`, unsafe.Pointer(&text), &length) != nil || length < 2 || text == nil {
			continue
		}
		name := strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(text), length)))
		if strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }) || !utf8.ValidString(name) {
			continue
		}
		if len(name) > maxAppNameSize {
			name = strings.ToValidUTF8(name[:maxAppNameSize], "")
		}
		if name != "" {
			return name
		}
	}
	return ""
}
