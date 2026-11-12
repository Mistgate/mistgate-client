//go:build windows

package proxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// RuleName is the Windows Firewall rule that lets the home network reach the proxy ports.
const RuleName = "MistgateLocalProxy"

// FirewallRule adds (allow) or removes the inbound rule for the proxy's two ports: this program only, TCP, the
// private and domain profiles (never public), and only the machines of the local subnet. Windows Firewall blocks
// inbound connections by default, and our own kill-switch filters (WFP, another sub-layer) cannot lift that block.
// netsh is the plain way to do it, and the service runs as LocalSystem. Removing a rule that is not there is not an error.
func FirewallRule(allow bool) error {
	netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	// the add replaces an earlier rule of this name, so a moved binary or changed port never leaves a stale one
	_ = runNetsh(netsh, `advfirewall firewall delete rule name=`+RuleName) // fails when there is no such rule
	if !allow {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return runNetsh(netsh, `advfirewall firewall add rule name=`+RuleName+
		` dir=in action=allow protocol=TCP localport=`+strconv.Itoa(SocksPort)+`,`+strconv.Itoa(HTTPPort)+
		` program="`+exe+`" profile=private,domain remoteip=localsubnet enable=yes`)
}

func runNetsh(netsh, arguments string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // a stuck firewall service must not hold the service's start
	defer cancel()
	cmd := exec.CommandContext(ctx, netsh)
	// the whole line is given, so the quoting of the program path is exactly netsh's own syntax
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `"` + netsh + `" ` + arguments, HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Run(); err != nil {
		return errors.New("netsh: " + err.Error())
	}
	return nil
}
