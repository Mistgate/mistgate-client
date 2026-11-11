//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "MistgateClient"

// runAsService reports false when the process was started from a console; then the caller runs in the foreground.
func runAsService(run func(context.Context, <-chan time.Duration) error) (bool, error) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return false, err
	}
	return true, svc.Run(serviceName, handler(run))
}

type handler func(context.Context, <-chan time.Duration) error

func (run handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	powerEvents := make(chan time.Duration, 1)
	go func() { done <- run(ctx, powerEvents) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	var suspendedAt time.Time
	var pendingSleep time.Duration
	var resumeTimer *time.Timer
	var resumeC <-chan time.Time
	defer func() {
		if resumeTimer != nil {
			resumeTimer.Stop()
		}
		close(powerEvents)
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.PowerEvent:
				switch request.EventType {
				case 4:
					suspendedAt = time.Now()
					if resumeTimer != nil && !resumeTimer.Stop() {
						select {
						case <-resumeTimer.C:
						default:
						}
					}
					resumeC = nil
				case 7, 18:
					pendingSleep = sleptDuration(suspendedAt, time.Now())
					suspendedAt = time.Time{}
					if resumeTimer == nil {
						resumeTimer = time.NewTimer(5 * time.Second)
					} else {
						if !resumeTimer.Stop() {
							select {
							case <-resumeTimer.C:
							default:
							}
						}
						resumeTimer.Reset(5 * time.Second)
					}
					resumeC = resumeTimer.C
				}
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		case <-resumeC:
			resumeC = nil
			select {
			case powerEvents <- pendingSleep:
			default:
			}
		}
	}
}

// serviceStderrTo: a service's standard error leads nowhere, and some of the runtime's last words (an access violation
// with a broken stack, for one) go only there, not to the crash output. As a service, the standard error handle is the file.
func serviceStderrTo(file *os.File) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return
	}
	// Only the handle: the runtime looks it up when it writes. os.Stderr keeps the old one, so the service's ordinary
	// log lines do not fill the file.
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(file.Fd()))
}

func sleptDuration(suspendedAt, resumedAt time.Time) time.Duration {
	if suspendedAt.IsZero() || resumedAt.Before(suspendedAt) {
		return 120 * time.Second
	}
	return resumedAt.Sub(suspendedAt)
}

// install registers this binary as the LocalSystem service and starts it. The service SID (unrestricted) is what the
// kill switch's firewall rules name to let the service's own sockets through.
func install(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "Mistgate Client",
		Description: "Runs the Mistgate VPN connection for the Mistgate app.",
		StartType:   mgr.StartAutomatic,
		SidType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, append([]string{"run"}, args...)...)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Start()
}

func uninstall() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	_, _ = service.Control(svc.Stop)
	for range 50 { // the tunnel and the adapter go down with the process: wait for it before the binary is replaced
		if status, err := service.Query(); err != nil || status.State == svc.Stopped {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	return nil
}
