//go:build windows

package ipc

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const (
	PipeName                    = `\\.\pipe\mistgate-client`
	maxPipeConnections          = 8
	maxUntrustedPipeConnections = maxPipeConnections - 1
)

type pipeConnectionSlots struct {
	active   chan struct{}
	regular  chan struct{}
	reserved chan struct{}
}

type pipeConnectionPermit uint8

const (
	regularPermit pipeConnectionPermit = iota
	reservedPermit
)

func newPipeConnectionSlots() *pipeConnectionSlots {
	return &pipeConnectionSlots{
		active:   make(chan struct{}, maxPipeConnections),
		regular:  make(chan struct{}, maxUntrustedPipeConnections),
		reserved: make(chan struct{}, 1),
	}
}

func (s *pipeConnectionSlots) acquire() (pipeConnectionPermit, bool) {
	select {
	case s.active <- struct{}{}:
	default:
		return 0, false
	}
	select {
	case s.regular <- struct{}{}:
		return regularPermit, true
	default:
		select {
		case s.reserved <- struct{}{}:
			return reservedPermit, true
		default:
			<-s.active
			return 0, false
		}
	}
}

func (s *pipeConnectionSlots) promoteUntrusted(permit pipeConnectionPermit) (pipeConnectionPermit, bool) {
	if permit == regularPermit {
		return permit, true
	}
	select {
	case s.regular <- struct{}{}:
		<-s.reserved
		return regularPermit, true
	default:
		return permit, false
	}
}

func (s *pipeConnectionSlots) releasePermit(permit pipeConnectionPermit) {
	if permit == reservedPermit {
		<-s.reserved
	} else {
		<-s.regular
	}
}

func (s *pipeConnectionSlots) release(permit pipeConnectionPermit, holdsPermit bool) {
	if holdsPermit {
		s.releasePermit(permit)
	}
	<-s.active
}

func runPipeServer(ctx context.Context, server *Server) error {
	logger := server.Logger
	if logger == nil {
		logger = slog.Default()
	}
	servicePath, err := executablePath()
	if err != nil {
		return err
	}
	serviceSignature := inspectSignature(servicePath)
	// go-winio v0.6.2 creates server pipes with FILE_PIPE_REJECT_REMOTE_CLIENTS.
	listener, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL(server.callerAccess.AllowedSIDs()),
		MessageMode:        false,
		InputBufferSize:    32 * 1024,
		OutputBufferSize:   32 * 1024,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var clients sync.WaitGroup
	defer clients.Wait()
	slots := newPipeConnectionSlots()
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		permit, acquired := slots.acquire()
		if !acquired {
			_ = conn.Close()
			continue
		}
		clients.Add(1)
		// The caller is checked beside the accept loop, after its path is restricted to a local fixed drive.
		go func(conn net.Conn, permit pipeConnectionPermit) {
			defer clients.Done()
			holdsPermit := true
			defer func() { slots.release(permit, holdsPermit) }()
			pid, imagePath, callerSignature, callerAllowed, callerSID, inspectErr := inspectPipeCaller(conn, servicePath, serviceSignature.Signed, server.callerAccess != nil)
			facts := CallerFacts{
				PID:                     pid,
				ServicePath:             servicePath,
				CallerPath:              imagePath,
				ServiceSigned:           serviceSignature.Signed,
				ServiceSignatureValid:   serviceSignature.Valid,
				ServiceSignerThumbprint: serviceSignature.Thumbprint,
				CallerSigned:            callerSignature.Signed,
				CallerSignatureValid:    callerSignature.Valid,
				CallerSignerThumbprint:  callerSignature.Thumbprint,
			}
			if !serviceSignature.Signed {
				facts.DevelopmentClientPath = developmentClientPath()
			}
			trusted := false
			var allowListWriteErr error
			if inspectErr == nil && callerAllowed {
				if server.callerAccess == nil {
					trusted = IsCallerTrusted(facts)
				} else {
					trusted, allowListWriteErr = server.callerAccess.IsTrusted(facts, callerSID)
				}
			}
			if trusted {
				slots.releasePermit(permit)
				holdsPermit = false
			} else if promoted, ok := slots.promoteUntrusted(permit); !ok {
				_ = conn.Close()
				return
			} else {
				permit = promoted
			}
			if inspectErr != nil {
				logger.Warn("IPC caller check failed", "pid", pid, "trusted", false) // no path, no error text: both name the Windows user
			} else {
				logger.Info("IPC caller checked", "pid", pid, "trusted", trusted)
			}
			if allowListWriteErr != nil {
				logger.Warn("IPC allow-list write failed", "code", "write_failed")
			}
			server.ServeConn(ctx, conn, trusted)
		}(conn, permit)
	}
}

// pipeSDDL names LocalSystem the pipe's owner when the service runs as LocalSystem (its default owner would be the
// Administrators group). The window cannot open a LocalSystem process to read its path, so the owner is how it knows
// the pipe belongs to the service: a program without those rights that takes the name first cannot be that owner.
// A console run (development) keeps its own owner: the window checks that one by path.
func pipeSDDL(allowedSIDs []string) string {
	sddl := PipeSDDLForUsers(allowedSIDs)
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return "O:SY" + sddl
	}
	return sddl
}

func inspectPipeCaller(conn net.Conn, servicePath string, serviceSigned, readCallerSID bool) (uint32, string, signatureFacts, bool, string, error) {
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, "", signatureFacts{}, false, "", windows.ERROR_INVALID_HANDLE
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &pid); err != nil {
		return 0, "", signatureFacts{}, false, "", err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return pid, "", signatureFacts{}, false, "", err
	}
	defer windows.CloseHandle(process)
	imagePath, err := processImagePath(process)
	if err != nil {
		return pid, "", signatureFacts{}, false, "", err
	}
	callerSignature, allowed := inspectCallerSignature(imagePath, servicePath, serviceSigned)
	if !readCallerSID {
		return pid, imagePath, callerSignature, allowed, "", nil
	}
	callerSID, err := processUserSID(process)
	if err != nil {
		return pid, imagePath, signatureFacts{}, false, "", err
	}
	return pid, imagePath, callerSignature, allowed, callerSID, nil
}

func processUserSID(process windows.Handle) (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", windows.ERROR_INVALID_DATA
	}
	return user.User.Sid.String(), nil
}
