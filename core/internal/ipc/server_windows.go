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
	PipeName = `\\.\pipe\mistgate-client`
	PipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
)

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
		SecurityDescriptor: PipeSDDL,
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
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		pid, imagePath, callerSignature, inspectErr := inspectPipeCaller(conn)
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
		trusted := inspectErr == nil && IsCallerTrusted(facts)
		if inspectErr != nil {
			logger.Warn("IPC caller check failed", "pid", pid, "image", imagePath, "trusted", false, "error", inspectErr)
		} else {
			logger.Info("IPC caller checked", "pid", pid, "image", imagePath, "trusted", trusted)
		}
		clients.Add(1)
		go func(conn net.Conn, trusted bool) {
			defer clients.Done()
			server.ServeConn(ctx, conn, trusted)
		}(conn, trusted)
	}
}

func inspectPipeCaller(conn net.Conn) (uint32, string, signatureFacts, error) {
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, "", signatureFacts{}, windows.ERROR_INVALID_HANDLE
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &pid); err != nil {
		return 0, "", signatureFacts{}, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return pid, "", signatureFacts{}, err
	}
	defer windows.CloseHandle(process)
	imagePath, err := processImagePath(process)
	if err != nil {
		return pid, "", signatureFacts{}, err
	}
	return pid, imagePath, inspectSignature(imagePath), nil
}
