package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/session"
)

func TestReadLineFramingAndLimit(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr error
	}{
		{name: "newline frame", input: "{\"id\":1}\n", want: len("{\"id\":1}")},
		{name: "exact limit", input: strings.Repeat("x", MaxLineBytes) + "\n", want: MaxLineBytes},
		{name: "over limit", input: strings.Repeat("x", MaxLineBytes+1) + "\n", wantErr: ErrLineTooLong},
		{name: "unterminated", input: "{\"id\":1}", wantErr: ErrUnterminatedLine},
		{name: "empty stream", input: "", wantErr: io.EOF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line, err := ReadLine(bufio.NewReader(strings.NewReader(test.input)))
			if test.wantErr != nil {
				if err != test.wantErr {
					t.Fatalf("ReadLine error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(line) != test.want {
				t.Fatalf("line length = %d, want %d", len(line), test.want)
			}
		})
	}
}

func TestParseRequestAndDispatchErrors(t *testing.T) {
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}))
	defer manager.Close()
	server := &Server{Manager: manager, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tests := []struct {
		name       string
		line       string
		trusted    bool
		wantCode   string
		wantResult bool
	}{
		{name: "unknown method", line: `{"id":7,"method":"unknown","params":{}}`, trusted: true, wantCode: "unknown_method"},
		{name: "bad connect params", line: `{"id":8,"method":"connect","params":{"protocol":"vless"}}`, trusted: true, wantCode: "bad_params"},
		{name: "null connect value", line: `{"id":13,"method":"connect","params":{"server":null}}`, trusted: true, wantCode: "bad_params"},
		{name: "bad JSON params", line: `{"id":9,"method":"hello","params":{"client":7}}`, trusted: true, wantCode: "bad_params"},
		{name: "untrusted connect", line: `{"id":10,"method":"connect","params":{}}`, trusted: false, wantCode: "not_trusted"},
		{name: "untrusted hello", line: `{"id":12,"method":"hello","params":{"client":"0.0.1"}}`, trusted: false, wantCode: "not_trusted"},
		{name: "untrusted status", line: `{"id":11,"method":"status","params":{}}`, trusted: false, wantResult: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, parseErr := ParseRequest([]byte(test.line))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			result, _, rpcErr := server.dispatch(context.Background(), request, test.trusted)
			if test.wantCode != "" {
				if rpcErr == nil || rpcErr.Code != test.wantCode {
					t.Fatalf("dispatch error = %#v, want code %q", rpcErr, test.wantCode)
				}
				return
			}
			if rpcErr != nil || result == nil {
				t.Fatalf("dispatch result = %#v, error = %#v", result, rpcErr)
			}
		})
	}

	if _, err := ParseRequest([]byte(`{"id":{},"method":"status"}`)); err == nil || err.Code != "bad_params" {
		t.Fatalf("invalid request id error = %#v, want bad_params", err)
	}
	if _, err := ParseRequest([]byte(`{"id":1,"method":"status"} {}`)); err == nil || err.Code != "bad_params" {
		t.Fatalf("trailing JSON error = %#v, want bad_params", err)
	}
}

func TestSlowClientIsDroppedWhenWriteQueueFills(t *testing.T) {
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}))
	defer manager.Close()
	server := &Server{Manager: manager, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), QueueSize: 1}
	serverConn, clientConn := netPipe(t)
	serveDone := make(chan struct{})
	go func() {
		server.ServeConn(context.Background(), serverConn, true)
		close(serveDone)
	}()

	request := []byte("{\"id\":1,\"method\":\"status\",\"params\":{}}\n")
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for range 100 {
			if _, err := clientConn.Write(request); err != nil {
				return
			}
		}
	}()
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server kept a client whose outbound queue was blocked")
	}
	_ = clientConn.Close()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("client writer stayed blocked after server dropped the connection")
	}
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	return net.Pipe()
}

func TestMarshalResponseIsJSONLine(t *testing.T) {
	line, err := MarshalResponse(Response{ID: json.RawMessage("2"), Result: map[string]bool{"trusted": true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(line), "\n") {
		t.Fatalf("response missing newline: %q", line)
	}
}
