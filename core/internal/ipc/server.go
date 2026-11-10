package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

const (
	ServiceVersion = "0.0.1"
	API            = 0
	DefaultQueue   = 64
)

type Server struct {
	Manager   *session.Manager
	Diag      *diag.Runner
	Subs      *subs.Store
	Settings  *settings.Store
	Logs      *LogStore
	Logger    *slog.Logger
	QueueSize int
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn, trusted bool) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	queueSize := s.QueueSize
	if queueSize < 1 {
		queueSize = DefaultQueue
	}
	client := newClient(conn, queueSize)
	defer client.close()
	go func() {
		select {
		case <-ctx.Done():
			client.close()
		case <-client.done:
		}
	}()

	var subscription *session.Subscription
	var cancelRelay context.CancelFunc
	defer func() {
		if cancelRelay != nil {
			cancelRelay()
		}
		if subscription != nil {
			subscription.Close()
		}
	}()
	reader := bufio.NewReaderSize(conn, 32*1024)
	for {
		line, err := ReadLine(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrLineTooLong) && !errors.Is(err, ErrUnterminatedLine) {
				logger.Debug("IPC read failed", "error", err)
			}
			return
		}
		request, parseError := ParseRequest(line)
		if parseError != nil {
			response, _ := MarshalResponse(Response{ID: json.RawMessage("null"), Error: parseError})
			if !client.enqueue(response) {
				return
			}
			continue
		}
		result, nextSubscription, rpcError := s.dispatch(ctx, request, trusted)
		response := Response{ID: request.ID, Result: result, Error: rpcError}
		encoded, marshalErr := MarshalResponse(response)
		if marshalErr != nil || !client.enqueue(encoded) {
			return
		}
		if nextSubscription != nil {
			if subscription != nil {
				if cancelRelay != nil {
					cancelRelay()
				}
				subscription.Close()
			}
			subscription = nextSubscription
			relayContext, relayCancel := context.WithCancel(ctx)
			cancelRelay = relayCancel
			go client.forwardEvents(relayContext, subscription.C)
		}
	}
}

func (s *Server) dispatch(ctx context.Context, request Request, trusted bool) (any, *session.Subscription, *RPCError) {
	if !trusted && request.Method != "status" {
		return nil, nil, &RPCError{Code: "not_trusted", Message: "caller is not trusted"}
	}
	if s.Manager == nil {
		return nil, nil, &RPCError{Code: "service_error", Message: "session manager is unavailable"}
	}
	switch request.Method {
	case "hello":
		var params struct {
			Client string `json:"client"`
		}
		if !decodeParams(request.Params, &params) || strings.TrimSpace(params.Client) == "" {
			return nil, nil, badParams()
		}
		return map[string]any{"service": ServiceVersion, "trusted": trusted, "api": API}, nil, nil
	case "status":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		status, err := s.Manager.Status(ctx)
		if err != nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "could not read connection status"}
		}
		return status, nil, nil
	case "connect":
		var params map[string]json.RawMessage
		if !decodeParams(request.Params, &params) || params == nil {
			return nil, nil, badParams()
		}
		for key := range params {
			if key != "server" && key != "protocol" && key != "sub" {
				return nil, nil, badParams()
			}
		}
		target := engine.Target{Server: "auto", Protocol: "auto"}
		if serverJSON, exists := params["server"]; exists {
			var server string
			if json.Unmarshal(serverJSON, &server) != nil || strings.TrimSpace(server) == "" {
				return nil, nil, badParams()
			}
			target.Server = server
		}
		if protocolJSON, exists := params["protocol"]; exists {
			var protocol string
			if json.Unmarshal(protocolJSON, &protocol) != nil {
				return nil, nil, badParams()
			}
			switch protocol {
			case "auto", "hysteria2", "awg":
				target.Protocol = protocol
			default:
				return nil, nil, badParams()
			}
		}
		if subJSON, exists := params["sub"]; exists {
			if json.Unmarshal(subJSON, &target.Sub) != nil {
				return nil, nil, badParams()
			}
		}
		if s.Settings != nil {
			// what "connect when Windows starts" will connect to
			server, _ := json.Marshal(target.Server)
			sub, _ := json.Marshal(target.Sub)
			_, _ = s.Settings.Set(map[string]json.RawMessage{"last_server": server, "last_sub": sub})
		}
		status, err := s.Manager.Connect(ctx, target)
		if err != nil {
			code := "service_error"
			var codeError *session.CodeError
			if errors.As(err, &codeError) {
				code = codeError.Code
			}
			return nil, nil, &RPCError{Code: code, Message: "connection could not be started"}
		}
		return status, nil, nil
	case "disconnect":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		status, err := s.Manager.Disconnect(ctx)
		if err != nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "connection could not be stopped"}
		}
		return status, nil, nil
	case "settings.get":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Settings == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "settings store is unavailable"}
		}
		return s.Settings.Get(), nil, nil
	case "settings.set":
		var patch map[string]json.RawMessage
		if !decodeParams(request.Params, &patch) || patch == nil {
			return nil, nil, badParams()
		}
		if s.Settings == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "settings store is unavailable"}
		}
		configured, err := s.Settings.Set(patch)
		if errors.Is(err, settings.ErrBadParams) {
			return nil, nil, badParams()
		}
		if err != nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "settings could not be saved"}
		}
		return configured, nil, nil
	case "diag.run":
		var params struct {
			Sub string `json:"sub"`
		}
		if !decodeParams(request.Params, &params) {
			return nil, nil, badParams()
		}
		if s.Diag == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "diagnostics are unavailable"}
		}
		return s.Diag.Start(params.Sub), nil, nil
	case "diag.get", "diag.cancel":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Diag == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "diagnostics are unavailable"}
		}
		if request.Method == "diag.cancel" {
			return s.Diag.Cancel(), nil, nil
		}
		return s.Diag.Get(), nil, nil
	case "log.get":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		entries := []LogEntry{}
		if s.Logs != nil {
			entries = s.Logs.Entries()
		}
		return map[string]any{"entries": entries}, nil, nil
	case "subscribe":
		var params struct {
			Events []string `json:"events"`
		}
		if !decodeParams(request.Params, &params) || params.Events == nil {
			return nil, nil, badParams()
		}
		subscription, err := s.Manager.Events().Subscribe(params.Events)
		if err != nil {
			return nil, nil, badParams()
		}
		return map[string]any{}, subscription, nil
	case "subs.list":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Subs == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
		}
		return map[string]any{"subs": s.Subs.List()}, nil, nil
	case "subs.preview", "subs.add":
		var params struct {
			Text *string `json:"text"`
		}
		if !decodeParams(request.Params, &params) || params.Text == nil {
			return nil, nil, badParams()
		}
		if s.Subs == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
		}
		var result any
		var err error
		if request.Method == "subs.preview" {
			result, err = s.Subs.Preview(ctx, *params.Text)
		} else {
			result, err = s.Subs.Add(ctx, *params.Text)
		}
		if err != nil {
			return nil, nil, subscriptionRPCError(err)
		}
		return result, nil, nil
	case "subs.refresh":
		var params struct {
			ID string `json:"id"`
		}
		if !decodeParams(request.Params, &params) || params.ID == "" {
			return nil, nil, badParams()
		}
		if s.Subs == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
		}
		result, err := s.Subs.Refresh(ctx, params.ID)
		if err != nil {
			return nil, nil, subscriptionRPCError(err)
		}
		return result, nil, nil
	case "subs.remove":
		var params struct {
			ID string `json:"id"`
		}
		if !decodeParams(request.Params, &params) || params.ID == "" {
			return nil, nil, badParams()
		}
		if s.Subs == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
		}
		if err := s.Subs.Remove(params.ID); err != nil {
			return nil, nil, subscriptionRPCError(err)
		}
		return map[string]any{}, nil, nil
	default:
		return nil, nil, &RPCError{Code: "unknown_method", Message: "method is not supported"}
	}
}

func subscriptionRPCError(err error) *RPCError {
	var coded *subs.Error
	if errors.As(err, &coded) && coded.Code != "" {
		return &RPCError{Code: coded.Code, Message: "subscription request failed"}
	}
	return &RPCError{Code: "service_error", Message: "subscription request failed"}
}

func decodeParams(raw json.RawMessage, target any) bool {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func emptyParams(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var fields map[string]json.RawMessage
	return json.Unmarshal(raw, &fields) == nil && len(fields) == 0
}

type clientConn struct {
	conn   net.Conn
	out    chan []byte
	done   chan struct{}
	once   sync.Once
	closed bool
	mu     sync.Mutex
}

func newClient(conn net.Conn, queueSize int) *clientConn {
	client := &clientConn{conn: conn, out: make(chan []byte, queueSize), done: make(chan struct{})}
	go client.writeLoop()
	return client
}

func (c *clientConn) enqueue(message []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	select {
	case c.out <- message:
		return true
	default:
		c.closeLocked()
		return false
	}
}

func (c *clientConn) forwardEvents(ctx context.Context, events <-chan session.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case event, ok := <-events:
			if !ok {
				if ctx.Err() == nil {
					c.close()
				}
				return
			}
			line, err := json.Marshal(event)
			if err != nil || !c.enqueue(append(line, '\n')) {
				return
			}
		}
	}
}

func (c *clientConn) writeLoop() {
	for {
		select {
		case <-c.done:
			return
		case message := <-c.out:
			for len(message) > 0 {
				written, err := c.conn.Write(message)
				if err != nil || written == 0 {
					c.close()
					return
				}
				message = message[written:]
			}
		}
	}
}

func (c *clientConn) close() {
	c.mu.Lock()
	c.closeLocked()
	c.mu.Unlock()
}

func (c *clientConn) closeLocked() {
	c.once.Do(func() {
		c.closed = true
		close(c.done)
		_ = c.conn.Close()
	})
}

func Run(ctx context.Context, manager *session.Manager, logger *slog.Logger, store *subs.Store, settingsStore *settings.Store, diagnostics *diag.Runner, logs *LogStore) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{Manager: manager, Diag: diagnostics, Logger: logger.With("src", "ipc"), Subs: store, Settings: settingsStore, Logs: logs}
	if diagnostics != nil {
		defer diagnostics.Cancel()
	}
	if store != nil {
		go func() {
			for {
				select {
				case <-runCtx.Done():
					return
				case <-store.Changes():
					manager.Events().Publish("subs", map[string]any{"subs": store.List()})
				}
			}
		}()
	}
	if settingsStore != nil {
		go func() {
			for {
				select {
				case <-runCtx.Done():
					return
				case <-settingsStore.Changes():
					manager.SettingsChanged()
					manager.Events().Publish("settings", settingsStore.Get())
				}
			}
		}()
	}
	return runPipeServer(runCtx, server)
}
