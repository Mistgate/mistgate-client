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
	"time"

	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/proxy"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

// PingFunc is one round trip to a profile's server outside the tunnel (diag.Handshake in the real service).
type PingFunc func(ctx context.Context, p profile.Profile, timeout time.Duration) (time.Duration, error)

const (
	pingTimeout  = 3 * time.Second  // per server
	pingTotal    = 20 * time.Second // per request; servers not reached by then are left out
	pingParallel = 8
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
	Geo       *geo.Store
	Routes    func() geo.Routes
	Check     func(name string) geo.Check // routes.check
	Ping      PingFunc                    // servers.ping
	Logs      *LogStore
	Proxy     *proxy.Proxy
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
			// what "connect when Windows starts" will connect to, and that the user left the VPN on
			server, _ := json.Marshal(target.Server)
			sub, _ := json.Marshal(target.Sub)
			_, _ = s.Settings.Set(map[string]json.RawMessage{"last_server": server, "last_sub": sub, "last_on": json.RawMessage(`true`)})
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
		if s.Settings != nil {
			_, _ = s.Settings.Set(map[string]json.RawMessage{"last_on": json.RawMessage(`false`)})
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
	case "routes.get":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Routes == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route state is unavailable"}
		}
		return s.Routes(), nil, nil
	case "routes.update":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Geo == nil || s.Routes == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route rules store is unavailable"}
		}
		// Not awaited: the downloads take up to a minute and this connection's other calls must not wait behind them.
		// The `routes` event says when they are done.
		go s.Geo.Update(context.Background(), s.Routes().Effective)
		return s.Routes(), nil, nil
	case "routes.lists":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Geo == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route lists are unavailable"}
		}
		return s.Geo.Lists(), nil, nil
	case "routes.set":
		var patch map[string]json.RawMessage
		if !decodeParams(request.Params, &patch) || patch == nil {
			return nil, nil, badParams()
		}
		if s.Geo == nil || s.Routes == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route rules store is unavailable"}
		}
		rules := s.Geo.GetRules()
		for key, raw := range patch {
			switch key {
			case "direct":
				if !mergeSelection(raw, &rules.Direct) {
					return nil, nil, badParams()
				}
			case "vpn":
				if !mergeSelection(raw, &rules.VPN) {
					return nil, nil, badParams()
				}
			case "block":
				if !mergeSelection(raw, &rules.Block) {
					return nil, nil, badParams()
				}
			default:
				return nil, nil, badParams()
			}
		}
		if _, _, err := s.Geo.SetRules(rules); errors.Is(err, geo.ErrBadRules) {
			return nil, nil, badParams()
		} else if err != nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route rules could not be saved"}
		}
		return s.Routes(), nil, nil
	case "routes.check":
		var params struct {
			Site string `json:"site"`
		}
		if !decodeParams(request.Params, &params) {
			return nil, nil, badParams()
		}
		name, ok := geo.NormalizeSite(params.Site)
		if !ok {
			return nil, nil, badParams()
		}
		if s.Check == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route check is unavailable"}
		}
		return s.Check(name), nil, nil
	case "routes.dismiss":
		var params struct {
			Route string `json:"route"`
			Site  string `json:"site"`
		}
		if !decodeParams(request.Params, &params) || params.Route != "direct" && params.Route != "vpn" {
			return nil, nil, badParams()
		}
		if s.Geo == nil || s.Routes == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "route rules store is unavailable"}
		}
		if !s.Geo.Dismiss(params.Route == "vpn", params.Site) {
			return nil, nil, badParams()
		}
		return s.Routes(), nil, nil
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
		// the proxy follows its switches before this answer goes out, so a proxy.get right after sees the result
		_, onKey := patch["proxy"]
		_, lanKey := patch["proxy_lan"]
		if s.Proxy != nil && (onKey || lanKey) {
			s.Proxy.Reload()
		}
		return configured, nil, nil
	case "proxy.get", "proxy.password":
		if !emptyParams(request.Params) {
			return nil, nil, badParams()
		}
		if s.Proxy == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "local proxy is unavailable"}
		}
		// The answer carries the password: it is not logged, not sent as an event, and goes to this caller only.
		if request.Method == "proxy.password" {
			state, err := s.Proxy.NewPassword()
			if err != nil {
				return nil, nil, &RPCError{Code: "service_error", Message: "the new password could not be saved"}
			}
			return state, nil, nil
		}
		state := s.Proxy.State()
		if s.Logger != nil {
			s.Logger.Debug("proxy state read", "clients", state.Clients)
		}
		return state, nil, nil
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
	case "servers.ping":
		var params struct {
			Sub     string   `json:"sub"`
			Servers []string `json:"servers"`
		}
		if !decodeParams(request.Params, &params) {
			return nil, nil, badParams()
		}
		if s.Subs == nil || s.Ping == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "latency check is unavailable"}
		}
		rtt, err := s.pingServers(ctx, params.Sub, params.Servers)
		if err != nil {
			return nil, nil, subscriptionRPCError(err)
		}
		if s.Logger != nil {
			s.Logger.Debug("servers pinged", "answered", len(rtt))
		}
		return map[string]any{"rtt": rtt}, nil, nil
	case "servers.hosts":
		var params struct {
			Sub string `json:"sub"`
		}
		if !decodeParams(request.Params, &params) {
			return nil, nil, badParams()
		}
		if s.Subs == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
		}
		hosts, err := s.serverHosts(ctx, params.Sub)
		if err != nil {
			return nil, nil, subscriptionRPCError(err)
		}
		return map[string]any{"hosts": hosts}, nil, nil
	case "subs.link":
		var params struct {
			ID string `json:"id"`
		}
		if !decodeParams(request.Params, &params) || params.ID == "" {
			return nil, nil, badParams()
		}
		if s.Subs == nil {
			return nil, nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
		}
		link, err := s.Subs.Link(params.ID)
		if err != nil {
			return nil, nil, subscriptionRPCError(err)
		}
		return map[string]any{"url": link}, nil, nil
	default:
		return nil, nil, &RPCError{Code: "unknown_method", Message: "method is not supported"}
	}
}

// ServerHost is where a server is: the name or address its profile connects to, and the addresses that name has now.
type ServerHost struct {
	Host string   `json:"host"`
	IPs  []string `json:"ips"`
}

// serverHosts tells the window where each server of a subscription is, so that two servers of one country can be told
// apart. The addresses are the user's own subscription: they go to the trusted window only and never into the log.
func (s *Server) serverHosts(ctx context.Context, sub string) (map[string]ServerHost, error) {
	all := s.Subs.List()
	if sub == "" && len(all) > 0 {
		sub = all[0].ID
	}
	known := false
	for _, item := range all {
		known = known || item.ID == sub
	}
	if !known {
		return nil, &subs.Error{Code: "unknown_subscription"}
	}
	profiles, err := s.Subs.Profiles()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	hosts := make(map[string]ServerHost)
	resolved := make(map[string][]string) // by name: one lookup for the paths of one node
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, p := range profiles {
		host := ""
		switch {
		case p.Sub != sub:
			continue
		case p.Hy2 != nil:
			host = p.Hy2.Host
		case p.AWG != nil:
			host = p.AWG.EndpointHost
		}
		if host == "" {
			continue
		}
		hosts[p.ID] = ServerHost{Host: host, IPs: []string{}}
		if _, seen := resolved[host]; seen || net.ParseIP(host) != nil {
			continue
		}
		resolved[host] = nil
		wait.Add(1)
		go func() {
			defer wait.Done()
			if ips, err := net.DefaultResolver.LookupHost(ctx, host); err == nil {
				mu.Lock()
				resolved[host] = ips
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	for id, entry := range hosts {
		if ips := resolved[entry.Host]; len(ips) > 0 {
			entry.IPs = ips
			hosts[id] = entry
		}
	}
	return hosts, nil
}

// pingServers measures the servers of a subscription (all of them when ids is empty; an empty sub is the first
// subscription) and returns milliseconds by server id. A server that did not answer is not in the map.
func (s *Server) pingServers(ctx context.Context, sub string, ids []string) (map[string]int64, error) {
	all := s.Subs.List()
	if sub == "" && len(all) > 0 {
		sub = all[0].ID
	}
	known := false
	for _, item := range all {
		known = known || item.ID == sub
	}
	if !known {
		return nil, &subs.Error{Code: "unknown_subscription"}
	}
	profiles, err := s.Subs.Profiles()
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	ctx, cancel := context.WithTimeout(ctx, pingTotal)
	defer cancel()
	rtt := make(map[string]int64)
	var mu sync.Mutex
	var wait sync.WaitGroup
	slots := make(chan struct{}, pingParallel)
launch:
	for _, p := range profiles {
		if p.Sub != sub || len(want) > 0 && !want[p.ID] {
			continue
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break launch
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer func() { <-slots }()
			if d, err := s.Ping(ctx, p, pingTimeout); err == nil {
				mu.Lock()
				rtt[p.ID] = max(d.Milliseconds(), 1)
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	return rtt, nil
}

func subscriptionRPCError(err error) *RPCError {
	var coded *subs.Error
	if errors.As(err, &coded) && coded.Code != "" {
		message := "subscription request failed"
		if coded.Notice != "" {
			message = coded.Notice
		}
		return &RPCError{Code: coded.Code, Message: message}
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

func mergeSelection(raw json.RawMessage, selection *geo.Selection) bool {
	var patch map[string]json.RawMessage
	if json.Unmarshal(raw, &patch) != nil || patch == nil {
		return false
	}
	for key, value := range patch {
		var items []string
		if key != "collections" && key != "sites" || strings.TrimSpace(string(value)) == "null" || json.Unmarshal(value, &items) != nil || items == nil {
			return false
		}
		if key == "collections" {
			selection.Collections = items
		} else {
			selection.Sites = items
		}
	}
	return true
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

func Run(ctx context.Context, manager *session.Manager, logger *slog.Logger, store *subs.Store, settingsStore *settings.Store, diagnostics *diag.Runner, logs *LogStore, geoStore *geo.Store, routes func() geo.Routes, check func(string) geo.Check, ping PingFunc, localProxy *proxy.Proxy) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{Manager: manager, Diag: diagnostics, Logger: logger.With("src", "ipc"), Subs: store, Settings: settingsStore, Geo: geoStore, Routes: routes, Check: check, Ping: ping, Logs: logs, Proxy: localProxy}
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
					if localProxy != nil {
						localProxy.Reload() // idempotent: settings.set has done it already for the proxy's own keys
					}
				}
			}
		}()
	}
	if geoStore != nil {
		go func() {
			for {
				select {
				case <-runCtx.Done():
					return
				case <-geoStore.Changes():
					manager.RoutesChanged()
				}
			}
		}()
		go publishSuggestions(runCtx, manager.Events(), geoStore, routes)
	}
	return runPipeServer(runCtx, server)
}
