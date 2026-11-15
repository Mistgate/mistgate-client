package trusttunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxPoolConnections = 8                // The provisional account limit is 16; a second device may share it.
	primaryReserve     = 4                // Keep room on the first connection for _udp2 and _check.
	defaultExtraIdle   = 60 * time.Second // Our server closes an extra connection after it has no streams for this long.
)

// Pool keeps UDP on the first connection and spreads TCP streams across the endpoint's HTTP/2 connections.
type Pool struct {
	ctx       context.Context
	cancel    context.CancelFunc
	config    Config
	primary   *Client
	extras    []*Client
	idleAfter time.Duration

	mu          sync.Mutex
	closed      bool
	connections map[*Client]time.Time
	reserved    map[*Client]int
	dialing     chan struct{}
	changed     chan struct{}
	closeOnce   sync.Once
}

// NewPool creates a pool around the already checked first connection. idleAfter is injectable for local tests.
func NewPool(ctx context.Context, primary *Client, config Config, idleAfter time.Duration) (*Pool, error) {
	if ctx == nil || primary == nil || !validConfig(config) {
		return nil, ErrConfig
	}
	select {
	case <-primary.Done():
		return nil, ErrSession
	default:
	}
	if idleAfter <= 0 {
		idleAfter = defaultExtraIdle
	}
	poolCtx, cancel := context.WithCancel(ctx)
	p := &Pool{
		ctx: poolCtx, cancel: cancel, config: config, primary: primary, idleAfter: idleAfter,
		connections: map[*Client]time.Time{primary: time.Now()}, reserved: make(map[*Client]int), changed: make(chan struct{}),
	}
	go p.maintain()
	go p.watchPrimary(primary)
	return p, nil
}

// Primary returns the first connection, which also carries the shared UDP stream.
func (p *Pool) Primary() *Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.primary
}

// DialTCP picks a connection with room, opening another connection when the live pool is full.
func (p *Pool) DialTCP(ctx context.Context, authority string) (net.Conn, error) {
	if ctx == nil || !validAuthority(authority) {
		return nil, ErrConfig
	}
	client, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialTCP(ctx, authority)
	p.release(client)
	if err != nil {
		return nil, err
	}
	return &pooledConn{Conn: conn, done: func() { p.noteActivity(client) }}, nil
}

// ReplacePrimary starts a fresh session after the first connection dies and closes its extras.
func (p *Pool) ReplacePrimary(client *Client) bool {
	if client == nil {
		return false
	}
	select {
	case <-client.Done():
		return false
	default:
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return false
	}
	old := append([]*Client(nil), p.extras...)
	old = append(old, p.primary)
	p.primary = client
	p.extras = nil
	p.connections = map[*Client]time.Time{client: time.Now()}
	p.reserved = make(map[*Client]int)
	p.signalLocked()
	p.mu.Unlock()
	for _, connection := range old {
		if connection != nil && connection != client {
			_ = connection.Close()
		}
	}
	go p.watchPrimary(client)
	return true
}

// KeepaliveClients returns the live first connection and extras that still carry streams.
func (p *Pool) KeepaliveClients() []*Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	clients := make([]*Client, 0, len(p.extras)+1)
	if p.primary != nil && !clientDone(p.primary) {
		clients = append(clients, p.primary)
	}
	for _, client := range p.extras {
		if clientDone(client) {
			continue
		}
		active, _ := client.Load()
		if active+p.reserved[client] > 0 {
			clients = append(clients, client)
		}
	}
	return clients
}

// ConnectionCount reports the current live pool size.
func (p *Pool) ConnectionCount() int {
	p.mu.Lock()
	removed := p.removeDeadExtrasLocked()
	count := 0
	if !p.closed && p.primary != nil && !clientDone(p.primary) {
		count = 1 + len(p.extras)
	}
	p.mu.Unlock()
	closeClients(removed)
	return count
}

// Close ends the first connection and every extra connection.
func (p *Pool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		clients := append([]*Client(nil), p.extras...)
		if p.primary != nil {
			clients = append(clients, p.primary)
		}
		p.extras = nil
		p.connections = make(map[*Client]time.Time)
		p.reserved = make(map[*Client]int)
		p.signalLocked()
		p.mu.Unlock()
		p.cancel()
		closeClients(clients)
	})
	return nil
}

func (p *Pool) acquire(ctx context.Context) (*Client, error) {
	for {
		p.mu.Lock()
		removed := p.removeDeadExtrasLocked()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			closeClients(removed)
			return nil, ErrSession
		}
		if p.primary == nil || clientDone(p.primary) {
			p.mu.Unlock()
			closeClients(removed)
			return nil, ErrSession
		}
		if client := p.withRoomLocked(); client != nil {
			p.reserveLocked(client)
			p.mu.Unlock()
			closeClients(removed)
			return client, nil
		}
		if len(p.extras)+1 >= maxPoolConnections {
			client := p.leastLoadedLocked()
			if client == nil {
				p.mu.Unlock()
				closeClients(removed)
				return nil, ErrSession
			}
			p.reserveLocked(client)
			p.mu.Unlock()
			closeClients(removed)
			return client, nil
		}
		if p.dialing != nil {
			dialing, changed := p.dialing, p.changed
			p.mu.Unlock()
			closeClients(removed)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-p.ctx.Done():
				return nil, ErrSession
			case <-dialing:
			case <-changed:
			}
			continue
		}
		dialing := make(chan struct{})
		p.dialing = dialing
		p.mu.Unlock()
		closeClients(removed)

		client, err := p.dialExtra(ctx)
		p.mu.Lock()
		if p.dialing == dialing {
			p.dialing = nil
			close(dialing)
			p.signalLocked()
		}
		added := err == nil && !p.closed && p.ctx.Err() == nil && p.primary != nil && !clientDone(p.primary)
		if added {
			p.extras = append(p.extras, client)
			p.connections[client] = time.Now()
			p.signalLocked()
		}
		p.mu.Unlock()
		if !added {
			if client != nil {
				_ = client.Close()
			}
			if err != nil {
				return nil, err
			}
			return nil, ErrSession
		}
		go p.watchExtra(client)
	}
}

func (p *Pool) withRoomLocked() *Client {
	var best *Client
	bestLoad := int(^uint(0) >> 1)
	for index, client := range append([]*Client{p.primary}, p.extras...) {
		if client == nil || clientDone(client) {
			continue
		}
		load, limit := client.Load()
		if limit < 1 {
			limit = 1
		}
		if index == 0 {
			limit -= primaryReserve
			if limit < 1 {
				limit = 1
			}
		}
		load += p.reserved[client]
		if load < limit && load < bestLoad {
			best, bestLoad = client, load
		}
	}
	return best
}

func (p *Pool) leastLoadedLocked() *Client {
	var best *Client
	bestLoad := int(^uint(0) >> 1)
	for _, client := range append([]*Client{p.primary}, p.extras...) {
		if client == nil || clientDone(client) {
			continue
		}
		load, _ := client.Load()
		load += p.reserved[client]
		if load < bestLoad {
			best, bestLoad = client, load
		}
	}
	return best
}

func (p *Pool) reserveLocked(client *Client) {
	p.reserved[client]++
	p.connections[client] = time.Now()
	p.signalLocked()
}

func (p *Pool) release(client *Client) {
	p.mu.Lock()
	if p.reserved[client] > 0 {
		p.reserved[client]--
	}
	p.connections[client] = time.Now()
	p.signalLocked()
	p.mu.Unlock()
}

func (p *Pool) noteActivity(client *Client) {
	p.mu.Lock()
	if !p.closed {
		p.connections[client] = time.Now()
		p.signalLocked()
	}
	p.mu.Unlock()
}

func (p *Pool) dialExtra(ctx context.Context) (*Client, error) {
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	client, err := Dial(dialCtx, p.config)
	if err != nil {
		return nil, err
	}
	if err := client.Check(dialCtx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

func (p *Pool) watchPrimary(client *Client) {
	select {
	case <-p.ctx.Done():
		return
	case <-client.Done():
	}
	p.mu.Lock()
	if p.closed || p.primary != client {
		p.mu.Unlock()
		return
	}
	extras := append([]*Client(nil), p.extras...)
	p.extras = nil
	for _, extra := range extras {
		delete(p.connections, extra)
		delete(p.reserved, extra)
	}
	p.signalLocked()
	p.mu.Unlock()
	closeClients(extras)
}

func (p *Pool) watchExtra(client *Client) {
	select {
	case <-p.ctx.Done():
		return
	case <-client.Done():
	}
	p.removeExtra(client)
}

func (p *Pool) removeExtra(client *Client) {
	p.mu.Lock()
	for index, extra := range p.extras {
		if extra == client {
			p.extras = append(p.extras[:index], p.extras[index+1:]...)
			delete(p.connections, client)
			delete(p.reserved, client)
			p.signalLocked()
			break
		}
	}
	p.mu.Unlock()
	_ = client.Close()
}

func (p *Pool) maintain() {
	interval := p.idleAfter / 4
	if interval > time.Second {
		interval = time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			_ = p.Close()
			return
		case now := <-ticker.C:
			p.reap(now)
		}
	}
}

func (p *Pool) reap(now time.Time) {
	p.mu.Lock()
	removed := p.removeDeadExtrasLocked()
	kept := p.extras[:0]
	for _, client := range p.extras {
		load, _ := client.Load()
		if load+p.reserved[client] > 0 {
			kept = append(kept, client)
			continue
		}
		idleSince := p.connections[client]
		if idleSince.IsZero() {
			idleSince = now
			p.connections[client] = now
		}
		if now.Sub(idleSince) < p.idleAfter {
			kept = append(kept, client)
			continue
		}
		removed = append(removed, client)
		delete(p.connections, client)
		delete(p.reserved, client)
	}
	if len(kept) != len(p.extras) {
		p.extras = kept
		p.signalLocked()
	}
	p.mu.Unlock()
	closeClients(removed)
}

func (p *Pool) removeDeadExtrasLocked() []*Client {
	removed := make([]*Client, 0)
	kept := p.extras[:0]
	for _, client := range p.extras {
		if clientDone(client) {
			removed = append(removed, client)
			delete(p.connections, client)
			delete(p.reserved, client)
			continue
		}
		kept = append(kept, client)
	}
	if len(kept) != len(p.extras) {
		p.extras = kept
		p.signalLocked()
	}
	return removed
}

func (p *Pool) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func clientDone(client *Client) bool {
	select {
	case <-client.Done():
		return true
	default:
		return false
	}
}

func closeClients(clients []*Client) {
	for _, client := range clients {
		if client != nil {
			_ = client.Close()
		}
	}
}

type pooledConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *pooledConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	if err != nil {
		c.once.Do(c.done)
	}
	return n, err
}

func (c *pooledConn) Write(payload []byte) (int, error) {
	n, err := c.Conn.Write(payload)
	if err != nil {
		c.once.Do(c.done)
	}
	return n, err
}

func (c *pooledConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.done)
	return err
}

func (c *pooledConn) CloseWrite() error {
	conn, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("TrustTunnel stream does not support half close")
	}
	return conn.CloseWrite()
}

func (c *pooledConn) CloseRead() error {
	conn, ok := c.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.New("TrustTunnel stream does not support read close")
	}
	err := conn.CloseRead()
	if err != nil {
		c.once.Do(c.done)
	}
	return err
}

var _ net.Conn = (*pooledConn)(nil)
var _ io.Reader = (*pooledConn)(nil)
