//go:build windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	ttclient "github.com/mistgate/mistgate-client/core/internal/trusttunnel"
)

var errTTUnavailable = errors.New("TrustTunnel session unavailable")

// Our server closes a connection with no streams after 60 seconds; the reference server drops live streams after 600 seconds without a new stream.
const ttKeepaliveInterval = 45 * time.Second

// ttRefusalPatience is how long a tunnel that was up keeps redialing against refusals before it takes them for final.
// The server also refuses an account that is at its 16 connections, a connection it is expiring and one whose account
// was just switched off; it forgets a dead connection within about 2.5 to 15 minutes, which frees the places again. A
// variable for the test.
var ttRefusalPatience = 10 * time.Minute

type ttOutbound struct {
	ctx      context.Context
	config   ttclient.Config
	endpoint netip.AddrPort

	mu        sync.RWMutex
	pool      *ttclient.Pool
	fatal     error
	fatalCh   chan struct{}
	fatalOnce sync.Once
	closed    bool

	asking atomic.Bool // one _check at a time decides what a refused stream meant
}

func startTT(ctx context.Context, p *profile.TrustTunnel, endpoints []netip.AddrPort) (*ttOutbound, error) {
	if p == nil || len(endpoints) == 0 {
		return nil, ttclient.ErrConfig
	}
	addresses := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.IsValid() && endpoint.Port() != 0 {
			addresses = append(addresses, endpoint.String())
		}
	}
	if len(addresses) == 0 {
		return nil, ttclient.ErrConfig
	}
	config := ttclient.Config{
		Host: p.Host, Addresses: addresses, SNI: p.SNI, Username: p.Username, Password: p.Password,
		HasIPv6: p.HasIPv6, Insecure: p.Insecure, PinSHA256: p.PinSHA256, HasPin: p.HasPin, Certs: p.Certs, Name: p.Name,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, ttclient.ErrEndpoint
			}
			return (directOutbound{}).DialTCP(ctx, endpoint)
		},
	}
	client, err := ttclient.Dial(ctx, config)
	if err != nil {
		return nil, err
	}
	if err := client.Check(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	endpoint := client.Endpoint()
	// Keep reconnects on the endpoint whose bypass route the adapter will install.
	config.Addresses = []string{endpoint.String()}
	pool, err := ttclient.NewPool(ctx, client, config, 0)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	out := &ttOutbound{ctx: ctx, config: config, endpoint: endpoint, pool: pool, fatalCh: make(chan struct{})}
	go out.reconnect()
	go out.keepalive()
	return out, nil
}

func (o *ttOutbound) Endpoint() netip.AddrPort { return o.endpoint }

func (o *ttOutbound) current() (*ttclient.Pool, error) {
	o.mu.RLock()
	if o.fatal != nil {
		err := o.fatal
		o.mu.RUnlock()
		return nil, err
	}
	if o.closed || o.pool == nil {
		o.mu.RUnlock()
		return nil, errTTUnavailable
	}
	pool := o.pool
	o.mu.RUnlock()
	primary := pool.Primary()
	if primary == nil {
		return nil, errTTUnavailable
	}
	select {
	case <-primary.Done():
		return nil, errTTUnavailable
	default:
		return pool, nil
	}
}

func (o *ttOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	if !target.IsValid() || target.Port() == 0 {
		return nil, ttclient.ErrConfig
	}
	return o.DialAuthority(ctx, target.String())
}

func (o *ttOutbound) DialAuthority(ctx context.Context, authority string) (net.Conn, error) {
	pool, err := o.current()
	if err != nil {
		return nil, err
	}
	primary := pool.Primary()
	conn, err := pool.DialTCP(ctx, authority)
	o.refuse(primary, err)
	return conn, err
}

func (o *ttOutbound) ListenUDP(ctx context.Context) (packetFlow, error) {
	pool, err := o.current()
	if err != nil {
		return nil, err
	}
	primary := pool.Primary()
	if primary == nil {
		return nil, errTTUnavailable
	}
	flow, err := primary.ListenUDP(ctx)
	if err != nil {
		o.refuse(primary, err)
		return nil, err
	}
	return ttPacketFlow{flow: flow, outbound: o, primary: primary}, nil
}

func (o *ttOutbound) reconnect() {
	backoff := time.Second
	// refusedSince is the first refusal since the last success. Refusals alone, for ttRefusalPatience, are final.
	var refusedSince time.Time
	patientlyRefused := func(err error) bool {
		if !ttclient.IsRefusal(err) {
			return false
		}
		if refusedSince.IsZero() {
			refusedSince = time.Now()
		}
		return time.Since(refusedSince) >= ttRefusalPatience
	}
	for {
		pool := o.poolSnapshot()
		if pool == nil {
			return
		}
		client := pool.Primary()
		if client == nil {
			return
		}
		select {
		case <-o.ctx.Done():
			return
		case <-o.fatalCh:
			return
		case <-client.Done():
		}
		if o.ctx.Err() != nil || o.isFatal() {
			return
		}
		if patientlyRefused(client.Err()) {
			o.setFatal(client.Err())
			return
		}
		for {
			if !o.wait(backoff) {
				return
			}
			replacement, err := o.redial()
			if patientlyRefused(err) {
				o.setFatal(err)
				return
			}
			if err != nil {
				backoff = nextTTBackoff(backoff)
				continue
			}
			if !pool.ReplacePrimary(replacement) {
				_ = replacement.Close()
				return
			}
			backoff = time.Second
			refusedSince = time.Time{}
			break
		}
	}
}

func (o *ttOutbound) keepalive() {
	ticker := time.NewTicker(ttKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-o.fatalCh:
			return
		case <-ticker.C:
			pool := o.poolSnapshot()
			if pool == nil {
				return
			}
			primary := pool.Primary()
			clients := pool.KeepaliveClients()
			results := make(chan error, len(clients))
			for _, client := range clients {
				go func(client *ttclient.Client) { results <- client.Check(o.ctx) }(client)
			}
			for range clients {
				o.drop(primary, <-results)
			}
		}
	}
}

func (o *ttOutbound) poolSnapshot() *ttclient.Pool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.pool
}

func (o *ttOutbound) wait(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-o.ctx.Done():
		return false
	case <-o.fatalCh:
		return false
	case <-timer.C:
		return true
	}
}

func (o *ttOutbound) isFatal() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.fatal != nil
}

// refuse takes a refusal seen once the tunnel was up as no final word: the server shows its site to an account that is
// at its connection limit or on a connection it is expiring as well as to a wrong one. The first connection is dropped
// (primary, as it was when the refused call began) so that reconnect redials and decides, with ttRefusalPatience.
// A 5xx is about one destination (502 with a warning: unreachable, timed out, blocked) and is not a refusal.
//
// A refused stream is asked about first: a _check on the same connection. Some servers answer 4xx for one destination,
// and dropping the connection for that would cut every program off each time one of them tried such an address.
func (o *ttOutbound) refuse(primary *ttclient.Client, err error) {
	if primary == nil || !ttclient.IsRefusal(err) || !o.asking.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer o.asking.Store(false)
		o.drop(primary, primary.Check(o.ctx))
	}()
}

// drop closes the first connection when its own _check was refused: reconnect takes it from there.
func (o *ttOutbound) drop(primary *ttclient.Client, checkErr error) {
	if primary != nil && ttclient.IsRefusal(checkErr) {
		_ = primary.Close()
	}
}

func (o *ttOutbound) redial() (*ttclient.Client, error) {
	client, err := ttclient.Dial(o.ctx, o.config)
	if err != nil {
		return nil, err
	}
	if err := client.Check(o.ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

func (o *ttOutbound) setFatal(err error) {
	if err == nil {
		return
	}
	o.mu.Lock()
	if !o.closed && o.fatal == nil {
		o.fatal = err
		pool := o.pool
		o.fatalOnce.Do(func() { close(o.fatalCh) })
		o.mu.Unlock()
		if pool != nil {
			_ = pool.Close()
		}
		return
	}
	o.mu.Unlock()
}

func (o *ttOutbound) Close() error {
	o.mu.Lock()
	o.closed = true
	pool := o.pool
	o.pool = nil
	o.mu.Unlock()
	if pool != nil {
		return pool.Close()
	}
	return nil
}

func nextTTBackoff(delay time.Duration) time.Duration {
	next := time.Duration(float64(delay) * 1.3)
	if next <= delay {
		next = delay + time.Second
	}
	return min(next, 30*time.Second)
}

type ttPacketFlow struct {
	flow     ttclient.PacketFlow
	outbound *ttOutbound
	primary  *ttclient.Client // the connection this flow was made on
}

func (f ttPacketFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	err := f.flow.WriteTo(payload, target)
	f.outbound.refuse(f.primary, err)
	return err
}

func (f ttPacketFlow) ReadFrom() ([]byte, netip.AddrPort, error) { return f.flow.ReadFrom() }
func (f ttPacketFlow) Close() error                              { return f.flow.Close() }

func resolveTTAddresses(ctx context.Context, r *Real, run *realRun, p *profile.TrustTunnel, hold bool) ([]netip.AddrPort, error) {
	if p == nil || len(p.Addresses) == 0 {
		return nil, ttclient.ErrConfig
	}
	endpoints := make([]netip.AddrPort, 0, len(p.Addresses))
	for _, address := range p.Addresses {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			continue
		}
		ip, err := r.resolveServer(ctx, run, host, hold)
		if err == nil {
			endpoints = append(endpoints, netip.AddrPortFrom(ip, uint16(port)))
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if len(endpoints) == 0 {
		return nil, ttclient.ErrEndpoint
	}
	return endpoints, nil
}
