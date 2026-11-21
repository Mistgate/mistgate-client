//go:build windows

package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	dohType    = "application/dns-message"
	dohMaxBody = 64 << 10
)

var (
	dohWait  = 3 * time.Second  // a variable for the test: silence after which the question goes through the VPN as before
	dohPause = 30 * time.Second // after one such failure the resolver rests this long (a broken one would cost every question 3 s)
)

// dohResolver is the preset's DoH resolver (RFC 8484), reached through the VPN: the questions the tunnel would carry in
// the clear are sent to it instead. One client per run; its connections are dialed by address, the name in the URL is
// only what TLS checks the certificate against.
type dohResolver struct {
	url    string
	port   uint16
	client *http.Client
	addrs  atomic.Pointer[[]netip.Addr] // nil until known; without it no question is sent
	down   atomic.Int64                 // unix nanoseconds until which it rests
}

var errNoDoHAddress = errors.New("no DoH address")

// newDoH makes the resolver of raw (checked by the subscription store; nil if it does not parse). Its addresses are ips,
// else the host when that is a literal, else the host's name is asked once of dnsServer through the VPN, in the background.
// ponytail: that one try per run; when it fails DoH stays off until the next start, and questions go as they did.
func newDoH(ctx context.Context, raw string, ips []netip.Addr, vpn outbound, dnsServer netip.Addr) *dohResolver {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	port := uint64(443)
	if text := u.Port(); text != "" {
		if port, err = strconv.ParseUint(text, 10, 16); err != nil || port == 0 {
			return nil
		}
	}
	d := &dohResolver{url: raw, port: uint16(port)}
	d.client = &http.Client{
		Transport: &http.Transport{ // no proxy: the zero Proxy is none
			DialContext:         d.dial(vpn),
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: dohWait,
			IdleConnTimeout:     time.Minute,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if address, err := netip.ParseAddr(u.Hostname()); err == nil && len(ips) == 0 {
		ips = []netip.Addr{address}
	}
	if len(ips) != 0 {
		d.addrs.Store(&ips)
	} else {
		go d.resolve(ctx, u.Hostname(), vpn, dnsServer)
	}
	return d
}

// dial connects to the first of the addresses that answers, whatever name the request carries.
func (d *dohResolver) dial(vpn outbound) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		err := errNoDoHAddress
		if addrs := d.addrs.Load(); addrs != nil {
			for _, address := range *addrs {
				conn, dialErr := vpn.DialTCP(ctx, netip.AddrPortFrom(address, d.port))
				if dialErr == nil {
					return conn, nil
				}
				err = dialErr
			}
		}
		return nil, err
	}
}

// resolve asks dnsServer (TCP port 53 through the VPN) for the host's addresses, once.
func (d *dohResolver) resolve(ctx context.Context, host string, vpn outbound, dnsServer netip.Addr) {
	ctx, cancel := context.WithTimeout(ctx, 2*dohWait)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return vpn.DialTCP(ctx, netip.AddrPortFrom(dnsServer, 53))
	}}
	found, err := resolver.LookupNetIP(ctx, "ip", host+".") // absolute: no search suffix of this machine is appended
	if err != nil || len(found) == 0 {
		return
	}
	for i := range found {
		found[i] = found[i].Unmap()
	}
	found = found[:min(len(found), 4)]
	d.addrs.Store(&found)
}

// ready says whether a question may be sent now.
func (d *dohResolver) ready() bool {
	return d != nil && d.addrs.Load() != nil && time.Now().UnixNano() >= d.down.Load()
}

func (d *dohResolver) rest() { d.down.Store(time.Now().Add(dohPause).UnixNano()) }

// ask sends a DNS message and returns the answer, or nil: nothing in the failure is kept (the error of the client names
// the URL). Only a 200 with the right type and a body of at most dohMaxBody counts.
func (d *dohResolver) ask(ctx context.Context, query []byte) []byte {
	ctx, cancel := context.WithTimeout(ctx, dohWait)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(query))
	if err != nil {
		return nil
	}
	request.Header.Set("Content-Type", dohType)
	request.Header.Set("Accept", dohType)
	response, err := d.client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); response.StatusCode != http.StatusOK || err != nil || mediaType != dohType {
		return nil
	}
	answer, err := io.ReadAll(io.LimitReader(response.Body, dohMaxBody+1))
	if err != nil || len(answer) < 12 || len(answer) > dohMaxBody || answer[2]&0x80 == 0 {
		return nil
	}
	copy(answer[:2], query[:2]) // a resolver may answer with id 0
	return answer
}

func (d *dohResolver) close() {
	if d != nil {
		d.client.CloseIdleConnections()
	}
}
