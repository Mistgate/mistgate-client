//go:build windows

package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// serverOutbound is a VPN outbound whose TCP dials all reach one test server (and records where they were meant to go);
// a dial to port 53 reaches dns instead.
type serverOutbound struct {
	addr   string
	dialed chan netip.AddrPort
	dns    func(net.Conn)
}

func (o *serverOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	select {
	case o.dialed <- target:
	default:
	}
	if target.Port() == 53 && o.dns != nil {
		client, server := net.Pipe()
		go o.dns(server)
		return client, nil
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", o.addr)
}

func (o *serverOutbound) ListenUDP(context.Context) (packetFlow, error) {
	return nil, errors.New("no UDP")
}

type dohSeen struct {
	method, contentType, accept string
	body                        []byte
}

// dohRig is a TLS server standing in for the DoH resolver of a preset, and the resolver that reaches it through a fake VPN.
type dohRig struct {
	doh    *dohResolver
	out    *serverOutbound
	port   uint16
	hits   atomic.Int32
	seen   chan dohSeen
	server *httptest.Server
}

func newDoHRig(t *testing.T, handler func(w http.ResponseWriter, query []byte)) *dohRig {
	t.Helper()
	rig := &dohRig{seen: make(chan dohSeen, 16)}
	rig.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.hits.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		rig.seen <- dohSeen{r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept"), body}
		handler(w, body)
	}))
	parsed, err := url.Parse(rig.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddrPort(parsed.Host)
	rig.port = address.Port()
	rig.out = &serverOutbound{addr: parsed.Host, dialed: make(chan netip.AddrPort, 8)}
	// The certificate of the test server names example.com: the URL does, and the connection goes to the listed address.
	rig.doh = newDoH(context.Background(), "https://example.com:"+parsed.Port()+"/dns-query", []netip.Addr{netip.MustParseAddr("198.51.100.9")}, rig.out, netip.MustParseAddr("192.0.2.53"))
	pool := x509.NewCertPool()
	pool.AddCert(rig.server.Certificate())
	rig.doh.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
	t.Cleanup(func() {
		rig.doh.close()
		rig.server.Close()
	})
	return rig
}

// answerWith responds to a query as a resolver does: the dns-message type and an A record, here with id 0.
func answerWith(t *testing.T) func(http.ResponseWriter, []byte) {
	return func(w http.ResponseWriter, query []byte) {
		w.Header().Set("Content-Type", dohType)
		_, _ = w.Write(replyFor(t, query, 0, [4]byte{203, 0, 113, 9}))
	}
}

func TestDoHAnswersTheQuestionsThatGoThroughTheVPN(t *testing.T) {
	doh := newDoHRig(t, answerWith(t))
	rig := newDNSRigDoH(t, func(name string) (bool, netip.AddrPort) {
		switch name {
		case "ads.example":
			return true, netip.AddrPort{}
		case "yandex.ru":
			return false, testResolver
		}
		return false, netip.AddrPort{}
	}, doh.doh)

	query := dnsQuery(t, 0x0102, "site.example", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.ask(t, query)
	var parser dnsmessage.Parser
	header, err := parser.Start(rig.heard(t))
	if err != nil || header.ID != 0x0102 || !header.Response {
		t.Fatalf("answer header = %+v, %v (the id of the question must come back)", header, err)
	}
	seen := <-doh.seen
	if seen.method != http.MethodPost || seen.contentType != dohType || seen.accept != dohType || string(seen.body) != string(query) {
		t.Fatalf("the resolver saw %q, type %q, accept %q, %d bytes", seen.method, seen.contentType, seen.accept, len(seen.body))
	}
	if target := <-doh.out.dialed; target != netip.AddrPortFrom(netip.MustParseAddr("198.51.100.9"), doh.port) {
		t.Fatalf("the connection was meant for %v", target)
	}
	nothingSent(t, rig.vpn)
	if names := rig.flow.dns.lookupNames(netip.MustParseAddr("203.0.113.9")); len(names) != 1 || names[0] != "site.example" {
		t.Fatalf("the answer was not remembered: %v", names)
	}

	// a question of another kind goes the same way
	rig.ask(t, dnsQuery(t, 7, "site.example", dnsmessage.TypeTXT, dnsmessage.ClassINET))
	rig.heard(t)
	if doh.hits.Load() != 2 {
		t.Fatalf("a TXT question: %d requests; want 2", doh.hits.Load())
	}

	// a blocked name and a regional one do not reach it
	rig.ask(t, dnsQuery(t, 8, "ads.example", dnsmessage.TypeA, dnsmessage.ClassINET))
	rig.heard(t)
	rig.ask(t, dnsQuery(t, 9, "yandex.ru", dnsmessage.TypeA, dnsmessage.ClassINET))
	recvPacket(t, rig.direct)
	if doh.hits.Load() != 2 {
		t.Fatalf("%d requests; a blocked or a regional name must not use the resolver", doh.hits.Load())
	}
}

func TestDoHFailureSendsTheQuestionThroughTheVPNAndRests(t *testing.T) {
	wait, pause := dohWait, dohPause
	dohWait, dohPause = 500*time.Millisecond, time.Minute
	defer func() { dohWait, dohPause = wait, pause }()
	tests := []struct {
		name    string
		handler func(http.ResponseWriter, []byte)
	}{
		{"a server error", func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusInternalServerError) }},
		{"another type", func(w http.ResponseWriter, _ []byte) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(make([]byte, 40))
		}},
		{"a body that is too large", func(w http.ResponseWriter, _ []byte) {
			w.Header().Set("Content-Type", dohType)
			w.Write(append([]byte{0, 0, 0x80}, make([]byte, dohMaxBody)...))
		}},
		{"not a DNS message", func(w http.ResponseWriter, _ []byte) {
			w.Header().Set("Content-Type", dohType)
			_, _ = w.Write([]byte("hello"))
		}},
		{"a redirect", func(w http.ResponseWriter, _ []byte) {
			w.Header().Set("Location", "https://other.example/dns-query")
			w.WriteHeader(http.StatusFound)
		}},
		{"silence", func(w http.ResponseWriter, _ []byte) { time.Sleep(2 * dohWait) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doh := newDoHRig(t, test.handler)
			rig := newDNSRigDoH(t, func(string) (bool, netip.AddrPort) { return false, netip.AddrPort{} }, doh.doh)
			first := dnsQuery(t, 0x0A0A, "site.example", dnsmessage.TypeA, dnsmessage.ClassINET)
			rig.ask(t, first)
			if got, _ := recvPacket(t, rig.vpn); string(got) != string(first) {
				t.Fatal("the question did not go through the VPN as it was")
			}
			second := dnsQuery(t, 0x0B0B, "other.example", dnsmessage.TypeA, dnsmessage.ClassINET)
			rig.ask(t, second)
			if got, _ := recvPacket(t, rig.vpn); string(got) != string(second) {
				t.Fatal("the next question did not go through the VPN as it was")
			}
			if doh.hits.Load() != 1 {
				t.Fatalf("%d requests; the resolver must rest after a failure", doh.hits.Load())
			}
			rig.silent(t)
		})
	}
}

func TestDoHAddressFromThePresetTheHostOrAQuestionThroughTheVPN(t *testing.T) {
	vpn := &serverOutbound{dialed: make(chan netip.AddrPort, 8)}
	dnsServer := netip.MustParseAddr("192.0.2.53")
	if d := newDoH(context.Background(), "https://198.51.100.5/q", nil, vpn, dnsServer); d == nil || !d.ready() || (*d.addrs.Load())[0] != netip.MustParseAddr("198.51.100.5") {
		t.Fatal("an IP literal is not the address")
	}
	if d := newDoH(context.Background(), "https://not a url", nil, vpn, dnsServer); d != nil {
		t.Fatal("a bad URL gave a resolver")
	}

	// a host name with no address: asked once, through the VPN, of the tunnel's DNS (over TCP)
	vpn.dns = func(conn net.Conn) {
		defer conn.Close()
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, int(size[0])<<8|int(size[1]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		name, end, ok := dnsQuestion(query)
		if !ok || name != "dns.example" {
			return
		}
		answer := noData(query, end)
		if query[end-3] == dnsTypeA {
			var parser dnsmessage.Parser
			_, _ = parser.Start(query)
			question, _ := parser.Question()
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(query[0])<<8 | uint16(query[1]), Response: true, RecursionAvailable: true})
			_ = builder.StartQuestions()
			_ = builder.Question(question)
			_ = builder.StartAnswers()
			_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{198, 51, 100, 7}})
			answer, _ = builder.Finish()
		}
		_, _ = conn.Write(append([]byte{byte(len(answer) >> 8), byte(len(answer))}, answer...))
	}
	d := newDoH(context.Background(), "https://dns.example/q", nil, vpn, dnsServer)
	defer d.close()
	deadline := time.Now().Add(3 * time.Second)
	for !d.ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !d.ready() || len(*d.addrs.Load()) != 1 || (*d.addrs.Load())[0] != netip.MustParseAddr("198.51.100.7") {
		t.Fatal("the host was not resolved through the VPN")
	}
	if target := <-vpn.dialed; target != netip.AddrPortFrom(dnsServer, 53) {
		t.Fatalf("the name was asked of %v", target)
	}

	// no answer: no address, and no question is ever sent
	silent := &serverOutbound{dialed: make(chan netip.AddrPort, 8), dns: func(conn net.Conn) { _ = conn.Close() }}
	if failed := newDoH(context.Background(), "https://dns.example/q", nil, silent, dnsServer); failed.ready() {
		t.Fatal("ready before any address")
	} else {
		time.Sleep(200 * time.Millisecond)
		if failed.ready() || failed.addrs.Load() != nil {
			t.Fatal("an address came from nowhere")
		}
	}
}
