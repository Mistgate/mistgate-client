package engine

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/geo"
	"golang.org/x/net/dns/dnsmessage"
)

func TestParseTLSClientHello(t *testing.T) {
	data := captureClientHello(t, "Example.com")
	name, complete := parseTLSClientHello(data)
	if !complete || name != "example.com" {
		t.Fatalf("ClientHello = %q, %t; want example.com, complete", name, complete)
	}
	recordLength := int(data[3])<<8 | int(data[4])
	payload := data[5 : 5+recordLength]
	cut := len(payload) / 2
	fragmented := appendTLSRecord(nil, data[1:3], payload[:cut])
	fragmented = appendTLSRecord(fragmented, data[1:3], payload[cut:])
	if name, complete = parseTLSClientHello(fragmented); !complete || name != "example.com" {
		t.Fatalf("fragmented ClientHello = %q, %t; want example.com, complete", name, complete)
	}
	if name, complete = parseTLSClientHello(data[:len(data)-1]); name != "" || complete {
		t.Fatalf("truncated ClientHello = %q, %t; want no name, incomplete", name, complete)
	}
	withoutSNI := captureClientHello(t, "")
	if name, complete = parseTLSClientHello(withoutSNI); name != "" || !complete {
		t.Fatalf("ClientHello without SNI = %q, %t; want empty, complete", name, complete)
	}
	if name, _ = parseTLSClientHello([]byte("not TLS")); name != "" {
		t.Fatalf("garbage TLS name = %q, want empty", name)
	}
}

func appendTLSRecord(data, version, payload []byte) []byte {
	data = append(data, 22, version[0], version[1], byte(len(payload)>>8), byte(len(payload)))
	return append(data, payload...)
}

func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	client := tls.Client(clientConn, &tls.Config{ServerName: serverName, InsecureSkipVerify: serverName == "", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	done := make(chan struct{})
	go func() {
		_ = client.Handshake()
		close(done)
	}()
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 0, maxSniffBytes)
	for len(data) < maxSniffBytes {
		var buffer [maxSniffBytes]byte
		n, err := serverConn.Read(buffer[:])
		if n > 0 {
			data = append(data, buffer[:n]...)
		}
		if len(data) >= 5 {
			recordLen := int(data[3])<<8 | int(data[4])
			if len(data) >= 5+recordLen {
				break
			}
		}
		if err != nil {
			t.Fatalf("capture ClientHello: %v", err)
		}
	}
	_ = clientConn.Close()
	_ = serverConn.Close()
	<-done
	return data
}

func TestParseHTTPHost(t *testing.T) {
	request := []byte("GET /watch HTTP/1.1\r\nhOsT: Example.com:443\r\nAccept: */*\r\n\r\n")
	if name, complete := parseHTTPHost(request); name != "example.com" || !complete {
		t.Fatalf("Host = %q, %t; want example.com, complete", name, complete)
	}
	if name, complete := parseHTTPHost([]byte("GET / HTTP/1.1\r\nHost: bad/name\r\n")); name != "" || !complete {
		t.Fatalf("malformed Host = %q, %t; want empty, complete", name, complete)
	}
	if name, complete := parseHTTPHost([]byte("GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n")); name != "" || !complete {
		t.Fatalf("duplicate Host = %q, %t; want empty, complete", name, complete)
	}
	if name, complete := parseHTTPHost([]byte("GET / HTTP/1.1\r\nHost: ex")); name != "" || complete {
		t.Fatalf("truncated Host = %q, %t; want empty, incomplete", name, complete)
	}
}

func TestDNSMemoryTTLChainAndCap(t *testing.T) {
	base := time.Unix(1000, 0)
	memory := &dnsMemory{entries: make(map[netip.Addr]dnsEntry)}
	memory.rememberAt(dnsAnswer(t, "www.example.com", []dnsRecord{
		{owner: "www.example.com.", cname: "edge.example.net.", ttl: 120},
		{owner: "edge.example.net.", address: netip.MustParseAddr("192.0.2.10"), ttl: 900},
		{owner: "www.example.com.", address: netip.MustParseAddr("192.0.2.11"), ttl: 1},
	}), base)
	if got := memory.lookupAt(netip.MustParseAddr("192.0.2.10"), base.Add(119*time.Second)); got != "www.example.com" {
		t.Fatalf("CNAME address name = %q; want question name", got)
	}
	if got := memory.lookupAt(netip.MustParseAddr("192.0.2.10"), base.Add(120*time.Second)); got != "" {
		t.Fatalf("CNAME address remained past chain TTL: %q", got)
	}
	if got := memory.entries[netip.MustParseAddr("192.0.2.11")].expires.Sub(base); got != time.Minute {
		t.Fatalf("minimum TTL = %s; want 1m", got)
	}

	memory.rememberAt(dnsAnswer(t, "long.example", []dnsRecord{
		{owner: "long.example.", address: netip.MustParseAddr("192.0.2.12"), ttl: 7200},
	}), base)
	if got := memory.entries[netip.MustParseAddr("192.0.2.12")].expires.Sub(base); got != time.Hour {
		t.Fatalf("maximum TTL = %s; want 1h", got)
	}

	memory.entries = make(map[netip.Addr]dnsEntry)
	for i := 0; i < dnsMemoryLimit; i++ {
		address := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		memory.entries[address] = dnsEntry{name: "expired.example", expires: base.Add(-time.Second)}
	}
	memory.rememberAddressAt(netip.MustParseAddr("192.0.2.20"), "new.example", time.Minute, base)
	if len(memory.entries) != 1 || memory.lookupAt(netip.MustParseAddr("192.0.2.20"), base) != "new.example" {
		t.Fatalf("expired DNS entries were not dropped: %d", len(memory.entries))
	}
	for i := 0; i < dnsMemoryLimit; i++ {
		address := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 2})
		memory.entries[address] = dnsEntry{name: "live.example", expires: base.Add(time.Hour)}
	}
	memory.rememberAddressAt(netip.MustParseAddr("192.0.2.21"), "new.example", time.Minute, base)
	if len(memory.entries) != 1 || memory.lookupAt(netip.MustParseAddr("192.0.2.21"), base) != "new.example" {
		t.Fatalf("full DNS memory was not cleared: %d", len(memory.entries))
	}
}

type dnsRecord struct {
	owner   string
	cname   string
	address netip.Addr
	ttl     uint32
}

func dnsAnswer(t *testing.T, question string, records []dnsRecord) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(question + ".")
	if err != nil {
		t.Fatal(err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		owner, err := dnsmessage.NewName(record.owner)
		if err != nil {
			t.Fatal(err)
		}
		header := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: record.ttl}
		if record.cname != "" {
			target, err := dnsmessage.NewName(record.cname)
			if err != nil {
				t.Fatal(err)
			}
			if err := builder.CNAMEResource(header, dnsmessage.CNAMEResource{CNAME: target}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if !record.address.Is4() {
			t.Fatal("test A record is not IPv4")
		}
		if err := builder.AResource(header, dnsmessage.AResource{A: record.address.As4()}); err != nil {
			t.Fatal(err)
		}
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestDecisionTable(t *testing.T) {
	dataDir := t.TempDir()
	store, err := geo.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	var regionBody string
	for i := 0; i < 100; i++ {
		regionBody += fmt.Sprintf("198.18.0.%d/32\n", i)
	}
	regionBody += "203.0.113.7/32\n"
	if err := os.WriteFile(filepath.Join(dataDir, "geo", "ru.list"), []byte(regionBody), 0600); err != nil {
		t.Fatal(err)
	}
	region, ok := store.Region("ru")
	if !ok {
		t.Fatal("region fixture was unavailable")
	}
	if _, _, err := store.SetRules(geo.Rules{
		Direct: geo.Selection{Sites: []string{"https://Direct.Example/path"}},
		VPN:    geo.Selection{Sites: []string{"vpn.example"}},
	}); err != nil {
		t.Fatal(err)
	}
	rules := store.ActiveSiteRules()
	tests := []struct {
		mode, address, name string
		region              *geo.Set
		want                bool
	}{
		{"all", "203.0.113.7", "direct.example", region, false},
		{"smart", "203.0.113.7", "", region, true},
		{"smart", "203.0.113.9", "sub.direct.example", region, true},
		{"smart", "203.0.113.9", "siblingexample", region, false},
		{"smart", "203.0.113.9", "vpn.example", region, false},
		{"smart", "203.0.113.7", "unknown.example", nil, false},
		{"selected", "203.0.113.9", "vpn.example", region, false},
		{"selected", "203.0.113.9", "sub.vpn.example", nil, false},
		{"selected", "203.0.113.9", "unknown.example", nil, true},
		{"selected", "2001:4860:4860::8888", "unknown.example", nil, true},
		{"smart", "203.0.113.9", "direct.example", nil, true},
		{"selected", "10.0.0.1", "unknown.example", nil, false},
		{"selected", "127.0.0.1", "unknown.example", nil, false},
		{"selected", "169.254.1.2", "unknown.example", nil, false},
		{"selected", "224.0.0.1", "unknown.example", nil, false},
	}
	for _, test := range tests {
		t.Run(test.mode+"/"+test.address+"/"+test.name, func(t *testing.T) {
			got := directByRules(netip.MustParseAddr(test.address), test.name, test.mode, test.region, rules)
			if got != test.want {
				t.Fatalf("directByRules = %t; want %t", got, test.want)
			}
		})
	}
}
