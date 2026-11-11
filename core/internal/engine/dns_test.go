package engine

import (
	"net/netip"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type, class dnsmessage.Class) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatal(err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: n, Type: qtype, Class: class}); err != nil {
		t.Fatal(err)
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// rawQuery is a query with a hand-made question section.
func rawQuery(counts [4]byte, question ...byte) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0, counts[0], 0, counts[1], 0, counts[2], 0, counts[3]}
	return append(msg, question...)
}

func TestDNSQuestion(t *testing.T) {
	label := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }
	join := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	tail := []byte{0, 0, 1, 0, 1} // root, A, IN
	good := func(name string, qtype dnsmessage.Type) []byte {
		return dnsQuery(t, 7, name, qtype, dnsmessage.ClassINET)
	}

	two := good("a.example", dnsmessage.TypeA)
	two[5] = 2
	two = append(two, 1, 'b', 0, 0, 1, 0, 1)
	withOPT := good("opt.example", dnsmessage.TypeAAAA)
	withOPT[11] = 1
	withOPT = append(withOPT, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0)
	response := good("a.example", dnsmessage.TypeA)
	response[2] |= 0x80
	opcode := good("a.example", dnsmessage.TypeA)
	opcode[2] |= 0x08
	answered := good("a.example", dnsmessage.TypeA)
	answered[7] = 1
	truncated := good("a.example", dnsmessage.TypeA)

	tests := []struct {
		name string
		msg  []byte
		want string // empty: not a question this code takes
	}{
		{"A mixed case", good("WwW.Example.COM", dnsmessage.TypeA), "www.example.com"},
		{"AAAA", good("v6.example.org", dnsmessage.TypeAAAA), "v6.example.org"},
		{"HTTPS", good("svc.example.org", dnsmessage.TypeHTTPS), "svc.example.org"},
		{"punycode and digits", good("xn--80ak6aa92e.xn--p1ai", dnsmessage.TypeA), "xn--80ak6aa92e.xn--p1ai"},
		{"additional OPT record", withOPT, "opt.example"},
		{"MX", good("a.example", dnsmessage.TypeMX), ""},
		{"TXT", good("a.example", dnsmessage.TypeTXT), ""},
		{"PTR", good("1.0.0.127.in-addr.arpa", dnsmessage.TypePTR), ""},
		{"class CH", dnsQuery(t, 7, "a.example", dnsmessage.TypeA, dnsmessage.ClassCHAOS), ""},
		{"two questions", two, ""},
		{"no questions", rawQuery([4]byte{0, 0, 0, 0}), ""},
		{"a response", response, ""},
		{"opcode STATUS", opcode, ""},
		{"an answer record", answered, ""},
		{"compression pointer", rawQuery([4]byte{1, 0, 0, 0}, 0xC0, 0x0C, 0, 1, 0, 1), ""},
		{"pointer after a label", rawQuery([4]byte{1, 0, 0, 0}, join(label("a"), []byte{0xC0, 0x0C}, []byte{0, 1, 0, 1})...), ""},
		{"label of 64", rawQuery([4]byte{1, 0, 0, 0}, join(label(string(make([]byte, 64))), tail)...), ""},
		{"underscore", rawQuery([4]byte{1, 0, 0, 0}, join(label("_dmarc"), label("example"), tail)...), ""},
		{"hyphen edge", rawQuery([4]byte{1, 0, 0, 0}, join(label("-a"), label("example"), tail)...), ""},
		{"non-ASCII", rawQuery([4]byte{1, 0, 0, 0}, join(label("\xd0\xbf"), label("example"), tail)...), ""},
		{"root only", rawQuery([4]byte{1, 0, 0, 0}, tail...), ""},
		{"name over 253", rawQuery([4]byte{1, 0, 0, 0}, join(label(string(repeat('a', 63))), label(string(repeat('b', 63))), label(string(repeat('c', 63))), label(string(repeat('d', 63))), tail)...), ""},
		{"cut inside the name", truncated[:16], ""},
		{"cut before the class", truncated[:len(truncated)-1], ""},
		{"empty", nil, ""},
		{"one byte", []byte{1}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, end, ok := dnsQuestion(test.msg)
			if test.want == "" {
				if ok || name != "" {
					t.Fatalf("dnsQuestion = %q, %d, %t; want none", name, end, ok)
				}
				return
			}
			if !ok || name != test.want {
				t.Fatalf("dnsQuestion = %q, %d, %t; want %q", name, end, ok, test.want)
			}
			if end > len(test.msg) || end < 12+1+4 {
				t.Fatalf("end = %d of %d", end, len(test.msg))
			}
		})
	}

	// The hot path: one allocation, the name.
	query := good("www.example.com", dnsmessage.TypeA)
	if allocs := testing.AllocsPerRun(100, func() { _, _, _ = dnsQuestion(query) }); allocs > 1 {
		t.Fatalf("dnsQuestion allocates %v times; want at most 1", allocs)
	}
}

func repeat(c byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = c
	}
	return out
}

func TestNXDOMAINAnswer(t *testing.T) {
	query := dnsQuery(t, 0xBEEF, "ads.example.com", dnsmessage.TypeA, dnsmessage.ClassINET)
	// an EDNS record after the question must not survive into the answer
	query[11] = 1
	query = append(query, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0)
	_, end, ok := dnsQuestion(query)
	if !ok {
		t.Fatal("query not read")
	}
	question := append([]byte(nil), query[12:end]...)
	answer := nxdomain(query, end)
	if len(answer) != end {
		t.Fatalf("answer is %d bytes; want the header and the question (%d)", len(answer), end)
	}

	var parser dnsmessage.Parser
	header, err := parser.Start(answer)
	if err != nil {
		t.Fatal(err)
	}
	if header.ID != 0xBEEF || !header.Response || header.RCode != dnsmessage.RCodeNameError || !header.RecursionAvailable ||
		!header.RecursionDesired || header.Authoritative || header.Truncated || header.OpCode != 0 {
		t.Fatalf("header = %+v", header)
	}
	q, err := parser.Question()
	if err != nil || q.Name.String() != "ads.example.com." || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
		t.Fatalf("question = %+v, %v", q, err)
	}
	if _, err := parser.Question(); err != dnsmessage.ErrSectionDone {
		t.Fatalf("second question: %v", err)
	}
	if answers, err := parser.AllAnswers(); err != nil || len(answers) != 0 {
		t.Fatalf("answers = %v, %v", answers, err)
	}
	if string(answer[12:]) != string(question) {
		t.Fatal("question section changed")
	}
	// and it is not mistaken for a query again
	if _, _, ok := dnsQuestion(answer); ok {
		t.Fatal("an answer was read as a question")
	}
}

func TestRegionResolver(t *testing.T) {
	panel := []profile.DNSSplit{
		{Geo: []string{"tr"}, Servers: nil},
		{Geo: []string{"cn", "ir"}, Servers: []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("9.9.9.10")}},
	}
	tests := []struct {
		region string
		split  []profile.DNSSplit
		want   string // empty: none
	}{
		{"ru", nil, "77.88.8.8:53"},
		{"by", nil, "77.88.8.8:53"},
		{"cn", nil, "223.5.5.5:53"},
		{"ir", nil, ""},
		{"tr", nil, ""},
		{"kz", nil, ""},
		{"", nil, ""},
		{"ru", panel, "77.88.8.8:53"},
		{"cn", panel, "9.9.9.9:53"}, // the panel's entry wins over the table
		{"ir", panel, "9.9.9.9:53"}, // and gives a region the table has nobody for
		{"tr", panel, ""},           // an entry with no resolver gives nothing
		{"", panel, ""},
	}
	for _, test := range tests {
		got := regionResolver(test.region, test.split)
		if test.want == "" && got.IsValid() || test.want != "" && got != netip.MustParseAddrPort(test.want) {
			t.Errorf("regionResolver(%q) = %v; want %q", test.region, got, test.want)
		}
	}
}

func TestTunnelDNSOrder(t *testing.T) {
	list := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	user, own, panel := list("9.9.9.9"), list("10.0.0.1"), list("8.8.8.8", "8.8.4.4")
	tests := []struct {
		name  string
		lists [][]netip.Addr
		want  []netip.Addr
	}{
		{"user over all", [][]netip.Addr{user, own, panel, defaultTunnelDNS}, user},
		{"profile's own over the panel (AmneziaWG)", [][]netip.Addr{nil, own, panel, defaultTunnelDNS}, own},
		{"panel over the default", [][]netip.Addr{nil, nil, panel, defaultTunnelDNS}, panel},
		{"Hysteria2: user over the panel", [][]netip.Addr{user, panel, defaultTunnelDNS}, user},
		{"Hysteria2: panel over the default", [][]netip.Addr{nil, panel, defaultTunnelDNS}, panel},
		{"the default", [][]netip.Addr{nil, nil, defaultTunnelDNS}, defaultTunnelDNS},
		{"nothing", [][]netip.Addr{nil, nil}, nil},
	}
	for _, test := range tests {
		got := tunnelDNS(test.lists...)
		if len(got) != len(test.want) {
			t.Errorf("%s: got %v; want %v", test.name, got, test.want)
			continue
		}
		for i := range got {
			if got[i] != test.want[i] {
				t.Errorf("%s: got %v; want %v", test.name, got, test.want)
			}
		}
	}
	// the caller may keep or change the result
	got := tunnelDNS(nil, nil, defaultTunnelDNS)
	got[0] = netip.MustParseAddr("2.2.2.2")
	if defaultTunnelDNS[0].String() != "1.1.1.1" {
		t.Fatal("tunnelDNS returned the default list itself")
	}
}
