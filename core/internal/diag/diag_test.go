package diag

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/stun"
)

func TestDNSReplacementRules(t *testing.T) {
	local := map[string]dnsAnswer{
		"missing.example": {Answered: true, NXDomain: true},
		"bogon.example":   {Answered: true, Addresses: []netip.Addr{netip.MustParseAddr("10.2.3.4")}},
		"stub-a.example":  {Answered: true, Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}},
		"stub-b.example":  {Answered: true, Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}},
		"cdn.example":     {Answered: true, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.20")}},
	}
	doh := map[string]dnsAnswer{}
	for name := range local {
		doh[name] = dnsAnswer{Answered: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	}
	checked, replaced := dnsReplacementCounts(local, doh)
	if checked != 5 || replaced != 4 || dnsVerdict(local, doh, checked, replaced) != "replaced" {
		t.Fatalf("got checked=%d replaced=%d", checked, replaced)
	}
	if got := dnsVerdict(nil, nil, 0, 0); got != "unknown" {
		t.Fatalf("empty DNS verdict = %q", got)
	}
}

func TestSTUNParserAndNATVerdict(t *testing.T) {
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], 0x2112A442)
	copy(request[8:], []byte("transaction"))
	response := make([]byte, 32)
	binary.BigEndian.PutUint16(response[:2], 0x0101)
	binary.BigEndian.PutUint16(response[2:4], 12)
	binary.BigEndian.PutUint32(response[4:8], 0x2112A442)
	copy(response[8:20], request[8:20])
	binary.BigEndian.PutUint16(response[20:22], 0x0020)
	binary.BigEndian.PutUint16(response[22:24], 8)
	response[25] = 1
	binary.BigEndian.PutUint16(response[26:28], 54321^0x2112)
	for i, value := range []byte{203, 0, 113, 9} {
		response[24+4+i] = value ^ []byte{0x21, 0x12, 0xa4, 0x42}[i]
	}
	mapped, ok := stun.ParseResponse(request, response)
	if !ok || mapped.Port != 54321 || mapped.Address.String() != "203.0.113.9" {
		t.Fatalf("mapped = %#v, ok=%t", mapped, ok)
	}
	if natVerdict([]uint16{42000, 42000}) != "open" || natVerdict([]uint16{42000, 42001}) != "limited" || natVerdict([]uint16{42000}) != "unknown" {
		t.Fatal("unexpected NAT verdict")
	}
}

func TestUDPAndForeignVerdicts(t *testing.T) {
	if udpVerdict(false, false, false, false) != "unknown" ||
		udpVerdict(true, false, false, false) != "ok" ||
		udpVerdict(false, true, false, false) != "ok" ||
		udpVerdict(false, false, true, false) != "blocked" ||
		udpVerdict(false, false, false, true) != "blocked" {
		t.Fatal("unexpected UDP verdict")
	}
	if foreignVerdict(10, 10) != "ok" || foreignVerdict(10, 9) != "ok" || foreignVerdict(10, 8) != "cut" || foreignVerdict(10, 0) != "unknown" {
		t.Fatal("unexpected foreign verdict")
	}
}

func TestHostAliveConnectRefusedAndBlackhole(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, rawPort, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.ParseUint(rawPort, 10, 16)
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	if !hostAlive(context.Background(), dial, "127.0.0.1", []uint16{uint16(port)}, 200*time.Millisecond) {
		t.Fatal("accepting local listener was not alive")
	}
	<-accepted
	_ = listener.Close()
	if !hostAlive(context.Background(), dial, "127.0.0.1", []uint16{uint16(port)}, 200*time.Millisecond) {
		t.Fatal("closed local port refusal was not alive")
	}
	blackhole := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if hostAlive(context.Background(), blackhole, "127.0.0.1", []uint16{1, 2}, 10*time.Millisecond) {
		t.Fatal("blackholed connection was reported alive")
	}
}

func TestRunnerProgressBusyAndCancel(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	events := make(chan State, 8)
	runner := NewRunner(Config{Profiles: func() ([]profile.Profile, error) {
		close(entered)
		<-release
		return []profile.Profile{{Sub: "sub"}}, nil
	}}, func(state State) { events <- state })
	started := runner.Start("sub")
	if started.State != "running" || started.Step != 0 || started.Pct != 0 {
		t.Fatalf("start state = %#v", started)
	}
	<-entered
	second := runner.Start("other")
	if second.State != "running" || second.Step != 0 {
		t.Fatalf("second start changed state: %#v", second)
	}
	for step := 1; step <= 4; step++ {
		runner.advance(step, step*20)
	}
	cancelled := runner.Cancel()
	if cancelled.State != "failed" || cancelled.Error != "cancelled" || cancelled.Step != 4 {
		t.Fatalf("cancel state = %#v", cancelled)
	}
	close(release)
	deadline := time.After(time.Second)
	for {
		runner.mu.Lock()
		active := runner.cancel != nil
		runner.mu.Unlock()
		if !active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cancelled run did not finish")
		case <-time.After(time.Millisecond):
		}
	}
	want := []int{0, 1, 2, 3, 4, 4}
	for i, step := range want {
		select {
		case event := <-events:
			if event.Step != step {
				t.Fatalf("event %d step=%d, want %d", i, event.Step, step)
			}
			if i == len(want)-1 && (event.State != "failed" || event.Error != "cancelled") {
				t.Fatalf("last event = %#v", event)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing event %d", i)
		}
	}
}

func TestResultDoesNotSerializeProfileSecrets(t *testing.T) {
	p := profile.Profile{
		ID: "server-id", Name: "Node", Protocol: "hysteria2", Sub: "sub",
		Hy2: &profile.Hy2{Auth: "auth-secret", ObfsPassword: "obfs-secret", Host: "203.0.113.55", ServerName: "sni-secret"},
		AWG: &profile.AWG{ServerKey: "awg-key-secret", EndpointHost: "endpoint-secret"},
	}
	result := Result{Sub: p.Sub, Servers: []Server{serverForProfile(p)}}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"auth-secret", "obfs-secret", "awg-key-secret", "endpoint-secret", "203.0.113.55", "sni-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("serialized result contains %q: %s", secret, encoded)
		}
	}
}

// A start right after a cancel is not lost: it begins when the cancelled run has left.
func TestRunnerStartAfterCancel(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}, 2), make(chan struct{})
	runner := NewRunner(Config{Profiles: func() ([]profile.Profile, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return nil, errors.New("none")
	}}, nil)
	runner.Start("sub")
	<-entered
	runner.Cancel()
	if again := runner.Start("sub"); again.State != "running" || again.Step != 0 {
		t.Fatalf("start after cancel = %#v", again)
	}
	close(release)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the second run did not start")
	}
	deadline := time.After(time.Second)
	for runner.Get().State == "running" {
		select {
		case <-deadline:
			t.Fatal("the second run did not finish")
		case <-time.After(time.Millisecond):
		}
	}
	if got := runner.Get(); calls.Load() != 2 || got.State != "failed" || got.Error == "cancelled" {
		t.Fatalf("calls=%d state=%#v", calls.Load(), got)
	}
}
