//go:build windows

package engine

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTable is a socket table that tests change; take counts the reads.
type fakeTable struct {
	mu    sync.Mutex
	rows  []ownerRow
	takes atomic.Int32
	delay time.Duration
	fail  bool
}

// take sees the table as it is when the read begins, as the system call does, and then takes its time.
func (f *fakeTable) take() ([]ownerRow, error) {
	f.takes.Add(1)
	f.mu.Lock()
	rows, fail := append([]ownerRow(nil), f.rows...), f.fail
	f.mu.Unlock()
	time.Sleep(f.delay)
	if fail {
		return nil, errors.New("table unreadable")
	}
	return rows, nil
}

func (f *fakeTable) set(rows ...ownerRow) {
	f.mu.Lock()
	f.rows = rows
	f.mu.Unlock()
}

func row(addr string, port uint16, pid uint32) ownerRow {
	return ownerRow{addr: netip.MustParseAddr(addr), port: port, pid: pid}
}

func fakeResolver(tcp, udp *fakeTable, paths map[uint32]string, calls *atomic.Int32) *appResolver {
	r := newAppResolver([2]func() ([]ownerRow, error){tcp.take, udp.take}, func(pid uint32) string {
		calls.Add(1)
		return paths[pid]
	}, 30*time.Millisecond)
	return r
}

func src(addr string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(addr), port)
}

func TestOwnerFindsBySocket(t *testing.T) {
	snap := &snapshot{rows: []ownerRow{
		row("10.9.0.2", 5000, 11), row("192.168.1.5", 5000, 12), // one port on two addresses
		row("0.0.0.0", 6000, 21), // a UDP socket on every address
		row("127.0.0.1", 7000, 31),
		row("192.168.1.5", 8000, 41), // the only owner of 8000
	}}
	for _, c := range []struct {
		src  netip.AddrPort
		pid  uint32
		want bool
	}{
		{src("10.9.0.2", 5000), 11, true},
		{src("192.168.1.5", 5000), 12, true},
		{src("172.16.0.1", 5000), 0, false}, // two owners, none on this address: not guessed
		{src("10.9.0.2", 6000), 21, true},
		{src("::1", 6000), 21, true}, // a wildcard serves either family
		{src("10.9.0.2", 8000), 41, true},
		{src("10.9.0.2", 9999), 0, false},
	} {
		if pid, ok := snap.find(c.src); pid != c.pid || ok != c.want {
			t.Errorf("find(%v) = %d, %t; want %d, %t", c.src, pid, ok, c.pid, c.want)
		}
	}
}

func TestParseOwnerTable(t *testing.T) {
	le := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	port := func(p uint16) []byte { return []byte{byte(p >> 8), byte(p), 0, 0} }
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	// TCP, IPv4: state, local address, local port, remote address, remote port, pid
	tcp4 := cat(le(2), []byte{0, 0, 0, 0}, port(445), le(0), port(0), le(4)) // listening: left out
	tcp4 = append(tcp4, cat(le(5), []byte{10, 9, 0, 2}, port(50000), []byte{1, 2, 3, 4}, port(443), le(1234))...)
	rows := parseOwnerTable(nil, cat(le(2), tcp4), false, false)
	if len(rows) != 1 || rows[0] != row("10.9.0.2", 50000, 1234) {
		t.Fatalf("TCP IPv4 rows = %+v", rows)
	}
	// a TIME_WAIT leftover (pid 0) before the live socket of the same port does not hide it
	tcp4 = cat(le(11), []byte{10, 9, 0, 2}, port(50001), []byte{1, 2, 3, 4}, port(443), le(0))
	tcp4 = append(tcp4, cat(le(5), []byte{10, 9, 0, 2}, port(50001), []byte{1, 2, 3, 5}, port(443), le(4321))...)
	rows = parseOwnerTable(nil, cat(le(2), tcp4), false, false)
	if len(rows) != 1 || rows[0] != row("10.9.0.2", 50001, 4321) {
		t.Fatalf("rows with a pid 0 leftover = %+v", rows)
	}
	snap := &snapshot{rows: rows}
	if pid, ok := snap.find(src("10.9.0.2", 50001)); !ok || pid != 4321 {
		t.Fatalf("find = %d, %t", pid, ok)
	}
	// UDP, IPv6: address, scope, port, pid
	v6 := make([]byte, 16)
	v6[15] = 1
	udp6 := cat(v6, le(0), port(5353), le(77))
	rows = parseOwnerTable(nil, cat(le(1), udp6), true, true)
	if len(rows) != 1 || rows[0] != row("::1", 5353, 77) {
		t.Fatalf("UDP IPv6 rows = %+v", rows)
	}
	// a count larger than the data is cut to the data; junk shorter than a header is ignored
	if rows := parseOwnerTable(nil, cat(le(1000), udp6), true, true); len(rows) != 1 {
		t.Fatalf("overlong count: %d rows", len(rows))
	}
	if rows := parseOwnerTable(nil, []byte{1}, true, false); len(rows) != 0 {
		t.Fatalf("junk: %d rows", len(rows))
	}
}

func TestOneSnapshotServesAWholeBurst(t *testing.T) {
	var tcp, udp fakeTable
	tcp.delay = 10 * time.Millisecond
	var rows []ownerRow
	paths := map[uint32]string{}
	for i := uint16(0); i < 10; i++ {
		rows = append(rows, row("10.9.0.2", 5000+i, 100+uint32(i)))
		paths[100+uint32(i)] = `c:\p` + string(rune('a'+i)) + `.exe`
	}
	tcp.set(rows...)
	var pathCalls atomic.Int32
	r := fakeResolver(&tcp, &udp, paths, &pathCalls)

	var wg sync.WaitGroup
	got := make([]string, 10)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = r.Owner(false, src("10.9.0.2", 5000+uint16(i)))
		}()
	}
	wg.Wait()
	for i, path := range got {
		if path != paths[100+uint32(i)] {
			t.Errorf("flow %d: owner %q; want %q", i, path, paths[100+uint32(i)])
		}
	}
	if n := tcp.takes.Load(); n != 1 {
		t.Fatalf("%d table reads for ten waiting flows; want 1", n)
	}
	if udp.takes.Load() != 0 {
		t.Fatal("the UDP table was read for TCP flows")
	}

	// again: all from memory
	for i := range got {
		if r.Owner(false, src("10.9.0.2", 5000+uint16(i))) != paths[100+uint32(i)] {
			t.Fatal("cached owner changed")
		}
	}
	if tcp.takes.Load() != 1 || pathCalls.Load() != 10 {
		t.Fatalf("cached lookups read the table or the process again: reads %d, path lookups %d", tcp.takes.Load(), pathCalls.Load())
	}
}

func TestSocketNewerThanTheSnapshotWaitsForTheNextOne(t *testing.T) {
	var tcp, udp fakeTable
	tcp.set(row("10.9.0.2", 5000, 100))
	var pathCalls atomic.Int32
	r := fakeResolver(&tcp, &udp, map[uint32]string{100: `c:\a.exe`, 101: `c:\b.exe`}, &pathCalls)
	if r.Owner(false, src("10.9.0.2", 5000)) != `c:\a.exe` {
		t.Fatal("first owner")
	}
	// a new socket appears right after the read: the flow of it must not be taken for "unknown"
	tcp.set(row("10.9.0.2", 5000, 100), row("10.9.0.2", 5001, 101))
	began := time.Now()
	if got := r.Owner(false, src("10.9.0.2", 5001)); got != `c:\b.exe` {
		t.Fatalf("owner of a socket newer than the snapshot = %q", got)
	}
	if tcp.takes.Load() != 2 {
		t.Fatalf("%d reads; want 2", tcp.takes.Load())
	}
	if waited := time.Since(began); waited < 20*time.Millisecond {
		t.Fatalf("second read came %v after the first, inside the gap", waited)
	}

	// a socket that is not there at all: one read after arrival settles it, and the "no" is remembered briefly
	reads := tcp.takes.Load()
	if got := r.Owner(false, src("10.9.0.2", 5999)); got != "" {
		t.Fatalf("owner of a missing socket = %q", got)
	}
	if got := r.Owner(false, src("10.9.0.2", 5999)); got != "" || tcp.takes.Load() > reads+1 {
		t.Fatalf("the miss was read again: %d reads", tcp.takes.Load()-reads)
	}
}

func TestFlowThatArrivesDuringAReadIsNotCalledUnknown(t *testing.T) {
	var tcp, udp fakeTable
	tcp.delay = 40 * time.Millisecond
	tcp.set(row("10.9.0.2", 5000, 100))
	var pathCalls atomic.Int32
	r := fakeResolver(&tcp, &udp, map[uint32]string{100: `c:.exe`, 101: `c:.exe`}, &pathCalls)
	first := make(chan string)
	go func() { first <- r.Owner(false, src("10.9.0.2", 5000)) }()
	time.Sleep(10 * time.Millisecond) // the read has begun and saw only the first socket
	tcp.set(row("10.9.0.2", 5000, 100), row("10.9.0.2", 5001, 101))
	if got := r.Owner(false, src("10.9.0.2", 5001)); got != `c:.exe` {
		t.Fatalf("owner of a socket made during a read = %q", got)
	}
	if got := <-first; got != `c:.exe` {
		t.Fatalf("first owner = %q", got)
	}
	if tcp.takes.Load() != 2 {
		t.Fatalf("%d reads; want 2 (the second for the late flow)", tcp.takes.Load())
	}
}

func TestOwnerEntriesExpireAndFollowTheTable(t *testing.T) {
	var tcp, udp fakeTable
	tcp.set(row("10.9.0.2", 5000, 100), row("10.9.0.2", 5001, 101))
	var pathCalls atomic.Int32
	r := fakeResolver(&tcp, &udp, map[uint32]string{100: `c:\a.exe`, 101: `c:\b.exe`, 102: `c:\c.exe`}, &pathCalls)
	r.ttl, r.missTTL = 80*time.Millisecond, 40*time.Millisecond
	a, b := src("10.9.0.2", 5000), src("10.9.0.2", 5001)
	r.Owner(false, a)
	r.Owner(false, b)
	if path, ok := r.Cached(false, a); !ok || path != `c:\a.exe` {
		t.Fatalf("Cached = %q, %t", path, ok)
	}

	// the port is taken over by another process; a newer table shows it, and the old entry goes at once
	tcp.set(row("10.9.0.2", 5000, 102), row("10.9.0.2", 5001, 101))
	time.Sleep(35 * time.Millisecond)
	if got := r.Owner(false, src("10.9.0.2", 5002)); got != "" { // any read refreshes the table
		t.Fatalf("unrelated owner = %q", got)
	}
	if _, ok := r.Cached(false, a); ok {
		t.Fatal("the entry outlived a table that shows another owner")
	}
	if got := r.Owner(false, a); got != `c:\c.exe` {
		t.Fatalf("owner after take-over = %q", got)
	}
	// an entry the newer table still shows stays
	if path, ok := r.Cached(false, b); !ok || path != `c:\b.exe` {
		t.Fatalf("an unchanged entry was dropped: %q, %t", path, ok)
	}

	// and the port that left the table is dropped
	tcp.set()
	time.Sleep(35 * time.Millisecond)
	r.Owner(false, src("10.9.0.2", 5003))
	if _, ok := r.Cached(false, b); ok {
		t.Fatal("the entry of a closed socket stayed")
	}

	// time alone ends an entry, a miss sooner than a hit
	tcp.set(row("10.9.0.2", 5004, 100))
	r.Owner(false, src("10.9.0.2", 5004))
	time.Sleep(100 * time.Millisecond)
	if _, ok := r.Cached(false, src("10.9.0.2", 5004)); ok {
		t.Fatal("an entry outlived its time")
	}
}

func TestUnreadableTableIsNotRemembered(t *testing.T) {
	var tcp, udp fakeTable
	tcp.set(row("10.9.0.2", 5000, 100))
	tcp.fail = true
	var pathCalls atomic.Int32
	r := fakeResolver(&tcp, &udp, map[uint32]string{100: `c:\a.exe`}, &pathCalls)
	if got := r.Owner(false, src("10.9.0.2", 5000)); got != "" {
		t.Fatalf("owner from a failed read = %q", got)
	}
	tcp.mu.Lock()
	tcp.fail = false
	tcp.mu.Unlock()
	if got := r.Owner(false, src("10.9.0.2", 5000)); got != `c:\a.exe` {
		t.Fatalf("owner after the table came back = %q", got)
	}
}

// The real tables: this process's own sockets on loopback.
func TestRealTablesFindThisProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ToLower(exe)
	r := newProcessOwners()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := listener.Accept(); err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer func() { (<-accepted).Close() }()
	clientAddr := client.LocalAddr().(*net.TCPAddr).AddrPort()
	if got := r.Owner(false, clientAddr); !strings.EqualFold(got, want) {
		t.Fatalf("TCP owner of %v = %q; want %q", clientAddr, got, want)
	}
	// the listening socket is not a source of flows
	if got := r.Owner(false, listener.Addr().(*net.TCPAddr).AddrPort()); got != "" && !strings.EqualFold(got, want) {
		t.Fatalf("owner of the accepted side = %q", got)
	}

	udpSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpSocket.Close()
	udpAddr := udpSocket.LocalAddr().(*net.UDPAddr).AddrPort()
	if got := r.Owner(true, udpAddr); !strings.EqualFold(got, want) {
		t.Fatalf("UDP owner of %v = %q; want %q", udpAddr, got, want)
	}
	// a socket on every address (a dual-stack one for Go), asked as the IPv4 source of a flow
	wide, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer wide.Close()
	widePort := wide.LocalAddr().(*net.UDPAddr).Port
	if got := r.Owner(true, netip.AddrPortFrom(netip.MustParseAddr("10.9.0.2"), uint16(widePort))); !strings.EqualFold(got, want) {
		t.Fatalf("UDP owner of a wildcard socket = %q; want %q", got, want)
	}
	// a UDP port is not a TCP port
	if got := r.Owner(false, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), udpAddr.Port())); strings.EqualFold(got, want) && udpAddr.Port() != clientAddr.Port() {
		// a TCP socket may happen to use the same number; only a wrong table would answer here without one
		t.Logf("same number used by a TCP socket of this process: %v", got)
	}
}

func TestProcessPathChecksTheCreationTime(t *testing.T) {
	exe, _ := os.Executable()
	self := uint32(os.Getpid())
	if got := processPath(self); !strings.EqualFold(got, exe) || got != strings.ToLower(got) {
		t.Fatalf("processPath(self) = %q; want %q in lower case", got, exe)
	}
	// a stale entry (another process once had this id) is not trusted
	pidPaths.Lock()
	pidPaths.m[self] = pidEntry{created: 1, path: `c:\other\program.exe`}
	pidPaths.Unlock()
	if got := processPath(self); !strings.EqualFold(got, exe) {
		t.Fatalf("a reused id lent its old path: %q", got)
	}
	if processPath(0) != "" || processPath(4) != "" || processPath(0xFFFFFFF0) != "" {
		t.Fatal("a path appeared for no process")
	}
}

// BenchmarkReadTables and BenchmarkOwner give the cost of one table read and of one decision from memory.
func BenchmarkReadTCPTable(b *testing.B) {
	var buf []byte
	for range b.N {
		if _, err := readOwnerTable(false, &buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadUDPTable(b *testing.B) {
	var buf []byte
	for range b.N {
		if _, err := readOwnerTable(true, &buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOwnerFromMemory(b *testing.B) {
	r := newProcessOwners()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	addr := c.LocalAddr().(*net.TCPAddr).AddrPort()
	if r.Owner(false, addr) == "" {
		b.Fatal("own socket not found")
	}
	b.ResetTimer()
	for range b.N {
		if _, ok := r.Cached(false, addr); !ok {
			b.Fatal("cache lost the entry")
		}
	}
}

func BenchmarkProcessPathOfCachedPID(b *testing.B) {
	self := uint32(os.Getpid())
	processPath(self)
	b.ResetTimer()
	for range b.N {
		processPath(self)
	}
}
