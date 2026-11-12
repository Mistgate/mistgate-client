//go:build windows

package engine

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Who owns a socket: the IP Helper owner tables map a local port to a process id, and the process id to an image path.
// The tables are costly to read, so they are read at most once per minGap, one reader serving every waiting flow,
// and the answers are kept for a few seconds.

const (
	snapshotGap  = 50 * time.Millisecond // least time between two table reads of one protocol
	ownerTTL     = 5 * time.Second       // see appResolver.ttl
	notOwnedTTL  = time.Second           // see appResolver.missTTL
	maxOwnerKeys = 4096
	maxPidPaths  = 2048
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet6             = 23
	tcpTableOwnerPIDAll = 5 // not "connections": that class may leave out a connection still in SYN_SENT
	udpTableOwnerPID    = 1
	tcpStateListen      = 2
)

// ownerRow is one socket of a table.
type ownerRow struct {
	addr netip.Addr
	port uint16
	pid  uint32
}

// snapshot is a table as it was when the read began. Its rows are never changed after it is published.
type snapshot struct {
	seq  uint64 // the reads of a table are numbered in the order they begin
	at   time.Time
	rows []ownerRow
}

// find returns the owner of the socket a flow comes from: the exact local address first, then a wildcard one (a UDP
// socket bound to 0.0.0.0 or ::), then the only owner of the port. If two programs hold the port on other addresses and
// none fits, the owner is unknown rather than guessed.
// ponytail: a linear scan, a few thousand rows at most; upgrade = sort the rows by port when tables get 10x larger.
func (s *snapshot) find(src netip.AddrPort) (pid uint32, ok bool) {
	var wild, only uint32
	var haveWild bool
	distinct := 0
	for _, row := range s.rows {
		if row.port != src.Port() {
			continue
		}
		if row.addr == src.Addr() {
			return row.pid, true
		}
		if row.addr.IsUnspecified() {
			wild, haveWild = row.pid, true
		}
		switch {
		case distinct == 0:
			only, distinct = row.pid, 1
		case row.pid != only:
			distinct = 2
		}
	}
	switch {
	case haveWild:
		return wild, true
	case distinct == 1:
		return only, true
	}
	return 0, false
}

// snapshotter reads one table, at most once per gap, one reader at a time.
type snapshotter struct {
	take func() ([]ownerRow, error)
	gap  time.Duration

	mu       sync.Mutex // guards the fields below; never held while a table is read or while sleeping
	seq      uint64     // reads begun so far
	cur      *snapshot
	lastTry  time.Time
	inflight *flight
}

type flight struct {
	seq  uint64
	done chan struct{}
	snap *snapshot // set before done is closed; nil when the read failed
}

func (s *snapshotter) current() *snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// look returns the newest snapshot if it is no older than the gap, and a mark: a snapshot numbered above the mark began
// after this call. (Reads are counted rather than timed because the Windows clock ticks too coarsely to tell a read that
// began before a socket existed from one that began after it.)
func (s *snapshotter) look() (fresh *snapshot, mark uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil && time.Since(s.cur.at) <= s.gap {
		fresh = s.cur
	}
	return fresh, s.seq
}

// wait returns a snapshot, reading one if none is going on. Callers that arrive while a read is going on share it
// instead of starting another. late says that the snapshot began before the mark: it can show a socket but cannot
// prove one missing, so the caller reads a hit from it and asks again for a miss. nil: the table could not be read.
func (s *snapshotter) wait(mark uint64) (snap *snapshot, late bool) {
	for {
		s.mu.Lock()
		if s.cur != nil && s.cur.seq > mark {
			cur := s.cur
			s.mu.Unlock()
			return cur, false
		}
		if f := s.inflight; f != nil {
			s.mu.Unlock()
			<-f.done
			return f.snap, f.seq <= mark
		}
		if wait := s.gap - time.Since(s.lastTry); wait > 0 {
			s.mu.Unlock()
			time.Sleep(wait)
			continue
		}
		s.seq++
		f := &flight{seq: s.seq, done: make(chan struct{})}
		s.inflight, s.lastTry = f, time.Now()
		s.mu.Unlock()

		rows, err := s.take()

		s.mu.Lock()
		if err == nil {
			f.snap = &snapshot{seq: f.seq, at: s.lastTry, rows: rows}
			s.cur = f.snap
		}
		s.inflight = nil
		s.mu.Unlock()
		close(f.done)
		return f.snap, false
	}
}

type portKey struct {
	udp  bool
	port uint16
	addr netip.Addr // the flow's source address: the same port may be open on two addresses
}

type portEntry struct {
	path  string
	pid   uint32 // 0: no local socket was found
	until time.Time
	seen  uint64 // the newest snapshot that showed the socket
}

// appResolver finds the program behind a flow's source socket.
type appResolver struct {
	tables  [2]*snapshotter // TCP, UDP
	pathOf  func(pid uint32) string
	gap     time.Duration
	ttl     time.Duration // how long a found owner is trusted without a newer table showing it
	missTTL time.Duration // how long "no local socket" is remembered

	mu    sync.Mutex // guards ports only; never held across a table read or a path lookup
	ports map[portKey]portEntry
}

func newAppResolver(take [2]func() ([]ownerRow, error), pathOf func(uint32) string, gap time.Duration) *appResolver {
	return &appResolver{
		tables:  [2]*snapshotter{{take: take[0], gap: gap}, {take: take[1], gap: gap}},
		pathOf:  pathOf,
		gap:     gap,
		ttl:     ownerTTL,
		missTTL: notOwnedTTL,
		ports:   make(map[portKey]portEntry),
	}
}

func newProcessOwners() *appResolver {
	var tcpBuf, udpBuf []byte // each used by its snapshotter only, which reads one table at a time
	return newAppResolver([2]func() ([]ownerRow, error){
		func() ([]ownerRow, error) { return readOwnerTable(false, &tcpBuf) },
		func() ([]ownerRow, error) { return readOwnerTable(true, &udpBuf) },
	}, processPath, snapshotGap)
}

// processOwners is the one resolver of the service: the tables are the machine's, not a tunnel's.
var processOwners = newProcessOwners()

func tableIndex(udp bool) int {
	if udp {
		return 1
	}
	return 0
}

// Cached answers from memory: a fresh entry whose socket the newest snapshot still shows.
func (r *appResolver) Cached(udp bool, src netip.AddrPort) (string, bool) {
	key := portKey{udp, src.Port(), src.Addr()}
	r.mu.Lock()
	e, ok := r.ports[key]
	r.mu.Unlock()
	if !ok || !time.Now().Before(e.until) {
		return "", false
	}
	if e.pid == 0 {
		return "", true
	}
	if cur := r.tables[tableIndex(udp)].current(); cur != nil && cur.seq > e.seen {
		// a newer table exists: the entry holds only while the port is still there and still the same process's
		if pid, found := cur.find(src); !found || pid != e.pid {
			r.mu.Lock()
			delete(r.ports, key)
			r.mu.Unlock()
			return "", false
		}
		e.seen = cur.seq
		r.mu.Lock()
		if old, ok := r.ports[key]; ok && old.pid == e.pid {
			r.ports[key] = e
		}
		r.mu.Unlock()
	}
	return e.path, true
}

// Owner returns the lower-case image path of the program holding the flow's source socket, "" when there is none (a
// process that is gone, a flow from another machine) or it cannot be opened.
func (r *appResolver) Owner(udp bool, src netip.AddrPort) string {
	if path, ok := r.Cached(udp, src); ok {
		return path
	}
	arrival := time.Now()
	table := r.tables[tableIndex(udp)]
	// A hit in a snapshot that is only a gap old is as good as a new one. A miss is not: the socket may be newer than the
	// snapshot, and the flow's packet proves it exists now, so a miss is settled only by a read that began after arrival.
	snap, mark := table.look()
	var pid uint32
	var found bool
	if snap != nil {
		pid, found = snap.find(src)
	}
	if !found {
		var late bool
		if snap, late = table.wait(mark); snap != nil {
			pid, found = snap.find(src)
			if !found && late { // that read began before the flow did: only a read begun now can say the socket is not there
				if snap, _ = table.wait(mark); snap != nil {
					pid, found = snap.find(src)
				}
			}
		}
	}
	if snap == nil {
		return "" // unreadable table: not remembered
	}
	key := portKey{udp, src.Port(), src.Addr()}
	entry := portEntry{until: arrival.Add(r.missTTL)}
	path := ""
	if found {
		path = r.pathOf(pid)
		entry = portEntry{path: path, pid: pid, until: arrival.Add(r.ttl), seen: snap.seq}
	}
	r.mu.Lock()
	if len(r.ports) >= maxOwnerKeys {
		now := time.Now()
		for k, e := range r.ports {
			if !now.Before(e.until) {
				delete(r.ports, k)
			}
		}
		if len(r.ports) >= maxOwnerKeys {
			clear(r.ports)
		}
	}
	r.ports[key] = entry
	r.mu.Unlock()
	return path
}

// readOwnerTable reads the owner table of a protocol for both address families. buf is reused between calls.
func readOwnerTable(udp bool, buf *[]byte) ([]ownerRow, error) {
	var rows []ownerRow
	for _, family := range [...]uint32{windows.AF_INET, afInet6} {
		table, err := getOwnerTable(udp, family, buf)
		if err != nil {
			return nil, err
		}
		rows = parseOwnerTable(rows, table, udp, family == afInet6)
	}
	return rows, nil
}

func getOwnerTable(udp bool, family uint32, buf *[]byte) ([]byte, error) {
	proc, class := procGetExtendedTCPTable, uintptr(tcpTableOwnerPIDAll)
	if udp {
		proc, class = procGetExtendedUDPTable, udpTableOwnerPID
	}
	for range 8 { // the table may grow between asking for its size and reading it
		size := uint32(len(*buf))
		var first unsafe.Pointer
		if size != 0 {
			first = unsafe.Pointer(&(*buf)[0])
		}
		r, _, _ := proc.Call(uintptr(first), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), class, 0)
		switch errno := windows.Errno(r); errno {
		case 0:
			return (*buf)[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			*buf = make([]byte, size+size/4+4096)
		default:
			return nil, errno
		}
	}
	return nil, errors.New("owner table keeps growing")
}

// parseOwnerTable appends the rows of a MIB_{TCP,UDP}{,6}TABLE_OWNER_PID: a count, then fixed-size rows. Listening TCP
// sockets are left out; a flow never comes from one. Ports are big endian in the first two bytes of their dword.
func parseOwnerTable(rows []ownerRow, table []byte, udp, v6 bool) []ownerRow {
	var rowSize, addrAt, addrLen, portAt, pidAt, stateAt int
	switch {
	case !udp && !v6:
		rowSize, addrAt, addrLen, portAt, pidAt, stateAt = 24, 4, 4, 8, 20, 0
	case !udp && v6:
		rowSize, addrAt, addrLen, portAt, pidAt, stateAt = 56, 0, 16, 20, 52, 48
	case udp && !v6:
		rowSize, addrAt, addrLen, portAt, pidAt, stateAt = 12, 0, 4, 4, 8, -1
	default:
		rowSize, addrAt, addrLen, portAt, pidAt, stateAt = 28, 0, 16, 20, 24, -1
	}
	if len(table) < 4 {
		return rows
	}
	count := int(binary.LittleEndian.Uint32(table))
	table = table[4:]
	if count > len(table)/rowSize {
		count = len(table) / rowSize
	}
	for i := 0; i < count; i++ {
		row := table[i*rowSize : (i+1)*rowSize]
		if stateAt >= 0 && binary.LittleEndian.Uint32(row[stateAt:]) == tcpStateListen {
			continue
		}
		var addr netip.Addr
		if addrLen == 4 {
			addr = netip.AddrFrom4([4]byte(row[addrAt:]))
		} else {
			addr = netip.AddrFrom16([16]byte(row[addrAt:])).Unmap()
		}
		// pid 0 is no program: a TIME_WAIT leftover on a port Windows has handed out again must not hide the live socket.
		pid := binary.LittleEndian.Uint32(row[pidAt:])
		if pid == 0 {
			continue
		}
		rows = append(rows, ownerRow{addr: addr, port: binary.BigEndian.Uint16(row[portAt:]), pid: pid})
	}
	return rows
}

type pidEntry struct {
	created uint64 // the process's creation time: a reused id has another
	path    string
}

var pidPaths = struct {
	sync.Mutex
	m map[uint32]pidEntry
}{m: make(map[uint32]pidEntry)}

// processPath is the lower-case image path of a process, "" when it is gone or closed to this service. It is kept
// with the creation time so that a process id taken over by another program never lends it the old path.
func processPath(pid uint32) string {
	if pid <= 4 { // Idle and System: no image
		return ""
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(handle, &created, &exited, &kernel, &user) != nil {
		return ""
	}
	stamp := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	pidPaths.Lock()
	e, ok := pidPaths.m[pid]
	pidPaths.Unlock()
	if ok && e.created == stamp {
		return e.path
	}
	path := imagePath(handle)
	pidPaths.Lock()
	if len(pidPaths.m) >= maxPidPaths {
		clear(pidPaths.m)
	}
	pidPaths.m[pid] = pidEntry{created: stamp, path: path}
	pidPaths.Unlock()
	return path
}

func imagePath(process windows.Handle) string {
	for _, n := range [...]int{1024, 32768} {
		buf := make([]uint16, n)
		size := uint32(n)
		err := windows.QueryFullProcessImageName(process, 0, &buf[0], &size)
		if err == nil {
			return strings.ToLower(windows.UTF16ToString(buf[:size]))
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return ""
		}
	}
	return ""
}
