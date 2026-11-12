package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// touchWriter notes the time of every write that got through: the idle timer reads it.
type touchWriter struct {
	net.Conn
	last *atomic.Int64
}

func (w touchWriter) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if n > 0 {
		w.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func copyDirection(dst, src net.Conn, last *atomic.Int64) error {
	buffer := bufPool.Get().(*[]byte)
	defer bufPool.Put(buffer)
	// touchWriter has no ReadFrom and src no WriteTo that matters: the copy goes through the pooled buffer
	_, err := io.CopyBuffer(touchWriter{Conn: dst, last: last}, src, *buffer)
	return err
}

// relay copies both ways until both are done and returns with both closed. An end of data in one direction is passed
// on as a half-close when the other side can take it, so that a request sent and shut can still be answered. A side
// that cannot (a Hysteria2 stream) leaves the other direction a short time to finish. A tunnel with no data in either
// direction for p.idle is closed.
func (p *Proxy) relay(client, up net.Conn) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	closeBoth := func() {
		_ = client.Close()
		_ = up.Close()
	}
	var mu sync.Mutex // the limit and the timer
	limit := p.idle
	var timer *time.Timer
	mu.Lock()
	timer = time.AfterFunc(limit, func() {
		mu.Lock()
		defer mu.Unlock()
		quiet := time.Since(time.Unix(0, last.Load()))
		if quiet >= limit {
			go closeBoth()
			return
		}
		timer.Reset(limit - quiet)
	})
	mu.Unlock()
	var done sync.WaitGroup
	done.Add(2)
	pump := func(dst, src net.Conn) {
		defer done.Done()
		if err := copyDirection(dst, src, &last); err != nil {
			closeBoth() // a reset, a timeout, or the other side's close: nothing more to say
			return
		}
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			if err := half.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
				return
			}
		}
		mu.Lock()
		limit = min(limit, p.halfCloseIdle)
		last.Store(time.Now().UnixNano())
		timer.Reset(limit)
		mu.Unlock()
	}
	go pump(up, client)
	pump(client, up)
	done.Wait()
	mu.Lock()
	timer.Stop()
	mu.Unlock()
	closeBoth()
}

// idleConn gives a connection a deadline that moves with every read and write, for the requests that go through
// net/http, which does not keep an idle time of its own for a body.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(b)
}

func (c idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(b)
}
