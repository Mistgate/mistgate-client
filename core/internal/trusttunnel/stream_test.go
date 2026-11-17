package trusttunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// echoClient is a client on a stub that tunnels every CONNECT to a local echo listener.
func echoClient(t *testing.T) (*Client, string) {
	t.Helper()
	target := startEchoListener(t)
	stub := newEndpoint(t, true, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		if r.Host == "_check" {
			w.WriteHeader(http.StatusOK)
			return
		}
		serveTCPTunnel(w, r, target.Addr().String())
	})
	client := stub.dial(t, "user", "password")
	t.Cleanup(func() { _ = client.Close() })
	return client, target.Addr().String()
}

// echoRound writes a word and reads it back, which only a stream that is still open can do.
func echoRound(conn net.Conn, word string) error {
	if _, err := conn.Write([]byte(word)); err != nil {
		return err
	}
	got := make([]byte, len(word))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != word {
		return fmt.Errorf("echo = %q, want %q", got, word)
	}
	return nil
}

// DialVPN and the proxy cancel the dial's context once the dial returns: the stream must live on.
func TestStreamOutlivesTheDialContext(t *testing.T) {
	client, target := echoClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := client.DialTCP(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	time.Sleep(100 * time.Millisecond) // a reset, if the cancel sent one, is on its way
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := echoRound(conn, "after the cancel"); err != nil {
		t.Fatalf("stream after the dial context was cancelled: %v", err)
	}
}

// A server that never answers the CONNECT holds nothing for ever, whatever the caller's context says.
func TestDialTCPHeaderWaitIsBounded(t *testing.T) {
	old := headerTimeout
	headerTimeout = 300 * time.Millisecond
	t.Cleanup(func() { headerTimeout = old })
	stub := newEndpoint(t, true, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		if r.Host == "_check" {
			w.WriteHeader(http.StatusOK)
			return
		}
		<-r.Context().Done() // no headers
	})
	client := stub.dial(t, "user", "password")
	defer client.Close()

	dial := func(ctx context.Context) error {
		result := make(chan error, 1)
		go func() {
			conn, err := client.DialTCP(ctx, "example.test:443")
			if err == nil {
				_ = conn.Close()
			}
			result <- err
		}()
		select {
		case err := <-result:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("DialTCP is still waiting")
		}
	}
	if err := dial(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialTCP with no context deadline = %v, want the header timeout", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if err := dial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialTCP cancelled by the caller = %v, want context.Canceled", err)
	}
}

// A read deadline is a timeout of that read: the stream stays, and an answer that comes later is not lost.
func TestReadDeadlineLeavesTheStreamUsable(t *testing.T) {
	pool, target := echoPool(t, 0)
	conn, err := pool.DialTCP(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1)) // one byte: the read left running has a one-byte buffer
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read past its deadline = %v, want a timeout error", err)
	}
	if len(pool.slots) != 1 {
		t.Fatalf("the stream holds %d places after a timed out read, want 1", len(pool.slots))
	}
	_ = conn.SetReadDeadline(time.Time{})
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write after the timeout: %v", err)
	}
	got := make([]byte, 0, 5)
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(got) < 5 {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("read after the timeout: %v (got %q)", err, got)
		}
	}
	if string(got) != "hello" {
		t.Fatalf("answer after the timeout = %q", got)
	}
	// A deadline that is set later than a read in flight moves that read's limit too.
	_ = conn.SetReadDeadline(time.Now().Add(time.Hour))
	time.AfterFunc(50*time.Millisecond, func() { _ = conn.SetReadDeadline(time.Now()) })
	if _, err := conn.Read(buf); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read woken by a new deadline = %v, want a timeout error", err)
	}
}

// A connection at the server's stream limit is full, not dead; only a closed or closing one is.
func TestSessionAtTheStreamLimitIsAlive(t *testing.T) {
	der, certificate := endpointCertificate(t)
	server := newHTTPTestServerWithMaxConcurrentStreams(t, certificate, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if r.Host != "_check" {
			<-r.Context().Done()
		}
	}, 2)
	config := Config{Host: "example.test", SNI: "example.test", Addresses: []string{server.Addr()}, Username: "user", Password: "password", Certs: [][]byte{der}}
	client, err := Dial(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for range 2 {
		conn, err := client.DialTCP(context.Background(), "example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	time.Sleep(400 * time.Millisecond) // the watcher looks every 100 ms
	select {
	case <-client.Done():
		t.Fatalf("session declared dead at the stream limit: %v", client.Err())
	default:
	}
	// A third stream waits for a place; the caller giving up must not end the session either.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := client.DialTCP(ctx, "example.test:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("third stream = %v, want the caller's deadline", err)
	}
	select {
	case <-client.Done():
		t.Fatalf("session declared dead after a stream was refused a place: %v", client.Err())
	default:
	}
}

func udpFrame(length uint32, body []byte) []byte {
	frame := binary.BigEndian.AppendUint32(nil, length)
	return append(frame, body...)
}

// One datagram the client cannot use is skipped, as a short one already was.
func TestOversizedIncomingFrameIsSkipped(t *testing.T) {
	var oversized bytes.Buffer
	oversized.Write(udpFrame(maxUDPFrame+1, make([]byte, maxUDPFrame+1)))
	oversized.Write(udpFrame(37, make([]byte, 37)))
	body, err := readIncomingFrame(&oversized)
	if err != nil || len(body) != 37 {
		t.Fatalf("frame after one above the datagram limit: %d bytes, %v", len(body), err)
	}
	if _, err := readIncomingFrame(bytes.NewReader(udpFrame(maxSkippedFrame+1, nil))); err == nil {
		t.Fatal("a length no datagram can have was taken for a frame to skip")
	}
}

// A frame for destination port 0 is a datagram no flow can have: it is skipped and the stream goes on.
func TestDestinationPortZeroFrameIsSkipped(t *testing.T) {
	stub := newEndpoint(t, true, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		portZero := make([]byte, 36)
		copy(portZero[12:16], []byte{203, 0, 113, 7})
		binary.BigEndian.PutUint16(portZero[16:18], 443)
		_, _ = w.Write(udpFrame(36, portZero))
		echoUDPFrames(w, r)
	})
	client := stub.dial(t, "user", "password")
	defer client.Close()
	flow, err := client.ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	target := netip.MustParseAddrPort("203.0.113.9:53")
	if err := flow.WriteTo([]byte("ping"), target); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		payload, source, err := flow.ReadFrom()
		if err == nil && (string(payload) != "ping" || source != target) {
			err = fmt.Errorf("reply %q from %v", payload, source)
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("the datagram after the odd frames: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply after the odd frames")
	}
}

type sentFrame struct {
	port    uint16
	payload []byte
}

// A datagram flood that the server's flow control holds back must not stop the other flows, and a flow's frames keep
// their order.
func TestStalledUDPUploadDoesNotBlockOtherFlows(t *testing.T) {
	release := make(chan struct{})
	received := make(chan sentFrame, 4096)
	stub := newEndpoint(t, true, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-release // the body is not read: HTTP/2 flow control stops the client's writes
		for {
			body, err := readOutgoingBody(r.Body)
			if err != nil {
				return
			}
			received <- sentFrame{port: binary.BigEndian.Uint16(body[16:18]), payload: append([]byte(nil), body[37+int(body[36]):]...)}
		}
	})
	client := stub.dial(t, "user", "password")
	defer client.Close()
	flood, err := client.ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer flood.Close()
	dns, err := client.ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	target := netip.MustParseAddrPort("203.0.113.9:443")
	floodPort := flood.(*udpFlow).port

	done := make(chan error, 1)
	go func() {
		if err := dns.WriteTo([]byte("first"), target); err != nil {
			done <- err
			return
		}
		big := make([]byte, maxUDPPayload)
		for seq := range 300 { // 18 MB, far more than the two flow-control windows
			binary.BigEndian.PutUint16(big, uint16(seq))
			if err := flood.WriteTo(big, target); err != nil {
				done <- err
				return
			}
		}
		done <- dns.WriteTo([]byte("second"), target)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UDP write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled upload blocked the writes of every flow")
	}

	close(release)
	last, sawFirst := -1, false
	deadline := time.After(10 * time.Second)
	for !sawFirst || last < 0 {
		select {
		case frame := <-received:
			switch {
			case frame.port == floodPort:
				seq := int(binary.BigEndian.Uint16(frame.payload))
				if seq <= last {
					t.Fatalf("flood frame %d arrived after %d", seq, last)
				}
				last = seq
			case string(frame.payload) == "first":
				sawFirst = true
			}
		case <-deadline:
			t.Fatalf("after the release: first frame seen = %v, flood frames up to %d", sawFirst, last)
		}
	}
}
