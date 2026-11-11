package diag

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpeedStats(t *testing.T) {
	// n buckets of the same size
	steady := func(n, size int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = size
		}
		return out
	}
	// a fast start of `head` buckets, then `tail` buckets of another size
	fall := func(head, headSize, tail, tailSize int) []int {
		return append(steady(head, headSize), steady(tail, tailSize)...)
	}
	s := time.Second
	cases := []struct {
		name              string
		buckets           []int
		elapsed           time.Duration
		verdict           string
		down, first, last float64 // -1: not checked
	}{
		{"steady 4 Mbit/s", steady(12, 250000), 6 * s, "ok", 4, 4, 4},
		{"ramp-up is not in down", append([]int{0}, steady(11, 250000)...), 6 * s, "ok", 4, 3, 4},
		{"falls after the first megabytes", fall(4, 1250000, 8, 100000), 6 * s, "throttled", 6.618, 20, 1.6},
		{"stops after the first megabytes", steady(4, 1250000), 6 * s, "throttled", 5.455, 20, 0},
		{"falls, but under 4 s measured", fall(4, 1250000, 2, 100000), 3 * s, "ok", 12.64, 20, 10.8},
		{"a slow start is not a shaper", fall(4, 93750, 8, 5000), 6 * s, "ok", -1, 1.5, 0.08},
		{"just under 0.4 of the first", fall(4, 1250000, 4, 480000), 4 * s, "throttled", -1, 20, 7.68},
		{"just over 0.4 of the first", fall(4, 1250000, 4, 520000), 4 * s, "ok", -1, 20, 8.32},
		{"10 KB in all", []int{10000}, 6 * s, "failed", -1, -1, -1},
		{"65535 bytes in all", []int{65535}, s, "failed", -1, -1, -1},
		{"65536 bytes in all", []int{65536}, s, "ok", 0, 0.524, 0.524},
		{"nothing", nil, 0, "failed", 0, 0, 0},
	}
	near := func(got, want float64) bool { return want < 0 || math.Abs(got-want) < 0.01 }
	for _, c := range cases {
		verdict, down, first, last := speedStats(c.buckets, c.elapsed)
		if verdict != c.verdict || !near(down, c.down) || !near(first, c.first) || !near(last, c.last) {
			t.Errorf("%s: got %s down=%.3f first=%.3f last=%.3f; want %s %v %v %v", c.name, verdict, down, first, last, c.verdict, c.down, c.first, c.last)
		}
	}
}

func TestSpeedDownBoundsAndFailures(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, 2<<20)) })
	mux.HandleFunc("/stall", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 100<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	sum := func(buckets []int) int { return bytesIn(buckets, 0, len(buckets)) }

	if buckets, elapsed := speedDown(context.Background(), server.Client(), server.URL+"/big", 1<<20, 5*time.Second); sum(buckets) != 1<<20 || elapsed > 3*time.Second {
		t.Errorf("byte bound: %d bytes in %v, want exactly 1 MiB, quickly", sum(buckets), elapsed)
	}
	// a stall is measured to the end of the time bound, so a download that dies is seen as one
	if buckets, elapsed := speedDown(context.Background(), server.Client(), server.URL+"/stall", 1<<20, 400*time.Millisecond); sum(buckets) != 100<<10 || elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("time bound: %d bytes in %v, want 100 KiB until about 400 ms", sum(buckets), elapsed)
	}
	if buckets, _ := speedDown(context.Background(), server.Client(), server.URL+"/missing", 1<<20, time.Second); sum(buckets) != 0 {
		t.Errorf("404 gave %d bytes", sum(buckets))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if buckets, _ := speedDown(ctx, server.Client(), server.URL+"/big", 1<<20, time.Second); sum(buckets) != 0 {
		t.Errorf("cancelled run gave %d bytes", sum(buckets))
	}
}

func TestSpeedUpSendsZerosAndStopsOnTime(t *testing.T) {
	var received, nonZero atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.Store(int64(len(body)))
		for _, b := range body {
			if b != 0 {
				nonZero.Add(1)
			}
		}
		if r.Method != http.MethodPost || r.ContentLength != int64(len(body)) {
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/refuse", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	release := make(chan struct{}) // a handler that does not read the body never sees the client leave
	mux.HandleFunc("/ignore", func(http.ResponseWriter, *http.Request) { <-release })
	server := httptest.NewServer(mux)
	defer server.Close()
	defer close(release)

	if up := speedUp(context.Background(), server.Client(), server.URL+"/up", 1<<20, 5*time.Second); up <= 0 || received.Load() != 1<<20 || nonZero.Load() != 0 {
		t.Errorf("upload: %.1f Mbit/s, host got %d bytes (%d not zero), want 1 MiB of zeros", up, received.Load(), nonZero.Load())
	}
	if up := speedUp(context.Background(), server.Client(), server.URL+"/refuse", 1<<20, 5*time.Second); up != 0 {
		t.Errorf("refused upload = %.1f Mbit/s, want 0", up)
	}
	begun := time.Now()
	speedUp(context.Background(), server.Client(), server.URL+"/ignore", 1<<30, 300*time.Millisecond)
	if took := time.Since(begun); took > 2*time.Second {
		t.Errorf("an upload nobody reads took %v, want about 300 ms", took)
	}
}
