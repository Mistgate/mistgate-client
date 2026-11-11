package diag

import (
	"context"
	"io"
	"math"
	"net/http"
	"sync/atomic"
	"time"
)

// Speed through the tunnel, with ordinary sockets (with the VPN up they leave through it). This is the user's own
// traffic quota, so every transfer is bounded: about 8 MiB down and 4 MiB up at most.
//
// ponytail: one connection each way, to one host. It reads lower than a browser's multi-connection test and says
// nothing about other hosts; upgrade = a few parallel downloads.
const (
	speedDownBytes = 8 << 20 // the host refuses requests above about 10 MB
	speedDownTime  = 6 * time.Second
	speedUpBytes   = 4 << 20
	speedUpTime    = 3 * time.Second
	speedStage     = 12 * time.Second
	speedBucket    = 500 * time.Millisecond
	speedFailed    = 64 << 10 // under this many bytes in all is a failure
	speedDownURL   = "https://speed.cloudflare.com/__down?bytes=8388608"
	speedUpURL     = "https://speed.cloudflare.com/__up"
)

type Speed struct {
	Verdict   string  `json:"verdict"`
	DownMbps  float64 `json:"down_mbps"`
	UpMbps    float64 `json:"up_mbps"`
	FirstMbps float64 `json:"first_mbps"`
	LastMbps  float64 `json:"last_mbps"`
	Server    string  `json:"server"`
}

func mbps(bytes int, over time.Duration) float64 {
	if over <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1e6 / over.Seconds()
}

func bytesIn(buckets []int, from, to int) (n int) {
	for i := max(from, 0); i < min(to, len(buckets)); i++ {
		n += buckets[i]
	}
	return n
}

// speedStats turns a download (bytes per speedBucket, and how long it ran) into numbers and a verdict. down skips
// the first bucket (ramp-up); first and last are the averages of the first and the last 2 s. The verdict is ok,
// failed (under speedFailed bytes) or throttled (the speed fell after the first megabytes: a shaper).
func speedStats(buckets []int, elapsed time.Duration) (verdict string, down, first, last float64) {
	skip := 1
	if elapsed <= speedBucket {
		skip = 0 // too short to have a ramp-up to drop
	}
	down = mbps(bytesIn(buckets, skip, len(buckets)), elapsed-time.Duration(skip)*speedBucket)
	first = mbps(bytesIn(buckets, 0, int(2*time.Second/speedBucket)), min(elapsed, 2*time.Second))
	from := 0 // the first bucket that starts inside the last 2 s
	if elapsed > 2*time.Second {
		from = int((elapsed - 2*time.Second + speedBucket - 1) / speedBucket)
	}
	last = mbps(bytesIn(buckets, from, len(buckets)), elapsed-time.Duration(from)*speedBucket)
	switch {
	case bytesIn(buckets, 0, len(buckets)) < speedFailed:
		verdict = "failed"
	case elapsed >= 4*time.Second && first >= 2 && last < 0.4*first:
		verdict = "throttled"
	default:
		verdict = "ok"
	}
	return verdict, down, first, last
}

// speedDown reads url for maxTime or maxBytes, whichever comes first. The clock starts when the answer begins, so
// the connect is not in it; elapsed is how long the body was read, a stall at the end included.
func speedDown(ctx context.Context, client *http.Client, url string, maxBytes int, maxTime time.Duration) (buckets []int, elapsed time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, maxTime)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return nil, 0
	}
	start := time.Now()
	buffer := make([]byte, 32<<10)
	for total := 0; total < maxBytes; {
		n, err := response.Body.Read(buffer[:min(len(buffer), maxBytes-total)])
		if n > 0 {
			i := int(time.Since(start) / speedBucket)
			for len(buckets) <= i {
				buckets = append(buckets, 0)
			}
			buckets[i] += n
			total += n
		}
		if err != nil {
			break
		}
	}
	return buckets, time.Since(start)
}

// zeros is the upload body: cheap bytes, counted as the transport takes them.
type zeros struct {
	left  int
	sent  atomic.Int64
	start atomic.Int64 // unix nanoseconds of the first read: the connect is over, the upload begins
}

func (z *zeros) Read(p []byte) (int, error) {
	if z.left == 0 {
		return 0, io.EOF
	}
	z.start.CompareAndSwap(0, time.Now().UnixNano())
	n := min(len(p), z.left)
	clear(p[:n])
	z.left -= n
	z.sent.Add(int64(n))
	return n, nil
}

// speedUp POSTs maxBytes of zeros to url for maxTime at most and returns Mbit/s, or 0 when the host refused.
//
// ponytail: it counts bytes handed to the socket, so on a slow link, when the time runs out, it reads high by what
// the send buffer holds. A finished upload is exact (the clock stops at the answer). Upgrade = timed fixed chunks.
func speedUp(ctx context.Context, client *http.Client, url string, maxBytes int, maxTime time.Duration) float64 {
	ctx, cancel := context.WithTimeout(ctx, maxTime)
	defer cancel()
	body := &zeros{left: maxBytes}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return 0
	}
	request.ContentLength = int64(maxBytes) // not chunked: the host sizes the upload from it
	request.Header.Set("Content-Type", "text/plain")
	response, err := client.Do(request)
	end := time.Now()
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if response.StatusCode/100 != 2 {
			return 0
		}
	}
	start := body.start.Load()
	if start == 0 {
		return 0
	}
	return mbps(int(body.sent.Load()), end.Sub(time.Unix(0, start)))
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

// checkSpeed runs the download, then the upload (not after a failed download), in speedStage at most.
func checkSpeed(ctx context.Context, client *http.Client) Speed {
	ctx, cancel := context.WithTimeout(ctx, speedStage)
	defer cancel()
	buckets, elapsed := speedDown(ctx, client, speedDownURL, speedDownBytes, speedDownTime)
	var s Speed
	s.Verdict, s.DownMbps, s.FirstMbps, s.LastMbps = speedStats(buckets, elapsed)
	if s.Verdict != "failed" {
		s.UpMbps = speedUp(ctx, client, speedUpURL, speedUpBytes, speedUpTime)
	}
	s.DownMbps, s.UpMbps, s.FirstMbps, s.LastMbps = round1(s.DownMbps), round1(s.UpMbps), round1(s.FirstMbps), round1(s.LastMbps)
	return s
}

// speedClient dials like any program on this machine: no proxy, no pinned interface.
func speedClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: freezeConnect,
	}}
}
