package diag

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// A download that "freezes": a device on the way lets the connection start and, after the first kilobytes, stops
// delivering it. A plain reachability check does not see it. The probe fetches the first 128 KiB of a file from a
// few foreign hosts and a control host, outside the tunnel.
//
// The reference client runs the same probe (131072 bytes from speed.cloudflare.com) but through each server under
// test; this client has no proxy per server, so it asks the network itself. Cloudflare is the host such devices are
// known to cut; the second target sits at a different provider, the control must not be cut at all.
//
// ponytail: the hosts are fixed and public; if one disappears the verdict degrades to "unknown", never to a false
// "freeze". Upgrade = hosts from the panel.
var (
	freezeTargets = []struct{ name, url string }{
		{"cloudflare", "https://speed.cloudflare.com/__down?bytes=131072"},
		{"hetzner", "https://fsn1-speed.hetzner.com/100MB.bin"},
	}
	freezeControl = "https://speedtest.selectel.ru/10MB"
)

const (
	freezeBytes   = 131072
	freezeWindow  = 65535 // a stall after 1..freezeWindow bytes is a freeze; later it is something else
	freezeIdle    = 6 * time.Second
	freezeConnect = 4 * time.Second
	freezeTotal   = 15 * time.Second
)

// transfer is what one download measured.
type transfer struct {
	Bytes   int
	Idle    time.Duration // silence since the last byte when the download ended
	Done    bool          // all of freezeBytes arrived
	Stalled bool          // it ended because nothing arrived for the idle limit
	Replied bool          // the host answered with an HTTP status, good or bad
}

// transferVerdict: ok (complete), freeze (stalled inside the window), blocked (nothing arrived and the host never
// replied: connect, handshake or request refused or timed out), unknown (anything else).
func transferVerdict(t transfer) string {
	switch {
	case t.Done:
		return "ok"
	case t.Bytes == 0 && !t.Replied:
		return "blocked"
	case t.Stalled && t.Bytes > 0 && t.Bytes <= freezeWindow:
		return "freeze"
	}
	return "unknown"
}

// freezeVerdict folds the targets into one verdict. Without a completed control download nothing can be said:
// a slow or broken network is not a freeze, so every verdict is "unknown".
func freezeVerdict(control transfer, targets []transfer) (overall string, each []string) {
	each = make([]string, len(targets))
	for i, t := range targets {
		each[i] = transferVerdict(t)
		if !control.Done {
			each[i] = "unknown"
		}
	}
	overall = "unknown"
	// one host out of reach says nothing about the network while another completes: "blocked" only when none did
	for _, want := range []string{"freeze", "ok", "blocked"} {
		for _, v := range each {
			if v == want {
				return want, each
			}
		}
	}
	return overall, each
}

// fetch reads up to want bytes of url, giving up when connecting takes longer than connect or nothing arrives for idle.
func fetch(ctx context.Context, client *http.Client, url string, want int, connect, idle time.Duration) (t transfer) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	timer := time.AfterFunc(connect, func() { stalled.Store(true); cancel() })
	defer timer.Stop()
	last := time.Now()
	defer func() { t.Stalled, t.Idle = stalled.Load(), time.Since(last) }()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return t
	}
	// speed.cloudflare.com sizes the answer itself and ignores this; the file hosts need it
	request.Header.Set("Range", fmt.Sprintf("bytes=0-%d", want-1))
	response, err := client.Do(request)
	if err != nil {
		return t
	}
	defer response.Body.Close()
	t.Replied = true
	if response.StatusCode/100 != 2 {
		return t
	}
	timer.Reset(idle)
	last = time.Now()
	buffer := make([]byte, 16<<10)
	for t.Bytes < want {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			t.Bytes += n
			timer.Reset(idle)
			last = time.Now()
		}
		if err != nil {
			break
		}
	}
	t.Done = t.Bytes >= want
	return t
}

// freezeClient dials every connection through the physical interface, as the other probes do.
func freezeClient(physical interfaceInfo) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: freezeConnect,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip, err := resolveHost(ctx, host, physical, Config{})
			if err != nil {
				return nil, err
			}
			return dialBound(ctx, network, net.JoinHostPort(ip.String(), port), physical)
		},
	}}
}

type FreezeTarget struct {
	Name    string `json:"name"`
	Bytes   int    `json:"bytes"`
	Verdict string `json:"verdict"`
}

// checkFreeze downloads from the control and all targets at once, in freezeTotal at most. facts is the log line:
// bytes and idle time per download, control first; no hosts.
func checkFreeze(ctx context.Context, client *http.Client) (overall string, targets []FreezeTarget, facts string) {
	ctx, cancel := context.WithTimeout(ctx, freezeTotal)
	defer cancel()
	urls := []string{freezeControl}
	for _, t := range freezeTargets {
		urls = append(urls, t.url)
	}
	results := make([]transfer, len(urls))
	var wait sync.WaitGroup
	for i, url := range urls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[i] = fetch(ctx, client, url, freezeBytes, freezeConnect, freezeIdle)
		}()
	}
	wait.Wait()
	overall, each := freezeVerdict(results[0], results[1:])
	targets = make([]FreezeTarget, len(freezeTargets))
	for i, t := range freezeTargets {
		targets[i] = FreezeTarget{Name: t.name, Bytes: results[i+1].Bytes, Verdict: each[i]}
	}
	for _, t := range results {
		facts += fmt.Sprintf(" %dB/%dms", t.Bytes, t.Idle.Milliseconds())
	}
	return overall, targets, facts
}
