//go:build windows

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/geo"
)

func watchedFlow(t *testing.T, tr *geo.Tracker) (*flowWatch, net.Conn) {
	t.Helper()
	remote, site := net.Pipe()
	t.Cleanup(func() { _ = remote.Close(); _ = site.Close() })
	return &flowWatch{track: tr, route: geo.ViaVPN, name: "www.example.com", remote: remote}, site
}

// failedOnVPN is how many failures example.com has through the VPN, once there are enough to be offered (3).
func failedOnVPN(store *geo.Store) int {
	for _, item := range store.Routes("selected", "", "").Suggest.Direct {
		if item.Site == "example.com" {
			return item.Count
		}
	}
	return 0
}

func TestFlowWatchCountsClosesAndSilenceNotAnswersOrOurOwnClose(t *testing.T) {
	store, err := geo.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := store.Failures()
	tr.OK(geo.ViaVPN, "other.org", time.Now())
	buf := make([]byte, 16)

	// closed by the site before any byte: two failures so far, one short of an offer
	for i := 0; i < 2; i++ {
		w, site := watchedFlow(t, tr)
		_ = site.Close()
		if _, err := w.Read(buf); err == nil {
			t.Fatal("expected an error")
		}
	}
	if got := failedOnVPN(store); got != 0 {
		t.Fatalf("two failures offered: %d", got)
	}

	// closed by us (the app went away): not the site's doing, so still no offer
	w, site := watchedFlow(t, tr)
	w.closing.Store(true)
	_ = site.Close()
	_, _ = w.Read(buf)
	if got := failedOnVPN(store); got != 0 {
		t.Fatalf("our own close counted: %d", got)
	}

	// silence is the third failure, counted once while the flow stays open; the late answer clears them all
	old := noAnswerAfter
	noAnswerAfter = 30 * time.Millisecond
	defer func() { noAnswerAfter = old }()
	w, site = watchedFlow(t, tr)
	read := make(chan string, 1)
	go func() {
		n, _ := w.Read(buf)
		read <- string(buf[:n])
	}()
	time.Sleep(200 * time.Millisecond)
	if got := failedOnVPN(store); got != 3 {
		t.Fatalf("silent flow: failures = %d, want 3", got)
	}
	_, _ = site.Write([]byte("hello"))
	if got := <-read; got != "hello" || !w.silent || !w.got {
		t.Fatalf("late answer = %q (silent %t, got %t)", got, w.silent, w.got)
	}
	if got := failedOnVPN(store); got != 0 {
		t.Fatalf("a late answer left %d failures", got)
	}

	// after the first byte nothing is counted any more
	_ = site.Close()
	if _, err := w.Read(buf); err == nil {
		t.Fatal("expected EOF")
	}
	for i := 0; i < 2; i++ {
		w, site := watchedFlow(t, tr)
		_ = site.Close()
		_, _ = w.Read(buf)
	}
	if got := failedOnVPN(store); got != 0 {
		t.Fatalf("a close after an answer counted: %d", got)
	}
}
