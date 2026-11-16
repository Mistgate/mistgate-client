package safe

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrLinkLocal: the address a fetch was about to reach is a link-local one.
var ErrLinkLocal = errors.New("link-local address refused")

// FetchClient is for requests to an address somebody else chose: a subscription link, a list by its link. The service
// runs as SYSTEM, and such a link can name anything the machine reaches. Link-local addresses are refused at connect
// time, after the name is resolved: nothing a person adds lives there, and a cloud machine's metadata service does.
// ponytail: private and loopback addresses stay open, a panel at home or on this PC is a real case. Upgrade = refuse
// them for a link that came from outside (mistgate://), which the service would have to be told.
func FetchClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: noLinkLocal}).DialContext
	return &http.Client{Timeout: timeout, Transport: transport}
}

func noLinkLocal(_, address string, _ syscall.RawConn) error {
	if target, err := netip.ParseAddrPort(address); err == nil && target.Addr().Unmap().IsLinkLocalUnicast() {
		return ErrLinkLocal
	}
	return nil
}
