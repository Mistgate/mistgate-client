package subs

import (
	"strings"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/version"
)

func TestSubscriptionUserAgentsUseServiceVersion(t *testing.T) {
	if !strings.Contains(apiUserAgent, "Mistgate/"+version.Service+" ") {
		t.Fatal("managed subscription User-Agent does not use the service version")
	}
	if got := plainUserAgent(); !strings.HasPrefix(got, "mihomo/1.19.33 ") || !strings.Contains(got, "Mistgate/"+version.Service+" ") {
		t.Fatal("plain subscription User-Agent changed its mihomo prefix or omitted the service version")
	}
}
