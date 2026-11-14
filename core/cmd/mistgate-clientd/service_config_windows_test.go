//go:build windows

package main

import (
	"reflect"
	"testing"

	"golang.org/x/sys/windows/svc/mgr"
)

func TestServiceConfigurationWaitsForFirewallAndTCPIP(t *testing.T) {
	if got := serviceConfiguration().Dependencies; !reflect.DeepEqual(got, []string{"BFE", "Tcpip"}) {
		t.Fatalf("service dependencies = %#v", got)
	}
}

func TestUpdatingServiceDependenciesPreservesExistingConfig(t *testing.T) {
	configured := withServiceDependencies(mgr.Config{
		DisplayName:  "Existing service",
		Description:  "Existing description",
		StartType:    mgr.StartManual,
		Dependencies: []string{"OldDependency"},
	})

	if configured.DisplayName != "Existing service" || configured.Description != "Existing description" || configured.StartType != mgr.StartManual {
		t.Fatalf("service config fields changed: %#v", configured)
	}
	if want := []string{"BFE", "Tcpip"}; !reflect.DeepEqual(configured.Dependencies, want) {
		t.Fatalf("updated dependencies = %#v, want %#v", configured.Dependencies, want)
	}
}
