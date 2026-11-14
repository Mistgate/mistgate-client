//go:build windows

package ipc

import "testing"

func TestPipeSlotsReserveCapacityForTrustedCaller(t *testing.T) {
	slots := newPipeConnectionSlots()
	regular := make([]pipeConnectionPermit, 0, maxUntrustedPipeConnections)
	for range maxUntrustedPipeConnections {
		permit, ok := slots.acquire()
		if !ok || permit != regularPermit {
			t.Fatal("an untrusted connection could not take an available slot")
		}
		regular = append(regular, permit)
	}
	reserved, ok := slots.acquire()
	if !ok || reserved != reservedPermit {
		t.Fatal("the trusted caller's classification slot was not available")
	}
	if _, ok := slots.acquire(); ok {
		t.Fatal("the connection limit was exceeded")
	}
	if _, ok := slots.promoteUntrusted(reserved); ok {
		t.Fatal("a reserved caller became an eighth untrusted connection")
	}

	// A trusted caller releases its classification permit but keeps the connection slot.
	slots.releasePermit(reserved)
	slots.release(reserved, false)
	for _, permit := range regular {
		slots.release(permit, true)
	}
	permit, ok := slots.acquire()
	if !ok {
		t.Fatal("released connection capacity was not reusable")
	}
	slots.release(permit, true)
}
