package auto

import "testing"

func TestASNNet(t *testing.T) {
	dir := t.TempDir()
	m := Open(dir)
	m.SetASNNet("s1", "net-a")
	m.SetASNNet("s2", "net-b")
	m.Flush()
	again := Open(dir) // a restart
	if again.ASNNet("s1") != "net-a" || again.ASNNet("s2") != "net-b" || again.ASNNet("s3") != "" {
		t.Fatalf("after a restart: %q %q %q", again.ASNNet("s1"), again.ASNNet("s2"), again.ASNNet("s3"))
	}
	again.SetASNNet("s1", "") // a sync in a network that cannot be named: the old note is no use
	if again.ASNNet("s1") != "" {
		t.Fatal("an unknown network left the old note")
	}
	var none *Memory // a nil memory remembers nothing
	none.SetASNNet("s1", "net-a")
	if none.ASNNet("s1") != "" {
		t.Fatal("a nil memory remembered")
	}
}
