package safe

import "testing"

func TestRecoverKeepsTheProcess(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer Recover("test")
		var m map[string]int
		m["x"] = 1
	}()
	<-done
}
