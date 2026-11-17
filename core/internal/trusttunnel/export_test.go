package trusttunnel

// ForgetHTTP3 clears what Connect remembers of the hosts that got HTTP/3, for tests that dial one host again.
func ForgetHTTP3() {
	h3Chosen.Lock()
	clear(h3Chosen.at)
	h3Chosen.Unlock()
}
