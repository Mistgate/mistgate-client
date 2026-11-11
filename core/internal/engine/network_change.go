package engine

import "time"

func debounceDelay(lastEvent, now time.Time, quiet time.Duration) time.Duration {
	delay := quiet - now.Sub(lastEvent)
	if delay < 0 {
		return 0
	}
	return delay
}
