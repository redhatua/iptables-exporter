package snapshot

import "time"

const maxBackoff = 5 * time.Minute

// backoffDelay is how long to wait before retrying a target that has failed
// `failures` times in a row: interval * 2^(failures-1), capped at 5 minutes.
func backoffDelay(interval time.Duration, failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := interval
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}
