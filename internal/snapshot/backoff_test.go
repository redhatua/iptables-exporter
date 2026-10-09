package snapshot

import (
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	iv := 15 * time.Second
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 0}, {1, 15 * time.Second}, {2, 30 * time.Second}, {3, 60 * time.Second},
		{4, 120 * time.Second}, {5, 240 * time.Second}, {6, 5 * time.Minute}, {50, 5 * time.Minute},
	}
	for _, tc := range cases {
		if got := backoffDelay(iv, tc.failures); got != tc.want {
			t.Errorf("failures=%d got %s want %s", tc.failures, got, tc.want)
		}
	}
}
