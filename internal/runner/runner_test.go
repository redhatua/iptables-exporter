package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunSuccess(t *testing.T) {
	r := Runner{Timeout: 5 * time.Second, MaxOutput: 1 << 20}
	out, err := r.Run(context.Background(), script(t, `echo "args: $*"`), "-c")
	if err != nil || strings.TrimSpace(string(out)) != "args: -c" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestRunNonZeroExitIncludesStderr(t *testing.T) {
	r := Runner{Timeout: 5 * time.Second, MaxOutput: 1 << 20}
	_, err := r.Run(context.Background(), script(t, `echo boom >&2; exit 3`))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunOutputTooLarge(t *testing.T) {
	r := Runner{Timeout: 5 * time.Second, MaxOutput: 1000}
	_, err := r.Run(context.Background(), script(t, `exec yes`))
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunTimeout(t *testing.T) {
	r := Runner{Timeout: 200 * time.Millisecond, MaxOutput: 1 << 20}
	start := time.Now()
	_, err := r.Run(context.Background(), script(t, `exec sleep 5`))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

func TestRunMissingBinary(t *testing.T) {
	r := Runner{Timeout: time.Second, MaxOutput: 1 << 20}
	if _, err := r.Run(context.Background(), "/nonexistent/iptables-save"); err == nil {
		t.Fatal("expected error")
	}
}
