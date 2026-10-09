// Package runner executes the save binaries with a timeout and an output cap.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// ErrOutputTooLarge is returned when stdout exceeds Runner.MaxOutput.
var ErrOutputTooLarge = errors.New("runner: output exceeds limit")

// Runner runs one command at a time-bounded, size-bounded.
type Runner struct {
	Timeout   time.Duration
	MaxOutput int64
}

// Run executes bin with args and returns stdout. It never passes extra flags.
func (r Runner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.WaitDelay = 2 * time.Second
	stderr := &limitedBuffer{max: 4096}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("runner: pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("runner: start %s: %w", bin, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(out, r.MaxOutput+1))
	tooLarge := int64(len(data)) > r.MaxOutput
	if tooLarge {
		cancel() // kill the process; we are not going to read the rest
	}
	waitErr := cmd.Wait()
	switch {
	case tooLarge:
		return nil, ErrOutputTooLarge
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("runner: %s timed out after %s", bin, r.Timeout)
	case readErr != nil:
		return nil, fmt.Errorf("runner: read %s: %w", bin, readErr)
	case waitErr != nil:
		return nil, fmt.Errorf("runner: %s: %w: %s", bin, waitErr, strings.TrimSpace(stderr.String()))
	}
	return data, nil
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }
