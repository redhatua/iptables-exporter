// Package snapshot collects targets in the background and publishes immutable snapshots.
package snapshot

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/redhatua/iptables-exporter/internal/model"
)

// Result is the latest state of one target. When Up is false, Tables is nil:
// counters are never served stale. Taken is the time of the last success.
type Result struct {
	Target   Target
	Up       bool
	Version  string
	Tables   []model.Table
	Taken    time.Time
	Duration time.Duration
}

// Snapshot is an immutable set of results.
type Snapshot struct {
	Results []Result
}

type targetState struct {
	last     Result
	failures int
	next     time.Time
}

// Manager owns the collection loop.
type Manager struct {
	targets  []Target
	fetcher  Fetcher
	interval time.Duration
	logger   *slog.Logger
	now      func() time.Time
	state    map[Target]*targetState
	cur      atomic.Pointer[Snapshot]
	ready    atomic.Bool
}

// NewManager builds a manager; call Run to start collecting.
func NewManager(targets []Target, f Fetcher, interval time.Duration, logger *slog.Logger) *Manager {
	m := &Manager{
		targets: targets, fetcher: f, interval: interval, logger: logger,
		now: time.Now, state: map[Target]*targetState{},
	}
	for _, t := range targets {
		m.state[t] = &targetState{last: Result{Target: t}}
	}
	m.cur.Store(&Snapshot{})
	return m
}

// Current returns the latest snapshot; never nil.
func (m *Manager) Current() *Snapshot { return m.cur.Load() }

// Ready reports whether the first collection round has completed.
func (m *Manager) Ready() bool { return m.ready.Load() }

// Run collects immediately and then every interval until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	m.tick(ctx)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

func (m *Manager) tick(ctx context.Context) {
	results := make([]Result, 0, len(m.targets))
	for _, t := range m.targets {
		st := m.state[t]
		if m.now().Before(st.next) {
			results = append(results, st.last)
			continue
		}
		start := m.now()
		f, err := m.fetcher.Fetch(ctx, t)
		d := m.now().Sub(start)
		if err != nil {
			st.failures++
			st.next = m.now().Add(backoffDelay(m.interval, st.failures))
			m.logger.Warn("collection failed", "family", t.Family, "backend", t.Backend,
				"failures", st.failures, "err", err)
			st.last = Result{Target: t, Up: false, Version: st.last.Version, Taken: st.last.Taken, Duration: d}
		} else {
			st.failures = 0
			st.next = time.Time{}
			st.last = Result{Target: t, Up: true, Version: f.Version, Tables: f.Tables, Taken: m.now(), Duration: d}
		}
		results = append(results, st.last)
	}
	m.cur.Store(&Snapshot{Results: results})
	m.ready.Store(true)
}
