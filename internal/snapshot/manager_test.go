package snapshot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/redhatua/iptables-exporter/internal/model"
)

type fakeFetcher struct {
	fail  map[Target]bool
	calls map[Target]int
}

func (f *fakeFetcher) Fetch(_ context.Context, t Target) (Fetched, error) {
	f.calls[t]++
	if f.fail[t] {
		return Fetched{}, errors.New("boom")
	}
	return Fetched{Version: "1.8.10", Tables: []model.Table{{Name: "filter"}}}, nil
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestManager(f Fetcher, targets ...Target) (*Manager, *time.Time) {
	clock := time.Unix(1_700_000_000, 0)
	m := NewManager(targets, f, 15*time.Second, discard())
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestSuccessfulTickPublishes(t *testing.T) {
	tg := Target{Family: "ipv4", Backend: "legacy", Binary: "x"}
	m, clock := newTestManager(&fakeFetcher{fail: map[Target]bool{}, calls: map[Target]int{}}, tg)
	if m.Ready() {
		t.Fatal("ready before first tick")
	}
	if got := m.Current(); got == nil || len(got.Results) != 0 {
		t.Fatalf("Current before tick = %+v", got)
	}
	m.tick(context.Background())
	res := m.Current().Results[0]
	if !m.Ready() || !res.Up || len(res.Tables) != 1 || res.Version != "1.8.10" || !res.Taken.Equal(*clock) {
		t.Fatalf("res = %+v", res)
	}
}

func TestFailureOmitsTablesKeepsLastSuccess(t *testing.T) {
	tg := Target{Family: "ipv4", Backend: "legacy", Binary: "x"}
	f := &fakeFetcher{fail: map[Target]bool{}, calls: map[Target]int{}}
	m, clock := newTestManager(f, tg)
	m.tick(context.Background())
	first := *clock

	f.fail[tg] = true
	*clock = clock.Add(20 * time.Second)
	m.tick(context.Background())
	res := m.Current().Results[0]
	if res.Up || res.Tables != nil || !res.Taken.Equal(first) || res.Version != "1.8.10" {
		t.Fatalf("res = %+v", res)
	}
}

func TestBackoffSkipsAttempts(t *testing.T) {
	tg := Target{Family: "ipv4", Backend: "legacy", Binary: "x"}
	f := &fakeFetcher{fail: map[Target]bool{tg: true}, calls: map[Target]int{}}
	m, _ := newTestManager(f, tg)
	// failure n skips backoff ticks: f1 -> 0, f2 -> 1, f3 -> 3, f4 -> 7.
	want := []int{1, 2, 2, 3, 3, 3, 3, 4}
	for i, w := range want {
		m.tick(context.Background())
		if f.calls[tg] != w {
			t.Fatalf("after tick %d calls = %d, want %d", i+1, f.calls[tg], w)
		}
	}
}

func TestCancelledFailureNotRecorded(t *testing.T) {
	tg := Target{Family: "ipv4", Backend: "legacy", Binary: "x"}
	f := &fakeFetcher{fail: map[Target]bool{tg: true}, calls: map[Target]int{}}
	m, _ := newTestManager(f, tg)
	before := m.Current()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.tick(ctx)
	if m.Current() != before || m.Ready() || m.state[tg].failures != 0 {
		t.Fatalf("shutdown tick published or recorded failure")
	}
}

func TestOneTargetFailingDoesNotAffectOthers(t *testing.T) {
	a := Target{Family: "ipv4", Backend: "legacy", Binary: "a"}
	b := Target{Family: "ipv4", Backend: "nft", Binary: "b"}
	m, _ := newTestManager(&fakeFetcher{fail: map[Target]bool{a: true}, calls: map[Target]int{}}, a, b)
	m.tick(context.Background())
	rs := m.Current().Results
	if rs[0].Up || !rs[1].Up {
		t.Fatalf("results = %+v", rs)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	tg := Target{Family: "ipv4", Backend: "legacy", Binary: "x"}
	m := NewManager([]Target{tg}, &fakeFetcher{fail: map[Target]bool{}, calls: map[Target]int{}}, 5*time.Millisecond, discard())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for !m.Ready() {
		select {
		case <-deadline:
			t.Fatal("never became ready")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}
