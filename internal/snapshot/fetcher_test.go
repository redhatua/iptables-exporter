package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redhatua/iptables-exporter/internal/parser"
	"github.com/redhatua/iptables-exporter/internal/runner"
)

func newFetcher() *ExecFetcher {
	return &ExecFetcher{Runner: runner.Runner{Timeout: 5 * time.Second, MaxOutput: 1 << 20}}
}

func TestExecFetcherSuccess(t *testing.T) {
	bin, _ := filepath.Abs("../../testdata/fake-save.sh")
	got, err := newFetcher().Fetch(context.Background(), Target{Family: "ipv4", Backend: "legacy", Binary: bin})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tables) != 2 || got.Version != "1.8.10" {
		t.Fatalf("got = %+v", got)
	}
}

func TestExecFetcherRejectsTruncatedDump(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile("../../testdata/truncated.save")
	os.WriteFile(filepath.Join(dir, "dump"), src, 0o644)
	bin := filepath.Join(dir, "save")
	os.WriteFile(bin, []byte("#!/bin/sh\ncat \""+filepath.Join(dir, "dump")+"\"\n"), 0o755)
	_, err := newFetcher().Fetch(context.Background(), Target{Binary: bin})
	if !errors.Is(err, parser.ErrTruncated) {
		t.Fatalf("err = %v", err)
	}
}

func TestExecFetcherCommandFailure(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "save")
	os.WriteFile(bin, []byte("#!/bin/sh\necho denied >&2\nexit 1\n"), 0o755)
	if _, err := newFetcher().Fetch(context.Background(), Target{Binary: bin}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecFetcherVersionNotCachedOnProbeFailure(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile("../../testdata/docker.save")
	os.WriteFile(filepath.Join(dir, "dump"), src, 0o644)
	counter := filepath.Join(dir, "n")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  if [ ! -e " + counter + " ]; then touch " + counter + "; exit 1; fi\n  echo \"iptables-save v1.8.10 (legacy)\"; exit 0\nfi\ncat " + filepath.Join(dir, "dump") + "\n"
	bin := filepath.Join(dir, "save")
	os.WriteFile(bin, []byte(script), 0o755)
	f := newFetcher()
	tg := Target{Binary: bin}
	got, err := f.Fetch(context.Background(), tg)
	if err != nil || got.Version != "unknown" {
		t.Fatalf("first: %+v %v", got, err)
	}
	got, err = f.Fetch(context.Background(), tg)
	if err != nil || got.Version != "1.8.10" {
		t.Fatalf("second: %+v %v", got, err)
	}
}
