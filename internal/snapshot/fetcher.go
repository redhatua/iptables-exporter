package snapshot

import (
	"bytes"
	"context"
	"regexp"

	"github.com/redhatua/iptables-exporter/internal/model"
	"github.com/redhatua/iptables-exporter/internal/parser"
	"github.com/redhatua/iptables-exporter/internal/runner"
)

// Target is one (family, backend) save binary.
type Target struct {
	Family  string // ipv4 | ipv6
	Backend string // legacy | nft
	Binary  string // resolved path of the *-save binary
}

// Fetched is the parsed output of one successful collection.
type Fetched struct {
	Version string
	Tables  []model.Table
}

// Fetcher collects one target.
type Fetcher interface {
	Fetch(ctx context.Context, t Target) (Fetched, error)
}

// ExecFetcher runs `<binary> -c` and parses the result. It is used from a
// single goroutine (the manager loop), so the version cache needs no lock.
type ExecFetcher struct {
	Runner   runner.Runner
	versions map[Target]string
}

var versionRe = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

// Fetch implements Fetcher. A dump that does not parse completely is an error.
func (f *ExecFetcher) Fetch(ctx context.Context, t Target) (Fetched, error) {
	out, err := f.Runner.Run(ctx, t.Binary, "-c")
	if err != nil {
		return Fetched{}, err
	}
	tables, err := parser.Parse(bytes.NewReader(out))
	if err != nil {
		return Fetched{}, err
	}
	return Fetched{Version: f.version(ctx, t), Tables: tables}, nil
}

func (f *ExecFetcher) version(ctx context.Context, t Target) string {
	if v, ok := f.versions[t]; ok {
		return v
	}
	out, err := f.Runner.Run(ctx, t.Binary, "--version")
	if err != nil {
		return "unknown"
	}
	m := versionRe.FindSubmatch(out)
	if m == nil {
		return "unknown"
	}
	v := string(m[1])
	if f.versions == nil {
		f.versions = map[Target]string{}
	}
	f.versions[t] = v
	return v
}
