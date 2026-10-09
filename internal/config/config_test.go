package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Interval != 15*time.Second || c.SeriesLimit != 5000 || !c.IDConvention {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestValidateRejects(t *testing.T) {
	mut := map[string]func(*Config){
		"interval too small": func(c *Config) { c.Interval = time.Second },
		"zero timeout":       func(c *Config) { c.Timeout = 0 },
		"bad family":         func(c *Config) { c.Families = []string{"ipv5"} },
		"bad backend":        func(c *Config) { c.Backends = []string{"ebtables"} },
		"bad regex":          func(c *Config) { c.CommentRegex = []string{"("} },
		"negative limit":     func(c *Config) { c.SeriesLimit = -1 },
		"zero max output":    func(c *Config) { c.MaxOutput = 0 },
		"no families":        func(c *Config) { c.Families = nil },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			c := Default()
			f(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadFileOverridesAndMergesBinaries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte("interval: 30s\nseries_limit: 10\ncomment_regex: ['^svc/(\\w+)$']\nbinaries:\n  ipv4/legacy: /opt/iptables-legacy-save\n"), 0o644)
	c := Default()
	if err := c.LoadFile(p); err != nil {
		t.Fatal(err)
	}
	if c.Interval != 30*time.Second || c.SeriesLimit != 10 || len(c.CommentRegex) != 1 {
		t.Fatalf("cfg = %+v", c)
	}
	if c.Binaries["ipv4/legacy"] != "/opt/iptables-legacy-save" || c.Binaries["ipv6/nft"] != "ip6tables-nft-save" {
		t.Fatalf("binaries = %v", c.Binaries)
	}
	if !c.IDConvention || c.Timeout != 10*time.Second {
		t.Fatal("unset keys must keep their defaults")
	}
}

func TestLoadFileRejectsUnknownKeysAndAcceptsEmpty(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("intervall: 5s\n"), 0o644)
	c := Default()
	if err := c.LoadFile(bad); err == nil {
		t.Fatal("expected unknown-key error")
	}
	empty := filepath.Join(dir, "empty.yaml")
	os.WriteFile(empty, nil, 0o644)
	if err := c.LoadFile(empty); err != nil {
		t.Fatalf("empty file: %v", err)
	}
}

func TestTargetsSkipMissingBinaries(t *testing.T) {
	c := Default()
	look := func(name string) (string, error) {
		if strings.Contains(name, "ip6tables") {
			return "", errors.New("not found")
		}
		return "/usr/sbin/" + name, nil
	}
	targets, skipped := c.Targets(look)
	if len(targets) != 2 || len(skipped) != 2 {
		t.Fatalf("targets=%v skipped=%v", targets, skipped)
	}
	if targets[0].Family != "ipv4" || targets[0].Backend != "legacy" || targets[0].Binary != "/usr/sbin/iptables-legacy-save" {
		t.Fatalf("targets[0] = %+v", targets[0])
	}
	if targets[1].Backend != "nft" {
		t.Fatalf("targets[1] = %+v", targets[1])
	}
}
