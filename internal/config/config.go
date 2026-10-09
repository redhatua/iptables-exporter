// Package config holds exporter settings; YAML mirrors the command-line flags.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/redhatua/iptables-exporter/internal/snapshot"
)

// DefaultBinaries maps "<family>/<backend>" to the save binary name.
var DefaultBinaries = map[string]string{
	"ipv4/legacy": "iptables-legacy-save",
	"ipv6/legacy": "ip6tables-legacy-save",
	"ipv4/nft":    "iptables-nft-save",
	"ipv6/nft":    "ip6tables-nft-save",
}

// Config is the full exporter configuration.
type Config struct {
	Interval  time.Duration `yaml:"interval"`
	Timeout   time.Duration `yaml:"timeout"`
	MaxOutput int64         `yaml:"max_output_bytes"`
	Families  []string      `yaml:"families"`
	Backends  []string      `yaml:"backends"`
	// Binaries overrides save binaries by "<family>/<backend>" key; only the
	// four keys of DefaultBinaries are valid.
	Binaries     map[string]string `yaml:"binaries"`
	CommentRegex []string          `yaml:"comment_regex"`
	IDConvention bool              `yaml:"id_convention"`
	SeriesLimit  int               `yaml:"series_limit"`
	// UserChainRules enables the iptables_rules gauge of user-defined chains.
	UserChainRules bool `yaml:"user_chain_rules"`
}

// maxOutputLimit bounds max_output_bytes so MaxOutput+1 cannot overflow.
const maxOutputLimit = 1 << 40

// Default returns the default configuration.
func Default() Config {
	bins := make(map[string]string, len(DefaultBinaries))
	for k, v := range DefaultBinaries {
		bins[k] = v
	}
	return Config{
		Interval:     15 * time.Second,
		Timeout:      10 * time.Second,
		MaxOutput:    64 << 20,
		Families:     []string{"ipv4", "ipv6"},
		Backends:     []string{"legacy", "nft"},
		Binaries:     bins,
		IDConvention: true,
		SeriesLimit:  5000,

		UserChainRules: true,
	}
}

// LoadFile overlays a YAML file onto c. Keys absent from the file keep their
// current value; "binaries" is merged key by key; unknown keys are an error.
func (c *Config) LoadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: %s: %w", path, err)
	}
	return nil
}

// Validate checks all fields.
func (c *Config) Validate() error {
	switch {
	case c.Interval < 5*time.Second:
		return errors.New("config: interval must be at least 5s")
	case c.Timeout <= 0:
		return errors.New("config: timeout must be positive")
	case c.MaxOutput <= 0:
		return errors.New("config: max_output_bytes must be positive")
	case c.SeriesLimit < 0:
		return errors.New("config: series_limit must be >= 0")
	case c.MaxOutput > maxOutputLimit:
		return fmt.Errorf("config: max_output_bytes must be at most %d", int64(maxOutputLimit))
	case len(c.Families) == 0 || len(c.Backends) == 0:
		return errors.New("config: at least one family and one backend are required")
	}
	seenF := map[string]bool{}
	for _, f := range c.Families {
		if f != "ipv4" && f != "ipv6" {
			return fmt.Errorf("config: unknown family %q (want ipv4 or ipv6)", f)
		}
		if seenF[f] {
			return fmt.Errorf("config: duplicate family %q", f)
		}
		seenF[f] = true
	}
	seenB := map[string]bool{}
	for _, b := range c.Backends {
		if b != "legacy" && b != "nft" {
			return fmt.Errorf("config: unknown backend %q (want legacy or nft)", b)
		}
		if seenB[b] {
			return fmt.Errorf("config: duplicate backend %q", b)
		}
		seenB[b] = true
	}
	for k := range c.Binaries {
		if _, ok := DefaultBinaries[k]; !ok {
			return fmt.Errorf("config: unknown binaries key %q (want one of ipv4/legacy, ipv6/legacy, ipv4/nft, ipv6/nft)", k)
		}
	}
	for _, p := range c.CommentRegex {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("config: invalid comment regex %q: %w", p, err)
		}
	}
	return nil
}

// Targets resolves the binaries of every enabled (family, backend) pair with
// look (exec.LookPath in production). Unresolvable ones are returned in skipped.
func (c *Config) Targets(look func(string) (string, error)) (targets []snapshot.Target, skipped []string) {
	for _, f := range c.Families {
		for _, b := range c.Backends {
			bin := c.Binaries[f+"/"+b]
			path, err := look(bin)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s/%s: %v", f, b, err))
				continue
			}
			targets = append(targets, snapshot.Target{Family: f, Backend: b, Binary: path})
		}
	}
	return targets, skipped
}
