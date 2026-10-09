// Package selector decides which rules get per-rule metric series.
package selector

import (
	"fmt"
	"regexp"

	"github.com/redhatua/iptables-exporter/internal/model"
)

var idConvention = regexp.MustCompile(`iptx:id=([A-Za-z0-9_.:-]{1,64})`)

const maxIDLen = 128

// Selector picks rules by ID comment convention and/or comment regexes.
type Selector struct {
	convention bool
	patterns   []*regexp.Regexp
}

// Rule is a selected rule with its stable ID.
type Rule struct {
	Table, Chain, ID string
	Packets, Bytes   uint64
}

// Result is the outcome of one selection pass.
type Result struct {
	Rules      []Rule
	Duplicates int // rules dropped because their ID was not unique within (table, chain)
}

// New compiles the patterns. The first capture group of a pattern is the ID;
// without a group the whole match is used.
func New(convention bool, patterns []string) (*Selector, error) {
	s := &Selector{convention: convention}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("selector: invalid comment regex %q: %w", p, err)
		}
		s.patterns = append(s.patterns, re)
	}
	return s, nil
}

func (s *Selector) id(r model.Rule) (string, bool) {
	for _, c := range r.Comments {
		if s.convention {
			if m := idConvention.FindStringSubmatch(c); m != nil {
				return m[1], true
			}
		}
		for _, re := range s.patterns {
			m := re.FindStringSubmatch(c)
			if m == nil {
				continue
			}
			id := m[0]
			if len(m) > 1 {
				id = m[1]
			}
			if id != "" && len(id) <= maxIDLen {
				return id, true
			}
		}
	}
	return "", false
}

// Select returns selected rules in table/chain/rule order. IDs must be unique
// within (table, chain); every rule with a repeated ID is dropped and counted.
func (s *Selector) Select(tables []model.Table) Result {
	var res Result
	for _, tb := range tables {
		for _, ch := range tb.Chains {
			type cand struct {
				id string
				r  model.Rule
			}
			var cands []cand
			count := map[string]int{}
			for _, r := range ch.Rules {
				if id, ok := s.id(r); ok {
					cands = append(cands, cand{id, r})
					count[id]++
				}
			}
			for _, c := range cands {
				if count[c.id] > 1 {
					res.Duplicates++
					continue
				}
				res.Rules = append(res.Rules, Rule{
					Table: tb.Name, Chain: ch.Name, ID: c.id,
					Packets: c.r.Packets, Bytes: c.r.Bytes,
				})
			}
		}
	}
	return res
}
