// Package parser parses `iptables-save -c` output into the model.
package parser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/redhatua/iptables-exporter/internal/model"
)

// MaxLineBytes bounds a single input line.
const MaxLineBytes = 1 << 20

// ErrTruncated is returned when a table is not terminated by COMMIT.
var ErrTruncated = errors.New("parser: table not terminated by COMMIT")

// ParseError reports a malformed line.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("parser: line %d: %s", e.Line, e.Msg) }

// Parse reads a complete iptables-save dump. An input without any table is valid
// (empty ruleset). Tables are only returned if every table was COMMITted.
func Parse(r io.Reader) ([]model.Table, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)

	var (
		tables []model.Table
		cur    *model.Table
		byName map[string]*model.Chain
		n      int
	)
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#':
			continue
		case line[0] == '*':
			if cur != nil {
				return nil, &ParseError{n, "table started before COMMIT"}
			}
			if line[1:] == "" {
				return nil, &ParseError{n, "empty table name"}
			}
			cur = &model.Table{Name: line[1:]}
			byName = map[string]*model.Chain{}
		case line == "COMMIT":
			if cur == nil {
				return nil, &ParseError{n, "COMMIT outside table"}
			}
			tables = append(tables, *cur)
			cur, byName = nil, nil
		default:
			if cur == nil {
				return nil, &ParseError{n, "statement outside table"}
			}
			if err := parseStatement(line, n, cur, byName); err != nil {
				return nil, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parser: read: %w", err)
	}
	if cur != nil {
		return nil, ErrTruncated
	}
	return tables, nil
}

func parseStatement(line string, n int, tb *model.Table, byName map[string]*model.Chain) error {
	if line[0] == ':' {
		return parseChain(line, n, tb, byName)
	}
	toks, err := tokenize(line)
	if err != nil {
		return &ParseError{n, err.Error()}
	}
	var pkts, bytes uint64
	if len(toks) > 0 && strings.HasPrefix(toks[0], "[") {
		pkts, bytes, err = parseCounters(toks[0])
		if err != nil {
			return &ParseError{n, err.Error()}
		}
		toks = toks[1:]
	}
	if len(toks) < 2 || toks[0] != "-A" {
		return &ParseError{n, "expected rule starting with -A <chain>"}
	}
	ch, ok := byName[toks[1]]
	if !ok {
		return &ParseError{n, fmt.Sprintf("rule references undeclared chain %q", toks[1])}
	}
	rest := toks[2:]
	rule := model.Rule{Packets: pkts, Bytes: bytes, Tokens: rest}
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-j", "-g":
			if i+1 < len(rest) && rule.Target == "" {
				rule.Target = rest[i+1]
			}
			i++
		case "--comment":
			if i+1 < len(rest) {
				rule.Comments = append(rule.Comments, rest[i+1])
			}
			i++
		}
	}
	ch.Rules = append(ch.Rules, rule)
	return nil
}

func parseChain(line string, n int, tb *model.Table, byName map[string]*model.Chain) error {
	f := strings.Fields(line)
	if len(f) < 2 {
		return &ParseError{n, "chain declaration needs a name and a policy"}
	}
	name := f[0][1:]
	if name == "" {
		return &ParseError{n, "empty chain name"}
	}
	if _, dup := byName[name]; dup {
		return &ParseError{n, fmt.Sprintf("duplicate chain %q", name)}
	}
	c := &model.Chain{Name: name, Policy: f[1]}
	if len(f) >= 3 {
		var err error
		c.Packets, c.Bytes, err = parseCounters(f[2])
		if err != nil {
			return &ParseError{n, err.Error()}
		}
	}
	tb.Chains = append(tb.Chains, c)
	byName[c.Name] = c
	return nil
}

// parseCounters parses "[pkts:bytes]".
func parseCounters(s string) (uint64, uint64, error) {
	if len(s) < 5 || s[0] != '[' || s[len(s)-1] != ']' {
		return 0, 0, fmt.Errorf("malformed counters %q", s)
	}
	a, b, ok := strings.Cut(s[1:len(s)-1], ":")
	if !ok {
		return 0, 0, fmt.Errorf("malformed counters %q", s)
	}
	p, err := strconv.ParseUint(a, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("bad packet counter in %q", s)
	}
	by, err := strconv.ParseUint(b, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("bad byte counter in %q", s)
	}
	return p, by, nil
}
