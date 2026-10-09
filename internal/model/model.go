// Package model holds the in-memory representation of an iptables-save dump.
package model

// Rule is one "-A" line, reduced to what the exporter consumes.
type Rule struct {
	Packets  uint64
	Bytes    uint64
	Target   string
	Comments []string
}

// Chain is a chain declaration plus its rules. Policy is "-" for user-defined chains.
type Chain struct {
	Name    string
	Policy  string
	Packets uint64
	Bytes   uint64
	Rules   []Rule
}

// Builtin reports whether the chain is a built-in chain (has a policy).
func (c *Chain) Builtin() bool { return c.Policy != "-" }

// Table is one "*table ... COMMIT" block. Chains keep declaration order.
type Table struct {
	Name   string
	Chains []*Chain
}
