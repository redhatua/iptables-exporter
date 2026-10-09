package parser

import (
	"errors"
	"strings"
)

var errUnterminatedQuote = errors.New("unterminated quoted string")

// tokenize splits an iptables-save line on spaces/tabs, honouring double
// quotes and backslash escapes inside quotes. Quotes are removed.
func tokenize(line string) ([]string, error) {
	var (
		toks    []string
		cur     strings.Builder
		inTok   bool
		inQuote bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQuote:
			switch c {
			case '\\':
				if i+1 >= len(line) {
					return nil, errUnterminatedQuote
				}
				i++
				cur.WriteByte(line[i])
			case '"':
				inQuote = false
			default:
				cur.WriteByte(c)
			}
		case c == '"':
			inQuote, inTok = true, true
		case c == ' ' || c == '\t':
			if inTok {
				toks = append(toks, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			inTok = true
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, errUnterminatedQuote
	}
	if inTok {
		toks = append(toks, cur.String())
	}
	return toks, nil
}
