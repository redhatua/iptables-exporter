package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParse(f *testing.F) {
	files, _ := filepath.Glob("../../testdata/*.save")
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err == nil {
			f.Add(string(b))
		}
	}
	f.Add("*filter\n:INPUT ACCEPT [1:2]\n[1:2] -A INPUT -m comment --comment \"a\\\"b\" -j ACCEPT\nCOMMIT\n")
	f.Fuzz(func(t *testing.T, in string) {
		tables, err := Parse(strings.NewReader(in))
		if err != nil {
			return
		}
		for _, tb := range tables {
			if tb.Name == "" || !utf8.ValidString(tb.Name) {
				t.Fatalf("bad table name %q accepted in %q", tb.Name, in)
			}
			for _, c := range tb.Chains {
				if c.Name == "" || !utf8.ValidString(c.Name) {
					t.Fatalf("bad chain name %q accepted in %q", c.Name, in)
				}
			}
		}
	})
}
