package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			for _, c := range tb.Chains {
				if c.Name == "" {
					t.Fatalf("empty chain name accepted in %q", in)
				}
			}
		}
	})
}
