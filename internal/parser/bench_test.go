package parser

import (
	"fmt"
	"strings"
	"testing"
)

// genRules builds a kube-proxy shaped nat table with n service rules.
func genRules(n int) string {
	var b strings.Builder
	b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n:KUBE-SERVICES - [0:0]\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, ":KUBE-SVC-%08d - [0:0]\n", i)
	}
	b.WriteString("[7:420] -A PREROUTING -m comment --comment \"kubernetes service portals\" -j KUBE-SERVICES\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "[%d:%d] -A KUBE-SERVICES -d 10.%d.%d.%d/32 -p tcp -m comment --comment \"ns%d/svc%d:http cluster IP\" -m tcp --dport 80 -j KUBE-SVC-%08d\n",
			i, i*60, (i>>16)&255, (i>>8)&255, i&255, i%100, i, i)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func benchParse(b *testing.B, n int) {
	in := genRules(n)
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(strings.NewReader(in)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParse10k(b *testing.B)  { benchParse(b, 10_000) }
func BenchmarkParse100k(b *testing.B) { benchParse(b, 100_000) }
