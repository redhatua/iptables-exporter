package collector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/redhatua/iptables-exporter/internal/parser"
	"github.com/redhatua/iptables-exporter/internal/selector"
	"github.com/redhatua/iptables-exporter/internal/snapshot"
)

func bigSnapshot(b *testing.B, services, selected int) *snapshot.Snapshot {
	var sb strings.Builder
	sb.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n:KUBE-SERVICES - [0:0]\n")
	for i := 0; i < services; i++ {
		fmt.Fprintf(&sb, ":KUBE-SVC-%08d - [0:0]\n", i)
	}
	for i := 0; i < services; i++ {
		comment := fmt.Sprintf("ns%d/svc%d", i%100, i)
		if i < selected {
			comment = fmt.Sprintf("iptx:id=svc-%d", i)
		}
		fmt.Fprintf(&sb, "[%d:%d] -A KUBE-SERVICES -m comment --comment \"%s\" -j KUBE-SVC-%08d\n", i, i*60, comment, i)
	}
	sb.WriteString("COMMIT\n")
	tables, err := parser.Parse(strings.NewReader(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	return &snapshot.Snapshot{Results: []snapshot.Result{{
		Target: snapshot.Target{Family: "ipv4", Backend: "legacy"}, Up: true,
		Tables: tables, Version: "1.8.10", Taken: time.Unix(1, 0),
	}}}
}

func benchCollect(b *testing.B, services, selected, limit int) {
	sel, _ := selector.New(true, nil)
	c := New(fakeSrc{bigSnapshot(b, services, selected)}, sel, limit)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := make(chan prometheus.Metric, 1024)
		done := make(chan struct{})
		var count int
		var sawRule bool
		go func() {
			for m := range ch {
				count++
				if !sawRule && strings.Contains(m.Desc().String(), "iptables_rule_packets_total") {
					sawRule = true
				}
			}
			close(done)
		}()
		c.Collect(ch)
		close(ch)
		<-done
		if count == 0 {
			b.Fatal("collector emitted no metrics")
		}
		if limit > 0 && selected > 0 && !sawRule {
			b.Fatal("no iptables_rule_packets_total emitted under limit")
		}
	}
}

func BenchmarkCollect100kRulesLimit5000(b *testing.B) { benchCollect(b, 100_000, 1000, 5000) }
func BenchmarkCollect100kRulesUnlimited(b *testing.B) { benchCollect(b, 100_000, 1000, 0) }
