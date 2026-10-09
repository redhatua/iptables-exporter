package collector

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/redhatua/iptables-exporter/internal/parser"
	"github.com/redhatua/iptables-exporter/internal/selector"
	"github.com/redhatua/iptables-exporter/internal/snapshot"
)

type fakeSrc struct{ s *snapshot.Snapshot }

func (f fakeSrc) Current() *snapshot.Snapshot { return f.s }

func snapOf(t *testing.T, up bool, text string) *snapshot.Snapshot {
	t.Helper()
	tables, err := parser.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	r := snapshot.Result{
		Target:   snapshot.Target{Family: "ipv4", Backend: "legacy", Binary: "x"},
		Up:       up,
		Duration: 250 * time.Millisecond,
	}
	if up {
		r.Tables, r.Version, r.Taken = tables, "1.8.10", time.Unix(1_700_000_000, 0)
	}
	return &snapshot.Snapshot{Results: []snapshot.Result{r}}
}

func dockerText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/docker.save")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gather(t *testing.T, c prometheus.Collector) map[string][]*dto.Metric {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]*dto.Metric{}
	for _, mf := range mfs {
		out[mf.GetName()] = mf.GetMetric()
	}
	return out
}

func value(m *dto.Metric) float64 {
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	}
	return -1
}

// find returns the value of the first metric in family whose labels include want.
func find(t *testing.T, got map[string][]*dto.Metric, name string, want map[string]string) (float64, bool) {
	t.Helper()
	for _, m := range got[name] {
		have := map[string]string{}
		for _, lp := range m.Label {
			have[lp.GetName()] = lp.GetValue()
		}
		ok := true
		for k, v := range want {
			if have[k] != v {
				ok = false
				break
			}
		}
		if ok {
			return value(m), true
		}
	}
	return 0, false
}

func newCollector(t *testing.T, s *snapshot.Snapshot, limit int) *Collector {
	t.Helper()
	return newCollectorOpts(t, s, limit, true)
}

func newCollectorOpts(t *testing.T, s *snapshot.Snapshot, limit int, userChainRules bool) *Collector {
	t.Helper()
	sel, err := selector.New(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(fakeSrc{s}, sel, limit, userChainRules)
}

func TestPolicyAndHealthMetrics(t *testing.T) {
	got := gather(t, newCollector(t, snapOf(t, true, dockerText(t)), 5000))
	base := map[string]string{"family": "ipv4", "backend": "legacy", "table": "filter"}
	with := func(k, v string) map[string]string {
		m := map[string]string{k: v}
		for bk, bv := range base {
			m[bk] = bv
		}
		return m
	}

	if v, ok := find(t, got, "iptables_chain_policy_packets_total", with("chain", "FORWARD")); !ok || v != 5 {
		t.Errorf("FORWARD policy packets = %v ok=%v", v, ok)
	}
	if v, ok := find(t, got, "iptables_chain_policy_bytes_total", with("chain", "FORWARD")); !ok || v != 420 {
		t.Errorf("FORWARD policy bytes = %v ok=%v", v, ok)
	}
	if _, ok := find(t, got, "iptables_chain_policy_packets_total", with("chain", "DOCKER")); ok {
		t.Error("user chain must not have policy counters")
	}
	if v, ok := find(t, got, "iptables_chain_policy_info", with("chain", "FORWARD")); !ok || v != 1 {
		t.Errorf("policy info = %v ok=%v", v, ok)
	}
	if m := got["iptables_chain_policy_info"]; len(m) == 0 {
		t.Error("no policy info")
	}
	if v, ok := find(t, got, "iptables_rules", with("chain", "INPUT")); !ok || v != 2 {
		t.Errorf("INPUT rules = %v ok=%v", v, ok)
	}
	if v, ok := find(t, got, "iptables_rules", with("chain", "DOCKER")); !ok || v != 0 {
		t.Errorf("DOCKER rules = %v ok=%v", v, ok)
	}
	id := map[string]string{"family": "ipv4", "backend": "legacy"}
	if v, ok := find(t, got, "iptables_up", id); !ok || v != 1 {
		t.Errorf("up = %v ok=%v", v, ok)
	}
	if v, ok := find(t, got, "iptables_snapshot_timestamp_seconds", id); !ok || v != 1_700_000_000 {
		t.Errorf("timestamp = %v ok=%v", v, ok)
	}
	if v, ok := find(t, got, "iptables_scrape_duration_seconds", id); !ok || v != 0.25 {
		t.Errorf("duration = %v ok=%v", v, ok)
	}
	if _, ok := find(t, got, "iptables_backend_info", map[string]string{"family": "ipv4", "backend": "legacy", "version": "1.8.10"}); !ok {
		t.Error("backend_info missing")
	}
	if v, ok := find(t, got, "iptables_series_omitted", nil); !ok || v != 0 {
		t.Errorf("series_omitted = %v ok=%v", v, ok)
	}
	if v, ok := find(t, got, "iptables_duplicate_rule_ids", id); !ok || v != 0 {
		t.Errorf("duplicates = %v ok=%v", v, ok)
	}
	if _, ok := find(t, got, "iptables_build_info", nil); !ok {
		t.Error("build_info missing")
	}
}

func TestOnlySelectedRulesGetSeries(t *testing.T) {
	got := gather(t, newCollector(t, snapOf(t, true, dockerText(t)), 5000))
	if n := len(got["iptables_rule_packets_total"]); n != 1 {
		t.Fatalf("rule series = %d, want 1", n)
	}
	want := map[string]string{"rule_id": "ssh-in", "chain": "INPUT", "table": "filter", "family": "ipv4", "backend": "legacy"}
	if v, ok := find(t, got, "iptables_rule_packets_total", want); !ok || v != 40 {
		t.Errorf("rule packets = %v ok=%v", v, ok)
	}
	if v, ok := find(t, got, "iptables_rule_bytes_total", want); !ok || v != 3200 {
		t.Errorf("rule bytes = %v ok=%v", v, ok)
	}
}

func TestDownTargetOmitsCounters(t *testing.T) {
	got := gather(t, newCollector(t, snapOf(t, false, ""), 5000))
	id := map[string]string{"family": "ipv4", "backend": "legacy"}
	if v, ok := find(t, got, "iptables_up", id); !ok || v != 0 {
		t.Errorf("up = %v ok=%v", v, ok)
	}
	for _, name := range []string{"iptables_rules", "iptables_chain_policy_packets_total", "iptables_snapshot_timestamp_seconds", "iptables_backend_info"} {
		if len(got[name]) != 0 {
			t.Errorf("%s must be absent for a down target that never succeeded", name)
		}
	}
}

func TestSeriesBudgetOmitsRulesFirstAndDeterministically(t *testing.T) {
	// docker.save: prio 1 = 5 built-in chains x 4 series = 20; prio 2 = ssh-in
	// pair = 2; prio 3 = DOCKER and DOCKER-USER rules gauges = 1 each (24 total).
	cases := []struct {
		limit       int
		wantRules   bool
		wantDocker  bool
		wantDUser   bool
		wantOmitted float64
	}{
		{24, true, true, true, 0},
		{23, true, true, false, 1},
		{22, true, false, false, 2},
		{21, false, false, false, 4}, // the rule pair does not fit and stops everything after it
		{20, false, false, false, 4},
		{0, true, true, true, 0}, // 0 = unlimited
	}
	for _, tc := range cases {
		got := gather(t, newCollector(t, snapOf(t, true, dockerText(t)), tc.limit))
		if has := len(got["iptables_rule_packets_total"]) > 0; has != tc.wantRules {
			t.Errorf("limit=%d rules present=%v want %v", tc.limit, has, tc.wantRules)
		}
		_, hasD := find(t, got, "iptables_rules", map[string]string{"chain": "DOCKER"})
		_, hasU := find(t, got, "iptables_rules", map[string]string{"chain": "DOCKER-USER"})
		if hasD != tc.wantDocker || hasU != tc.wantDUser {
			t.Errorf("limit=%d DOCKER=%v DOCKER-USER=%v want %v %v", tc.limit, hasD, hasU, tc.wantDocker, tc.wantDUser)
		}
		if _, ok := find(t, got, "iptables_rules", map[string]string{"chain": "INPUT"}); !ok {
			t.Errorf("limit=%d built-in chains must be kept", tc.limit)
		}
		if v, _ := find(t, got, "iptables_series_omitted", nil); v != tc.wantOmitted {
			t.Errorf("limit=%d omitted=%v want %v", tc.limit, v, tc.wantOmitted)
		}
		if len(got["iptables_up"]) == 0 {
			t.Errorf("limit=%d health metrics must always be present", tc.limit)
		}
	}
}

func TestSelectedRulesSurviveManyUserChains(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, ":USER-%03d - [0:0]\n", i)
	}
	sb.WriteString("[1:10] -A INPUT -m comment --comment \"iptx:id=a\" -j ACCEPT\n")
	sb.WriteString("[2:20] -A INPUT -p tcp -m comment --comment \"iptx:id=b\" -j DROP\n")
	sb.WriteString("COMMIT\n")
	got := gather(t, newCollector(t, snapOf(t, true, sb.String()), 50))
	if n := len(got["iptables_rule_packets_total"]); n != 2 {
		t.Fatalf("rule series = %d, want 2", n)
	}
	// 3 built-in x 4 = 12, rules 4, leaving 34 of 200 user-chain gauges.
	if n := len(got["iptables_rules"]); n != 3+34 {
		t.Errorf("rules gauges = %d, want 37", n)
	}
	if v, _ := find(t, got, "iptables_series_omitted", nil); v != 166 {
		t.Errorf("omitted = %v, want 166", v)
	}
}

func TestDownTargetWithStaleTablesEmitsNoCounters(t *testing.T) {
	s := snapOf(t, true, dockerText(t))
	s.Results[0].Up = false
	got := gather(t, newCollector(t, s, 5000))
	id := map[string]string{"family": "ipv4", "backend": "legacy"}
	if v, ok := find(t, got, "iptables_up", id); !ok || v != 0 {
		t.Errorf("up = %v ok=%v", v, ok)
	}
	for _, name := range []string{"iptables_snapshot_timestamp_seconds", "iptables_backend_info"} {
		if len(got[name]) != 1 {
			t.Errorf("%s must be present", name)
		}
	}
	for _, name := range []string{"iptables_rules", "iptables_chain_policy_packets_total", "iptables_chain_policy_bytes_total", "iptables_chain_policy_info", "iptables_rule_packets_total", "iptables_rule_bytes_total"} {
		if len(got[name]) != 0 {
			t.Errorf("%s must be absent for a down target", name)
		}
	}
}

func TestDuplicateRuleIDsReported(t *testing.T) {
	text := "*filter\n:INPUT ACCEPT [0:0]\n" +
		"[1:1] -A INPUT -m comment --comment \"iptx:id=dup\" -j ACCEPT\n" +
		"[2:2] -A INPUT -p tcp -m comment --comment \"iptx:id=dup\" -j DROP\nCOMMIT\n"
	got := gather(t, newCollector(t, snapOf(t, true, text), 5000))
	if v, ok := find(t, got, "iptables_duplicate_rule_ids", map[string]string{"family": "ipv4", "backend": "legacy"}); !ok || v != 2 {
		t.Errorf("duplicates = %v ok=%v", v, ok)
	}
	if len(got["iptables_rule_packets_total"]) != 0 {
		t.Error("duplicate IDs must not produce series")
	}
}

func TestUserChainRulesDisabled(t *testing.T) {
	// docker.save: 5 built-in chains (20 series) + ssh-in pair; DOCKER and
	// DOCKER-USER are user chains. Limit 22 would omit nothing without them.
	got := gather(t, newCollectorOpts(t, snapOf(t, true, dockerText(t)), 22, false))
	for _, ch := range []string{"DOCKER", "DOCKER-USER"} {
		if _, ok := find(t, got, "iptables_rules", map[string]string{"chain": ch}); ok {
			t.Errorf("user chain %s must have no iptables_rules series", ch)
		}
	}
	if _, ok := find(t, got, "iptables_rules", map[string]string{"chain": "INPUT"}); !ok {
		t.Error("built-in chain gauge must remain")
	}
	if n := len(got["iptables_rule_packets_total"]); n != 1 {
		t.Errorf("selected rule series = %d, want 1", n)
	}
	if v, _ := find(t, got, "iptables_series_omitted", nil); v != 0 {
		t.Errorf("omitted = %v, want 0 (user chains are not counted as omitted)", v)
	}
}
