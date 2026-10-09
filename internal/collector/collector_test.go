package collector

import (
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
	sel, err := selector.New(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(fakeSrc{s}, sel, limit)
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
	// docker.save yields 22 policy/inventory series and 2 selected-rule series.
	cases := []struct {
		limit       int
		wantRules   bool
		wantOmitted float64
	}{
		{24, true, 0},
		{23, false, 2}, // a rule pair that does not fit is omitted whole
		{22, false, 2},
		{0, true, 0}, // 0 = unlimited
	}
	for _, tc := range cases {
		got := gather(t, newCollector(t, snapOf(t, true, dockerText(t)), tc.limit))
		if has := len(got["iptables_rule_packets_total"]) > 0; has != tc.wantRules {
			t.Errorf("limit=%d rules present=%v want %v", tc.limit, has, tc.wantRules)
		}
		if v, _ := find(t, got, "iptables_series_omitted", nil); v != tc.wantOmitted {
			t.Errorf("limit=%d omitted=%v want %v", tc.limit, v, tc.wantOmitted)
		}
		if len(got["iptables_up"]) == 0 {
			t.Errorf("limit=%d health metrics must always be present", tc.limit)
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
