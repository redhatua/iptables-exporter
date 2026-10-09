// Package collector exposes snapshots as Prometheus metrics.
package collector

import (
	"math"
	"runtime"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/redhatua/iptables-exporter/internal/buildinfo"
	"github.com/redhatua/iptables-exporter/internal/selector"
	"github.com/redhatua/iptables-exporter/internal/snapshot"
)

// Source provides the latest snapshot.
type Source interface {
	Current() *snapshot.Snapshot
}

const ns = "iptables"

var (
	targetLabels = []string{"family", "backend"}
	chainLabels  = []string{"family", "backend", "table", "chain"}
	ruleLabels   = []string{"family", "backend", "table", "chain", "rule_id"}

	descPolicyPackets = prometheus.NewDesc(ns+"_chain_policy_packets_total", "Packets that reached the policy of a built-in chain.", chainLabels, nil)
	descPolicyBytes   = prometheus.NewDesc(ns+"_chain_policy_bytes_total", "Bytes that reached the policy of a built-in chain.", chainLabels, nil)
	descPolicyInfo    = prometheus.NewDesc(ns+"_chain_policy_info", "Policy of a built-in chain (value is always 1).", append(append([]string{}, chainLabels...), "policy"), nil)
	descRules         = prometheus.NewDesc(ns+"_rules", "Current number of rules in a chain.", chainLabels, nil)
	descRulePackets   = prometheus.NewDesc(ns+"_rule_packets_total", "Packets matched by a selected rule.", ruleLabels, nil)
	descRuleBytes     = prometheus.NewDesc(ns+"_rule_bytes_total", "Bytes matched by a selected rule.", ruleLabels, nil)
	descBackendInfo   = prometheus.NewDesc(ns+"_backend_info", "Backend and userspace version used for a target (value is always 1).", append(append([]string{}, targetLabels...), "version"), nil)
	descUp            = prometheus.NewDesc(ns+"_up", "1 if the last collection of the target succeeded.", targetLabels, nil)
	descTimestamp     = prometheus.NewDesc(ns+"_snapshot_timestamp_seconds", "Unix time of the last successful collection.", targetLabels, nil)
	descDuration      = prometheus.NewDesc(ns+"_scrape_duration_seconds", "Duration of the last collection attempt.", targetLabels, nil)
	descOmitted       = prometheus.NewDesc(ns+"_series_omitted", "Series omitted from this scrape because of the series limit.", nil, nil)
	descDuplicates    = prometheus.NewDesc(ns+"_duplicate_rule_ids", "Rules dropped because their rule ID is not unique within a chain.", targetLabels, nil)
	descBuildInfo     = prometheus.NewDesc(ns+"_build_info", "Build information (value is always 1).", []string{"version", "revision", "goversion"}, nil)

	allDescs = []*prometheus.Desc{
		descPolicyPackets, descPolicyBytes, descPolicyInfo, descRules, descRulePackets, descRuleBytes,
		descBackendInfo, descUp, descTimestamp, descDuration, descOmitted, descDuplicates, descBuildInfo,
	}
)

// Collector implements prometheus.Collector over a snapshot Source.
type Collector struct {
	src   Source
	sel   *selector.Selector
	limit int
}

// New returns a collector. limit caps non-health series per scrape; 0 means unlimited.
func New(src Source, sel *selector.Selector, limit int) *Collector {
	return &Collector{src: src, sel: sel, limit: limit}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range allDescs {
		ch <- d
	}
}

// group is an indivisible set of series (for example the packets+bytes pair of
// one rule) ordered by priority then key, so truncation is deterministic.
type group struct {
	prio int // 1 = built-in chains, 2 = selected rules, 3 = user-defined chains
	key  string
	ms   []prometheus.Metric
}

// Collect implements prometheus.Collector. Health metrics are reserved: they
// are always emitted and do not count against the series limit.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap := c.src.Current()
	ch <- prometheus.MustNewConstMetric(descBuildInfo, prometheus.GaugeValue, 1,
		buildinfo.Version, buildinfo.Revision, runtime.Version())

	var groups []group
	for _, r := range snap.Results {
		fam, be := r.Target.Family, r.Target.Backend
		up := 0.0
		if r.Up {
			up = 1
		}
		ch <- prometheus.MustNewConstMetric(descUp, prometheus.GaugeValue, up, fam, be)
		ch <- prometheus.MustNewConstMetric(descDuration, prometheus.GaugeValue, r.Duration.Seconds(), fam, be)
		if !r.Taken.IsZero() {
			ch <- prometheus.MustNewConstMetric(descTimestamp, prometheus.GaugeValue, float64(r.Taken.Unix()), fam, be)
			ch <- prometheus.MustNewConstMetric(descBackendInfo, prometheus.GaugeValue, 1, fam, be, r.Version)
		}
		if !r.Up {
			continue
		}

		for _, tb := range r.Tables {
			for _, chn := range tb.Chains {
				prio := 3
				ms := []prometheus.Metric{
					prometheus.MustNewConstMetric(descRules, prometheus.GaugeValue, float64(len(chn.Rules)), fam, be, tb.Name, chn.Name),
				}
				if chn.Builtin() {
					prio = 1
					ms = append(ms,
						prometheus.MustNewConstMetric(descPolicyPackets, prometheus.CounterValue, float64(chn.Packets), fam, be, tb.Name, chn.Name),
						prometheus.MustNewConstMetric(descPolicyBytes, prometheus.CounterValue, float64(chn.Bytes), fam, be, tb.Name, chn.Name),
						prometheus.MustNewConstMetric(descPolicyInfo, prometheus.GaugeValue, 1, fam, be, tb.Name, chn.Name, chn.Policy),
					)
				}
				groups = append(groups, group{prio, key(fam, be, tb.Name, chn.Name), ms})
			}
		}

		res := c.sel.Select(r.Tables)
		ch <- prometheus.MustNewConstMetric(descDuplicates, prometheus.GaugeValue, float64(res.Duplicates), fam, be)
		for _, sr := range res.Rules {
			groups = append(groups, group{2, key(fam, be, sr.Table, sr.Chain, sr.ID), []prometheus.Metric{
				prometheus.MustNewConstMetric(descRulePackets, prometheus.CounterValue, float64(sr.Packets), fam, be, sr.Table, sr.Chain, sr.ID),
				prometheus.MustNewConstMetric(descRuleBytes, prometheus.CounterValue, float64(sr.Bytes), fam, be, sr.Table, sr.Chain, sr.ID),
			}})
		}
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].prio != groups[j].prio {
			return groups[i].prio < groups[j].prio
		}
		return groups[i].key < groups[j].key
	})

	remaining := math.MaxInt
	if c.limit > 0 {
		remaining = c.limit
	}
	omitted := 0
	for i, g := range groups {
		if len(g.ms) > remaining {
			for _, rest := range groups[i:] {
				omitted += len(rest.ms)
			}
			break
		}
		remaining -= len(g.ms)
		for _, m := range g.ms {
			ch <- m
		}
	}
	ch <- prometheus.MustNewConstMetric(descOmitted, prometheus.GaugeValue, float64(omitted))
}

func key(parts ...string) string { return strings.Join(parts, "\x00") }
