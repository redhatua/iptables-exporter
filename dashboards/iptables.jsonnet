local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';

local ds = { type: 'prometheus', uid: '${datasource}' };
local sel = 'job=~"$job", instance=~"$instance"';

local q(expr, legend='') =
  g.query.prometheus.new('$datasource', expr)
  + g.query.prometheus.withLegendFormat(legend);

local ts(title, expr, legend, unit, desc='') =
  g.panel.timeSeries.new(title)
  + g.panel.timeSeries.queryOptions.withDatasource(ds.type, ds.uid)
  + g.panel.timeSeries.queryOptions.withTargets([q(expr, legend)])
  + g.panel.timeSeries.standardOptions.withUnit(unit)
  + g.panel.timeSeries.panelOptions.withDescription(if desc == '' then title else desc);

local stat(title, expr, unit='short', desc='') =
  g.panel.stat.new(title)
  + g.panel.stat.queryOptions.withDatasource(ds.type, ds.uid)
  + g.panel.stat.queryOptions.withTargets([q(expr)])
  + g.panel.stat.standardOptions.withUnit(unit)
  + g.panel.stat.panelOptions.withDescription(if desc == '' then title else desc);

local tbl(title, expr, desc='') =
  g.panel.table.new(title)
  + g.panel.table.queryOptions.withDatasource(ds.type, ds.uid)
  + g.panel.table.queryOptions.withTargets([
    q(expr) + g.query.prometheus.withInstant(true) + g.query.prometheus.withFormat('table'),
  ])
  + g.panel.table.standardOptions.withUnit('short')
  + g.panel.table.panelOptions.withDescription(if desc == '' then title else desc);

local coverage =
  g.panel.text.new('Coverage and semantics')
  + g.panel.text.options.withMode('markdown')
  + g.panel.text.options.withContent(|||
    **What these panels can and cannot tell you.**
    Policy counters count packets that fell through to the policy of a built-in chain.
    Per-rule series exist only for rules you selected (comment `iptx:id=<name>` or `--select.comment-regex`),
    so this dashboard does not show complete accept/drop totals. An ACCEPT at one hook is not final delivery.
    NAT counters count connection-establishing packets, not connection throughput.
    Counters reset on `iptables-restore`, flush or rule re-creation; `rate()` handles resets.
    Exporter health: when a target is down its counters are omitted (gaps), not frozen.
  |||);

local panels = [
  g.panel.row.new('Overview and coverage') + g.panel.row.withPanels([
    coverage,
    stat('Targets up', 'sum(iptables_up{%s})' % sel, 'short', 'Count of (family, backend) targets whose last collection succeeded.'),
    stat('Targets down', 'count(iptables_up{%s} == 0) or vector(0)' % sel, 'short', 'Targets with a failed last collection.'),
    stat('Max snapshot age', 'max(time() - iptables_snapshot_timestamp_seconds{%s})' % sel, 's', 'Age of the oldest successful snapshot.'),
    stat('Series omitted', 'sum(iptables_series_omitted{%s})' % sel, 'short', 'Non-zero means the series limit truncated this scrape: raise --limit.series or narrow selection.'),
    stat('Duplicate rule IDs', 'sum(iptables_duplicate_rule_ids{%s})' % sel, 'short', 'Rules dropped because their iptx:id is not unique within a chain.'),
  ]),
  g.panel.row.new('Policy chains') + g.panel.row.withPanels([
    ts('Policy-chain packet rate',
       'sum by (family, backend, table, chain) (rate(iptables_chain_policy_packets_total{%s}[$__rate_interval]))' % sel,
       '{{family}}/{{backend}} {{table}}/{{chain}}', 'pps',
       'Counts only packets that fall through to the policy of a built-in chain; it is not total traffic. For the nat table these are connection-establishing packets, not connection throughput. Counters reset on iptables-restore or flush; rate() handles resets.'),
    ts('Policy DROP packet rate',
       'sum by (instance, family, backend, table, chain) (rate(iptables_chain_policy_packets_total{%s}[$__rate_interval]) * on (instance, family, backend, table, chain) iptables_chain_policy_info{%s, policy="DROP"})' % [sel, sel],
       '{{instance}} {{family}}/{{backend}} {{table}}/{{chain}}', 'pps',
       'Packets/s dropped by a DROP policy. Chains whose policy is not DROP are excluded. Counts only packets that reach a DROP policy; Explicit DROP rules are not counted here; see the Selected rules panels. A chain appears only while its policy is DROP.'),
    ts('Policy-chain byte rate',
       'sum by (family, backend, table, chain) (rate(iptables_chain_policy_bytes_total{%s}[$__rate_interval]))' % sel,
       '{{family}}/{{backend}} {{table}}/{{chain}}', 'Bps',
       'Counts only packets that fall through to the policy of a built-in chain; it is not total traffic. For the nat table these are connection-establishing packets, not connection throughput. Counters reset on iptables-restore or flush; rate() handles resets.'),
  ]),
  g.panel.row.new('Selected rules') + g.panel.row.withPanels([
    ts('Rule hit rate',
       'sum by (rule_id, family, backend, table, chain) (rate(iptables_rule_packets_total{%s}[$__rate_interval]))' % sel,
       '{{rule_id}} ({{family}}/{{backend}} {{table}}/{{chain}})', 'pps',
       'Only rules selected with iptx:id=<name> or --select.comment-regex are shown; this is not a complete accept/drop total. An ACCEPT at one hook is not final delivery. Counters reset on iptables-restore or flush.'),
    ts('Rule throughput',
       'sum by (rule_id, family, backend, table, chain) (rate(iptables_rule_bytes_total{%s}[$__rate_interval]))' % sel,
       '{{rule_id}} ({{family}}/{{backend}} {{table}}/{{chain}})', 'Bps',
       'Only rules selected with iptx:id=<name> or --select.comment-regex are shown; this is not a complete accept/drop total. An ACCEPT at one hook is not final delivery. Counters reset on iptables-restore or flush.'),
    tbl('Selected rules, current counters',
        'iptables_rule_packets_total{%s}' % sel,
        'Instant values of the packets counter per selected rule. Only rules selected with iptx:id=<name> or --select.comment-regex are shown; this is not a complete accept/drop total. An ACCEPT at one hook is not final delivery. Counters reset on iptables-restore or flush.'),
  ]),
  g.panel.row.new('Inventory') + g.panel.row.withPanels([
    ts('Rules per chain',
       'topk(50, sum by (family, backend, table, chain) (iptables_rules{%s}))' % sel,
       '{{family}}/{{backend}} {{table}}/{{chain}}', 'short',
       'Top 50 chains by rule count. Current rule count per chain from the last successful snapshot; not a traffic measure.'),
    tbl('Backends and versions', 'iptables_backend_info{%s}' % sel,
        'Userspace version per backend as reported by the save binary.'),
    tbl('Policies', 'iptables_chain_policy_info{%s}' % sel),
  ]),
  g.panel.row.new('Exporter health') + g.panel.row.withPanels([
    ts('Target up', 'iptables_up{%s}' % sel, '{{instance}} {{family}}/{{backend}}', 'short'),
    ts('Snapshot age', 'time() - iptables_snapshot_timestamp_seconds{%s}' % sel, '{{instance}} {{family}}/{{backend}}', 's',
       'Time since the last successful collection. Grows while a target is failing.'),
    ts('Collection duration', 'iptables_scrape_duration_seconds{%s}' % sel, '{{instance}} {{family}}/{{backend}}', 's',
       'Duration of the last collection attempt; large values signal huge rulesets or xtables lock contention.'),
    ts('Series omitted by limit', 'iptables_series_omitted{%s}' % sel, '{{instance}}', 'short'),
  ]),
  g.panel.row.new('Conntrack (optional, requires node_exporter)') + g.panel.row.withPanels([
    ts('Conntrack table usage',
       'max by (node) (label_replace(node_nf_conntrack_entries, "node", "$1", "instance", "(.+):[0-9]+")) / max by (node) (label_replace(node_nf_conntrack_entries_limit, "node", "$1", "instance", "(.+):[0-9]+"))',
       '{{node}}', 'percentunit',
       'Joined by host (instance without port) because node_exporter and iptables-exporter use different ports. Empty if node_exporter or nf_conntrack is absent. Ignores the instance variable: it shows every host that node_exporter reports. Instances without a port are not rewritten, get no node label and are aggregated under an empty node.'),
  ]),
];

g.dashboard.new('iptables exporter')
+ g.dashboard.withUid('iptables-exporter')
+ g.dashboard.withDescription('Policy counters, selected rules and health of iptables-exporter.')
+ g.dashboard.withTags(['iptables', 'netfilter', 'firewall'])
+ g.dashboard.time.withFrom('now-6h')
+ g.dashboard.withRefresh('30s')
+ g.dashboard.withVariables([
  g.dashboard.variable.datasource.new('datasource', 'prometheus') + g.dashboard.variable.datasource.generalOptions.withLabel('Data source'),
  g.dashboard.variable.query.new('job')
  + g.dashboard.variable.query.generalOptions.withLabel('Job')
  + g.dashboard.variable.query.withDatasourceFromVariable(g.dashboard.variable.datasource.new('datasource', 'prometheus'))
  + g.dashboard.variable.query.queryTypes.withLabelValues('job', 'iptables_up')
  + g.dashboard.variable.query.selectionOptions.withMulti()
  + g.dashboard.variable.query.selectionOptions.withIncludeAll(true, '.+')
  + g.dashboard.variable.query.refresh.onTime(),
  g.dashboard.variable.query.new('instance')
  + g.dashboard.variable.query.generalOptions.withLabel('Instance')
  + g.dashboard.variable.query.withDatasourceFromVariable(g.dashboard.variable.datasource.new('datasource', 'prometheus'))
  + g.dashboard.variable.query.queryTypes.withLabelValues('instance', 'iptables_up{job=~"$job"}')
  + g.dashboard.variable.query.selectionOptions.withMulti()
  + g.dashboard.variable.query.selectionOptions.withIncludeAll(true, '.+')
  + g.dashboard.variable.query.refresh.onTime(),
])
+ g.dashboard.withPanels(g.util.grid.makeGrid(panels, panelWidth=8, panelHeight=8))
