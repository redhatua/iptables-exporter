{
  prometheusAlerts+:: {
    groups+: [{
      name: 'iptables-exporter',
      rules: [
        {
          alert: 'IptablesExporterDown',
          expr: 'up{%(iptablesSelector)s} == 0' % $._config,
          'for': '5m',
          labels: { severity: 'critical' },
          annotations: {
            summary: 'iptables-exporter is down on {{ $labels.instance }}',
            description: 'Prometheus cannot scrape the exporter.',
          },
        },
        {
          alert: 'IptablesCollectionFailing',
          expr: 'iptables_up{%(iptablesSelector)s} == 0' % $._config,
          'for': '5m',
          labels: { severity: 'warning' },
          annotations: {
            summary: 'iptables collection failing on {{ $labels.instance }} ({{ $labels.family }}/{{ $labels.backend }})',
            description: 'The save command failed, timed out or produced an incomplete dump. Counters for this target are omitted.',
          },
        },
        {
          alert: 'IptablesSnapshotStale',
          expr: 'time() - iptables_snapshot_timestamp_seconds{%(iptablesSelector)s} > %(snapshotStaleSeconds)d' % $._config,
          'for': '5m',
          labels: { severity: 'warning' },
          annotations: {
            summary: 'iptables-exporter snapshot is stale on {{ $labels.instance }} ({{ $labels.family }}/{{ $labels.backend }})',
            description: 'No successful collection for more than %(snapshotStaleSeconds)d seconds.' % $._config,
          },
        },
        {
          alert: 'IptablesSeriesOmitted',
          expr: 'iptables_series_omitted{%(iptablesSelector)s} > 0' % $._config,
          'for': '15m',
          labels: { severity: 'warning' },
          annotations: {
            summary: 'iptables-exporter is omitting series on {{ $labels.instance }}',
            description: 'The series limit truncated the scrape. Raise --limit.series or narrow rule selection.',
          },
        },
        {
          alert: 'IptablesDuplicateRuleIDs',
          expr: 'iptables_duplicate_rule_ids{%(iptablesSelector)s} > 0' % $._config,
          'for': '15m',
          labels: { severity: 'warning' },
          annotations: {
            summary: 'Duplicate iptx:id rule IDs on {{ $labels.instance }} ({{ $labels.family }}/{{ $labels.backend }})',
            description: 'Rules sharing an ID within a chain are dropped from the metrics. Make the IDs unique.',
          },
        },
        {
          alert: 'IptablesPolicyDropRateHigh',
          expr: 'sum by (instance, family, backend, table, chain) (rate(iptables_chain_policy_packets_total{%(iptablesSelector)s}[5m]) * on (instance, family, backend, table, chain) iptables_chain_policy_info{%(iptablesSelector)s, policy="DROP"}) > %(policyDropPacketsPerSecond)d' % $._config,
          'for': '10m',
          labels: { severity: 'warning' },
          annotations: {
            summary: 'High DROP-policy rate on {{ $labels.instance }} ({{ $labels.table }}/{{ $labels.chain }})',
            description: 'Packets are hitting the DROP policy of {{ $labels.table }}/{{ $labels.chain }} on {{ $labels.instance }}; see the dashboard policy row.',
          },
        },
      ],
    }],
  },
}
