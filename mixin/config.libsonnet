{
  _config+:: {
    // Selector for the exporter's scrape job, used in every alert.
    iptablesSelector: 'job="iptables-exporter"',
    // Packets/s reaching a DROP policy before PolicyDropRateHigh fires.
    policyDropPacketsPerSecond: 100,
    snapshotStaleSeconds: 300,
  },
}
