# iptables-exporter

Prometheus exporter for iptables (legacy and nft backends, IPv4 and IPv6).

Status: under development. See the repository releases for usable versions.

## What it exports

- Policy counters of built-in chains and rule counts (always on).
- Per-rule packet/byte counters for rules you select: add `-m comment --comment "iptx:id=<name>"` to a rule,
  or pass `--select.comment-regex`.
- Health metrics (`iptables_up`, snapshot age, duplicate IDs, omitted series).

## Privileges

Needs CAP_NET_ADMIN and CAP_NET_RAW. These capabilities also allow modifying firewall rules;
the exporter only ever runs `*-save -c`.

## Build

    export PATH=/usr/local/go/bin:$PATH
    make build test
