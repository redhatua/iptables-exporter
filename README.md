# iptables-exporter

Prometheus exporter for iptables (legacy and nft backends, IPv4 and IPv6).

Status: under development. See the repository releases for usable versions.

## What it exports

- Policy counters of built-in chains and rule counts (always on).
- Per-rule packet/byte counters for rules you select: add `-m comment --comment "iptx:id=<name>"` to a rule,
  or pass `--select.comment-regex`.
- Health metrics (`iptables_up`, snapshot age, duplicate IDs, omitted series).

## Install

Release binary and systemd unit: download the archive for your architecture from the GitHub releases page,
install the binary to `/usr/local/bin/iptables-exporter`, create the `iptables-exporter` user and group,
copy `deploy/systemd/iptables-exporter.service` to `/etc/systemd/system/`, then
`systemctl enable --now iptables-exporter`. The archive also contains the Grafana dashboard
(`dashboards/iptables.json`) and alert rules (`mixin/alerts.yaml`).

Container image: `ghcr.io/redhatua/iptables-exporter`.

Helm chart: `deploy/helm/iptables-exporter` (a DaemonSet with an optional PodMonitor):

    helm install iptables-exporter deploy/helm/iptables-exporter -n monitoring

## Privileges

The exporter needs CAP_NET_ADMIN and CAP_NET_RAW. These capabilities allow modifying firewall rules;
the exporter only ever runs `*-save -c`.

A non-root exporter using the legacy backend also needs CAP_DAC_READ_SEARCH, because
`iptables-legacy-save` reads the root-only files `/proc/net/ip_tables_names` and `/proc/net/ip6_tables_names`.
The nft backend does not need it. The systemd unit grants all three capabilities.

Kubernetes: the DaemonSet needs `hostNetwork: true` and a namespace with the privileged Pod Security level
(`pod-security.kubernetes.io/enforce=privileged`). It runs as root with all capabilities dropped except
NET_ADMIN and NET_RAW, so it needs no DAC capability.

Do not use `PrivateNetwork=` in systemd: it hides the host rules.

## Flags

    --config.file=CONFIG.FILE   Optional YAML file; its values override command-line flags.
    --web.listen-address=:9876  Addresses on which to expose metrics (repeatable).
    --web.telemetry-path=/metrics
    --web.config.file          TLS / basic auth configuration (exporter-toolkit format).
    --web.systemd-socket       Use systemd socket activation.
    --collect.interval=15s     How often to collect (minimum 5s).
    --collect.timeout=10s      Timeout of one save command.
    --collect.max-output=67108864  Maximum bytes accepted from one save command.
    --collect.families=ipv4... Address families to collect (repeatable): ipv4, ipv6.
    --collect.backends=legacy... Backends to collect (repeatable): legacy, nft.
    --select.comment-regex=RE  Regex over rule comments; first group is the ID (repeatable).
    --select.id-convention     Select rules whose comment contains iptx:id=<name> (default on).
    --limit.series=5000        Maximum non-health series per scrape; 0 disables the limit.
    --binary.ipv4.legacy=iptables-legacy-save
    --binary.ipv6.legacy=ip6tables-legacy-save
    --binary.ipv4.nft=iptables-nft-save
    --binary.ipv6.nft=ip6tables-nft-save
    --log.level=info           debug, info, warn, error.
    --log.format=logfmt        logfmt or json.
    --version, --help

## Metrics

| Metric | Meaning |
|---|---|
| iptables_chain_policy_packets_total | Packets that reached the policy of a built-in chain. |
| iptables_chain_policy_bytes_total | Bytes that reached the policy of a built-in chain. |
| iptables_chain_policy_info | Policy of a built-in chain (value is always 1). |
| iptables_rules | Current number of rules in a chain. |
| iptables_rule_packets_total | Packets matched by a selected rule. |
| iptables_rule_bytes_total | Bytes matched by a selected rule. |
| iptables_backend_info | Backend and userspace version used for a target (value is always 1). |
| iptables_up | 1 if the last collection of the target succeeded. |
| iptables_snapshot_timestamp_seconds | Unix time of the last successful collection. |
| iptables_scrape_duration_seconds | Duration of the last collection attempt. |
| iptables_series_omitted | Series omitted from this scrape because of the series limit. |
| iptables_duplicate_rule_ids | Rules dropped because their rule ID is not unique within a chain. |
| iptables_build_info | Build information (value is always 1). |

## Rule selection

Per-rule counters are exported only for selected rules. Tag a rule with a comment of the form
`iptx:id=<name>` (for example `-m comment --comment "iptx:id=ssh-in"`); the ID is at most 64 characters.
Alternatively pass `--select.comment-regex`; the first capture group is the ID.

If several rules in a chain share an ID, those rules are dropped and counted in
`iptables_duplicate_rule_ids`.

When the series budget (`--limit.series`) is exceeded, series are kept in this priority order:
health metrics (reserved, never dropped), then built-in chains, then selected rules,
then rule counts of user-defined chains. Omitted series are counted in `iptables_series_omitted`.

## Build

    export PATH=/usr/local/go/bin:$PATH
    make build test
