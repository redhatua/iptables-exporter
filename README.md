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

Container image: `ghcr.io/redhatua/iptables-exporter`. Run it on the host network with exactly the
capabilities it needs:

    docker run --rm --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --network host \
      ghcr.io/redhatua/iptables-exporter:<version>

A plain `docker run` with the default capability set lacks NET_ADMIN, so every `*-save` call fails and all
targets report `iptables_up 0`. The image runs as root inside the container on purpose: file capabilities on the
exporter binary would not reach the `*-save` child process, and no_new_privs (hardened Pod Security) blocks them
anyway. The runtime restricts the capability set instead.

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

## Kernel and userspace compatibility

The image ships Debian bookworm iptables 1.8.9 with both the legacy and the nft variants. The exporter runs
the binaries it finds, so the userspace must match the ruleset backend of the host kernel. Native nftables
rulesets without the iptables-nft shim are not supported in v1.

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
    --[no-]collect.user-chain-rules  Export iptables_rules for user-defined chains (default on).
    --binary.ipv4.legacy=iptables-legacy-save
    --binary.ipv6.legacy=ip6tables-legacy-save
    --binary.ipv4.nft=iptables-nft-save
    --binary.ipv6.nft=ip6tables-nft-save
    --log.level=info           debug, info, warn, error.
    --log.format=logfmt        logfmt or json.
    --version, --help

## Configuration file

Every setting except the web and log flags can also be set in a YAML file passed with `--config.file`.
Values in the file override command-line flags, and unknown keys are rejected. Example with all keys:

    interval: 15s
    timeout: 10s
    max_output_bytes: 67108864
    families: [ipv4, ipv6]
    backends: [legacy, nft]
    binaries:
      ipv4/legacy: iptables-legacy-save
      ipv6/legacy: ip6tables-legacy-save
      ipv4/nft: iptables-nft-save
      ipv6/nft: ip6tables-nft-save
    comment_regex:
      - '^svc/(\w+)$'
    id_convention: true
    series_limit: 5000
    user_chain_rules: true

`binaries` keys are `<family>/<backend>` and only these four are valid. `max_output_bytes` must not exceed 2^40.
Duplicate entries in `families` or `backends` are rejected.

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
Alternatively pass `--select.comment-regex`; the first capture group is the ID (the whole match if the
pattern has no group). IDs derived from a regex are limited to 128 bytes and must be valid UTF-8; convention
IDs are limited to 64 characters. A longer ID is never truncated: the comment simply yields no ID.

A rule may carry several comments. The first comment that yields an ID wins, and for each comment the
`iptx:id=` convention is tried before the regexes.

If several rules in a chain share an ID, those rules are dropped and counted in
`iptables_duplicate_rule_ids`.

### Counter resets and rule-ID churn

Counters are read from the kernel, so `iptables-restore`, a flush, or re-creating a rule resets them to zero.
Always query them with `rate()` or `increase()`, which handle resets.

Every distinct rule ID is a distinct series. IDs that change per deployment create new series and leave
stale ones behind; names such as the kube-proxy `KUBE-SEP-<hash>` chains churn constantly. Use stable
`iptx:id=` names that you assign yourself.

User-defined chains each get an `iptables_rules` gauge. On Kubernetes nodes kube-proxy creates thousands of
`KUBE-SVC`/`KUBE-SEP` chains, which would exhaust the series limit; disable them with
`--no-collect.user-chain-rules` (or `user_chain_rules: false`). The Helm chart does this by default.
Built-in chain gauges, policy counters and selected rule series are unaffected.

### Series budget

When the series budget (`--limit.series`) is exceeded, series are kept in this priority order:
health metrics (reserved, never dropped), then built-in chains, then selected rules,
then rule counts of user-defined chains. Omitted series are counted in `iptables_series_omitted`.

## Alerts and dashboard

`mixin/alerts.yaml` holds the alert rules and `dashboards/iptables.json` the Grafana dashboard. The mixin
selector defaults to `job="iptables-exporter"`. With the Helm PodMonitor the job label is `iptables-exporter`
(the PodMonitor sets `jobLabel: app.kubernetes.io/name`); in any other setup override
`_config.iptablesSelector` when rendering the mixin. Recommended: inhibit `IptablesSnapshotStale` and
`IptablesCollectionFailing` while `IptablesExporterDown` fires for the same instance, since they are
consequences of the exporter being unreachable.

## Memory sizing

Budget roughly 8 MB of live heap per 100k rules plus the raw `*-save` dump held while parsing (up to
`--collect.max-output`). The Helm chart defaults to a 256Mi limit with `GOMEMLIMIT=192MiB`; raise both for
very large rulesets.

## Build

Requires Go 1.26 or newer.

    make build test
