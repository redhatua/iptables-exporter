#!/usr/bin/env bash
# Runs inside a privileged container. Real iptables, both backends, IPv4+IPv6,
# exporter running as a non-root user with ambient capabilities.
set -euo pipefail
cd /src
go build -buildvcs=false -trimpath -o /tmp/iptables-exporter ./cmd/iptables-exporter

# Distinct rule sets per backend so we can tell them apart.
iptables-legacy  -A INPUT -i lo -p tcp --dport 9876 -m comment --comment "iptx:id=legacy-scrape" -j ACCEPT
iptables-nft     -A INPUT -i lo -p tcp --dport 9876 -m comment --comment "iptx:id=nft-scrape"    -j ACCEPT
ip6tables-legacy -A INPUT -p ipv6-icmp -m comment --comment "iptx:id=legacy6-icmp" -j ACCEPT
ip6tables-nft    -A INPUT -p ipv6-icmp -m comment --comment "iptx:id=nft6-icmp"    -j ACCEPT

# Non-root with NET_ADMIN + NET_RAW + DAC_READ_SEARCH ambient (DAC_READ_SEARCH is
# needed by iptables-legacy-save to read root-only /proc/net/ip{,6}_tables_names;
# nft does not need it).
capsh --caps="cap_net_admin,cap_net_raw,cap_dac_read_search,cap_setpcap,cap_setuid,cap_setgid+eip" --keep=1 --user=nobody \
      --addamb=cap_net_admin --addamb=cap_net_raw --addamb=cap_dac_read_search -- \
      -c 'exec /tmp/iptables-exporter --web.listen-address=127.0.0.1:9876 --collect.interval=5s' &
EXPORTER=$!
trap 'kill $EXPORTER ${EXPORTER2:-} 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -fs http://127.0.0.1:9876/-/ready >/dev/null 2>&1 && break
  sleep 0.2
done

# Generate traffic that hits the lo/9876 rules, then wait for a fresh snapshot.
for _ in 1 2 3; do curl -fs http://127.0.0.1:9876/healthz >/dev/null; done
sleep 7
m=$(curl -fs http://127.0.0.1:9876/metrics)

fail() { echo "FAIL: $1"; echo "$m" | grep '^iptables_' || true; exit 1; }
want() { grep -Eq "$1" <<<"$m" || fail "missing: $1"; }

user=$(ps -o user= -C iptables-exporter | head -1 | tr -d ' ')
[ "$user" = "nobody" ] || fail "exporter must run as nobody, got '$user'"

for fam in ipv4 ipv6; do
  for be in legacy nft; do
    want "^iptables_up\\{backend=\"$be\",family=\"$fam\"\\} 1"
    want "^iptables_chain_policy_packets_total\\{backend=\"$be\",chain=\"INPUT\",family=\"$fam\",table=\"filter\"\\}"
  done
done
want '^iptables_rule_packets_total\{backend="legacy",chain="INPUT",family="ipv4",rule_id="legacy-scrape",table="filter"\} [1-9]'
want '^iptables_rule_packets_total\{backend="nft",chain="INPUT",family="ipv4",rule_id="nft-scrape",table="filter"\}'
want '^iptables_rule_packets_total\{backend="legacy",chain="INPUT",family="ipv6",rule_id="legacy6-icmp",table="filter"\}'
want '^iptables_rule_packets_total\{backend="nft",chain="INPUT",family="ipv6",rule_id="nft6-icmp",table="filter"\}'
want '^iptables_series_omitted 0'

# Phase 2 (negative case): without DAC_READ_SEARCH the legacy targets must be
# down while nft keeps working.
capsh --caps="cap_net_admin,cap_net_raw,cap_setpcap,cap_setuid,cap_setgid+eip" --keep=1 --user=nobody \
      --addamb=cap_net_admin --addamb=cap_net_raw -- \
      -c 'exec /tmp/iptables-exporter --web.listen-address=127.0.0.1:9877 --collect.interval=5s' &
EXPORTER2=$!
for _ in $(seq 1 50); do
  curl -fs http://127.0.0.1:9877/-/ready >/dev/null 2>&1 && break
  sleep 0.2
done
sleep 1
m=$(curl -fs http://127.0.0.1:9877/metrics)
for fam in ipv4 ipv6; do
  want "^iptables_up\\{backend=\"legacy\",family=\"$fam\"\\} 0"
  want "^iptables_up\\{backend=\"nft\",family=\"$fam\"\\} 1"
done
echo "integration OK"
