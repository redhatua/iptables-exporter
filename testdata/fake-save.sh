#!/bin/sh
# Test double for iptables-*-save. Prints a version for --version, otherwise the docker fixture.
if [ "$1" = "--version" ]; then
  echo "iptables-save v1.8.10 (legacy)"
  exit 0
fi
cat "$(dirname "$0")/docker.save"
