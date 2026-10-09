FROM golang:1.26-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables curl libcap2-bin procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ENTRYPOINT ["/src/test/integration/run.sh"]
