ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/redhatua/iptables-exporter/internal/buildinfo.Version=${VERSION} -X github.com/redhatua/iptables-exporter/internal/buildinfo.Revision=${REVISION}" \
    -o /out/iptables-exporter ./cmd/iptables-exporter

FROM debian:bookworm-slim
# Both userspace variants are installed on purpose: the exporter probes legacy and nft separately.
# Kernel/userspace compatibility: iptables 1.8.9 (bookworm) works with Linux 4.x and newer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/iptables-exporter /usr/local/bin/iptables-exporter
LABEL org.opencontainers.image.source="https://github.com/redhatua/iptables-exporter" \
      org.opencontainers.image.licenses="Apache-2.0"
EXPOSE 9876
# Runs as root inside the container but with only NET_ADMIN and NET_RAW (see the Helm chart securityContext).
ENTRYPOINT ["/usr/local/bin/iptables-exporter"]
