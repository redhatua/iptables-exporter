PKG := github.com/redhatua/iptables-exporter
LDFLAGS := -s -w -X $(PKG)/internal/buildinfo.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) -X $(PKG)/internal/buildinfo.Revision=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

.PHONY: build test vet lint bench integration dashboards mixin

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/iptables-exporter ./cmd/iptables-exporter

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint: vet
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

bench:
	go test -run '^$$' -bench . -benchmem ./internal/...

integration:
	docker build -t iptables-exporter-it -f test/integration/Dockerfile .
	docker run --rm --privileged -v "$(CURDIR)":/src iptables-exporter-it

dashboards:
	jsonnet -J dashboards/vendor dashboards/iptables.jsonnet > dashboards/iptables.json

mixin:
	jsonnet -J dashboards/vendor -S -e 'std.manifestYamlDoc((import "mixin/mixin.libsonnet").prometheusAlerts)' > mixin/alerts.yaml
	promtool check rules mixin/alerts.yaml
	promtool test rules mixin/alerts_test.yaml
