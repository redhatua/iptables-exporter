// Command iptables-exporter exposes iptables counters as Prometheus metrics.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	promslogflag "github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/redhatua/iptables-exporter/internal/buildinfo"
	"github.com/redhatua/iptables-exporter/internal/collector"
	"github.com/redhatua/iptables-exporter/internal/config"
	"github.com/redhatua/iptables-exporter/internal/runner"
	"github.com/redhatua/iptables-exporter/internal/selector"
	"github.com/redhatua/iptables-exporter/internal/snapshot"
)

func main() { os.Exit(run()) }

// reservedPaths are served by the exporter itself.
var reservedPaths = map[string]bool{"/": true, "/healthz": true, "/-/ready": true}

// validateMetricsPath rejects telemetry paths that would collide with or
// panic the HTTP mux.
func validateMetricsPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("--web.telemetry-path %q must start with \"/\"", p)
	}
	if strings.ContainsAny(p, "{} \t\r\n") {
		return fmt.Errorf("--web.telemetry-path %q must not contain braces or whitespace (http.ServeMux treats them as pattern syntax)", p)
	}
	if reservedPaths[p] {
		return fmt.Errorf("--web.telemetry-path %q is reserved (/, /healthz and /-/ready are served by the exporter)", p)
	}
	return nil
}

// slogErrorLog adapts a slog logger to promhttp.Logger.
type slogErrorLog struct{ l *slog.Logger }

func (s slogErrorLog) Println(v ...interface{}) { s.l.Error(strings.TrimSpace(fmt.Sprintln(v...))) }

func run() int {
	cfg := config.Default()
	// kingpin appends parsed values to a slice target, so bind empty slices
	// and feed the defaults through Default(...) instead.
	defFamilies, defBackends := cfg.Families, cfg.Backends
	cfg.Families, cfg.Backends = nil, nil
	logCfg := &promslog.Config{}

	app := kingpin.New("iptables-exporter", "Prometheus exporter for iptables counters.")
	app.Version(buildinfo.String())
	app.HelpFlag.Short('h')

	configFile := app.Flag("config.file", "Optional YAML file; its values override command-line flags.").String()
	metricsPath := app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	app.Flag("collect.interval", "How often to collect (minimum 5s).").Default(cfg.Interval.String()).DurationVar(&cfg.Interval)
	app.Flag("collect.timeout", "Timeout of one save command.").Default(cfg.Timeout.String()).DurationVar(&cfg.Timeout)
	app.Flag("collect.max-output", "Maximum bytes accepted from one save command.").Default("67108864").Int64Var(&cfg.MaxOutput)
	app.Flag("collect.families", "Address families to collect (repeatable): ipv4, ipv6.").Default(defFamilies...).StringsVar(&cfg.Families)
	app.Flag("collect.backends", "Backends to collect (repeatable): legacy, nft.").Default(defBackends...).StringsVar(&cfg.Backends)
	app.Flag("select.comment-regex", "Regex over rule comments selecting rules for per-rule series; first group is the ID (repeatable).").StringsVar(&cfg.CommentRegex)
	app.Flag("select.id-convention", "Select rules whose comment contains iptx:id=<name>.").Default("true").BoolVar(&cfg.IDConvention)
	app.Flag("collect.user-chain-rules", "Export the iptables_rules gauge of user-defined chains. Disable with --no-collect.user-chain-rules (recommended on Kubernetes nodes).").Default("true").BoolVar(&cfg.UserChainRules)
	app.Flag("limit.series", "Maximum non-health series per scrape; 0 disables the limit.").Default("5000").IntVar(&cfg.SeriesLimit)

	binFlags := map[string]*string{}
	binKeys := make([]string, 0, len(config.DefaultBinaries))
	for key := range config.DefaultBinaries {
		binKeys = append(binKeys, key)
	}
	sort.Strings(binKeys) // deterministic --help
	for _, key := range binKeys {
		def := config.DefaultBinaries[key]
		name := "binary." + strings.Replace(key, "/", ".", 1)
		binFlags[key] = app.Flag(name, "Save binary for "+key+".").Default(def).String()
	}

	promslogflag.AddFlags(app, logCfg)
	webFlags := kingpinflag.AddFlags(app, ":10058")
	kingpin.MustParse(app.Parse(os.Args[1:]))

	logger := promslog.New(logCfg)
	if err := validateMetricsPath(*metricsPath); err != nil {
		logger.Error("invalid flag", "err", err)
		return 1
	}
	for key, p := range binFlags {
		cfg.Binaries[key] = *p
	}
	if *configFile != "" {
		if err := cfg.LoadFile(*configFile); err != nil {
			logger.Error("loading config", "err", err)
			return 1
		}
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", "err", err)
		return 1
	}

	targets, skipped := cfg.Targets(exec.LookPath)
	for _, s := range skipped {
		logger.Warn("target skipped, binary not found", "target", s)
	}
	if len(targets) == 0 {
		logger.Error("no usable iptables save binary found; check --collect.* and --binary.* flags")
		return 1
	}

	sel, err := selector.New(cfg.IDConvention, cfg.CommentRegex)
	if err != nil {
		logger.Error("invalid selector", "err", err)
		return 1
	}
	mgr := snapshot.NewManager(targets,
		&snapshot.ExecFetcher{Runner: runner.Runner{Timeout: cfg.Timeout, MaxOutput: cfg.MaxOutput}},
		cfg.Interval, logger)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collector.New(mgr, sel, cfg.SeriesLimit, cfg.UserChainRules),
	)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		ErrorLog:      slogErrorLog{logger},
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/-/ready", func(w http.ResponseWriter, _ *http.Request) {
		if !mgr.Ready() {
			http.Error(w, "first collection not finished", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "iptables-exporter\nmetrics: %s\n", *metricsPath)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go mgr.Run(ctx)

	logger.Info("starting", "version", buildinfo.Version, "revision", buildinfo.Revision, "targets", len(targets))
	errc := make(chan error, 1)
	go func() { errc <- web.ListenAndServe(srv, webFlags, logger) }()

	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			return 1
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}
	return 0
}
