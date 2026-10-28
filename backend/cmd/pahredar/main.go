// Command pahredar runs the Pahredar backend: HTTP API, sync scheduler, and
// maintenance subcommands.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/api"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/config"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/cvelist"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/exploits"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/fetch"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/nvd"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

const usage = `usage: pahredar <command>

commands:
  serve                           apply migrations, run the HTTP API and the sync scheduler
  migrate                         apply pending migrations and exit
  sync <source> [--bootstrap]     run one sync in the foreground and exit
                                  sources: cvelist, nvd, kev, epss, exploitdb, metasploit, nuclei
                                  --bootstrap (cvelist, nvd) re-imports everything
  healthcheck                     exit 0 if the local API reports healthy (for container health checks)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "serve":
		err = withConfig(ctx, serve)
	case "migrate":
		err = withConfig(ctx, func(ctx context.Context, cfg config.Config) error {
			return db.Migrate(ctx, cfg.DatabaseURL)
		})
	case "sync":
		err = withConfig(ctx, func(ctx context.Context, cfg config.Config) error {
			return syncOnce(ctx, cfg, os.Args[2:])
		})
	case "healthcheck":
		err = healthcheck()
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("fatal", "command", os.Args[1], "err", err)
		os.Exit(1)
	}
}

func withConfig(ctx context.Context, fn func(context.Context, config.Config) error) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})))
	return fn(ctx, cfg)
}

// openStore applies migrations and returns a store; the caller closes it.
func openStore(ctx context.Context, cfg config.Config) (*db.Store, func(), error) {
	if err := db.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return nil, nil, err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return db.NewStore(pool), pool.Close, nil
}

// syncTasks builds every source's task. bootstrap forces a full re-import
// for the sources that support it; serve always passes false.
func syncTasks(cfg config.Config, store *db.Store, bootstrap bool) []syncer.Task {
	runner := syncer.NewRunner(store)
	list := syncer.NewCVEList(cvelist.New(cfg.GitHubToken, cfg.DataDir), store, runner)
	nvdJob := syncer.NewNVD(nvd.New(cfg.NVDAPIKey), store, runner)
	enrich := syncer.NewEnrichment(fetch.NewClient(), store, runner)

	tasks := []syncer.Task{
		{Name: syncer.SourceCVEList, Interval: cfg.Intervals.CVEList, Fn: func(ctx context.Context) error { return list.Sync(ctx, bootstrap) }},
		{Name: syncer.SourceNVD, Interval: cfg.Intervals.NVD, Fn: func(ctx context.Context) error { return nvdJob.Sync(ctx, bootstrap) }},
		{Name: syncer.SourceKEV, Interval: cfg.Intervals.KEV, Fn: enrich.SyncKEV},
		{Name: syncer.SourceEPSS, Interval: cfg.Intervals.EPSS, Fn: enrich.SyncEPSS},
	}
	for _, src := range []string{exploits.SourceExploitDB, exploits.SourceMetasploit, exploits.SourceNuclei} {
		tasks = append(tasks, syncer.Task{Name: src, Interval: cfg.Intervals.Exploits,
			Fn: func(ctx context.Context) error { return enrich.SyncExploits(ctx, src) }})
	}
	return tasks
}

func syncOnce(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return errors.New("missing source; see usage")
	}
	fs := flag.NewFlagSet("sync "+args[0], flag.ContinueOnError)
	bootstrap := fs.Bool("bootstrap", false, "re-import everything even if a cursor exists (cvelist, nvd)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if cfg.NVDAPIKey == "" && args[0] == syncer.SourceNVD {
		slog.Warn("NVD_API_KEY is not set; NVD sync will be about 10x slower")
	}
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()
	var names []string
	for _, t := range syncTasks(cfg, store, *bootstrap) {
		if t.Name == args[0] {
			return t.Fn(ctx)
		}
		names = append(names, t.Name)
	}
	return fmt.Errorf("unknown source %q; available: %s", args[0], strings.Join(names, ", "))
}

func serve(ctx context.Context, cfg config.Config) error {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	syncCtx, stopSync := context.WithCancel(ctx)
	syncDone := make(chan struct{})
	var sched *syncer.Scheduler
	if cfg.SyncEnabled {
		if cfg.NVDAPIKey == "" {
			slog.Warn("NVD_API_KEY is not set; NVD sync will be about 10x slower")
		}
		sched = syncer.NewScheduler(syncTasks(cfg, store, false)...)
		go func() {
			defer close(syncDone)
			sched.Run(syncCtx)
		}()
	} else {
		slog.Info("sync scheduler disabled")
		close(syncDone)
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.New(store, sched).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	var serveErr error
	select {
	case serveErr = <-errCh:
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	stopSync()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if serveErr == nil {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	}
	select {
	case <-syncDone:
	case <-shutdownCtx.Done():
		slog.Warn("sync did not stop within the shutdown timeout")
	}
	return serveErr
}

func healthcheck() error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8080/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
