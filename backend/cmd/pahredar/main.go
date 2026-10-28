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
	"syscall"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/api"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/config"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/cvelist"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

const usage = `usage: pahredar <command>

commands:
  serve                         apply migrations, run the HTTP API and the sync scheduler
  migrate                       apply pending migrations and exit
  sync cvelist [--bootstrap]    run one cvelist sync in the foreground and exit
  healthcheck                   exit 0 if the local API reports healthy (for container health checks)
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

func newCVEListJob(cfg config.Config, store *db.Store) *syncer.CVEList {
	return syncer.NewCVEList(cvelist.New(cfg.GitHubToken, cfg.DataDir), store, syncer.NewRunner(store))
}

func syncOnce(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 || args[0] != syncer.SourceCVEList {
		return fmt.Errorf("unknown or missing source; available: %s", syncer.SourceCVEList)
	}
	fs := flag.NewFlagSet("sync "+args[0], flag.ContinueOnError)
	bootstrap := fs.Bool("bootstrap", false, "re-import the full baseline even if a cursor exists")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()
	return newCVEListJob(cfg, store).Sync(ctx, *bootstrap)
}

func serve(ctx context.Context, cfg config.Config) error {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	syncCtx, stopSync := context.WithCancel(ctx)
	syncDone := make(chan struct{})
	if cfg.SyncEnabled {
		job := newCVEListJob(cfg, store)
		go func() {
			defer close(syncDone)
			syncer.Schedule(syncCtx, syncer.Task{
				Name:     syncer.SourceCVEList,
				Interval: cfg.CVEListSyncInterval,
				Fn:       func(ctx context.Context) error { return job.Sync(ctx, false) },
			})
		}()
	} else {
		slog.Info("sync scheduler disabled")
		close(syncDone)
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.New(store).Handler(),
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
