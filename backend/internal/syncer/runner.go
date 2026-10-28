// Package syncer runs source sync jobs: locking, run logging, scheduling, and
// the per-source jobs that turn upstream data into stored rows.
package syncer

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

const (
	KindBootstrap   = "bootstrap"
	KindIncremental = "incremental"
)

// ErrAlreadyRunning means another process or goroutine holds the source's lock.
var ErrAlreadyRunning = errors.New("sync already running")

// Run accumulates a run's counters; jobs update it as they write.
type Run struct {
	Kind     string
	Inserted int
	Updated  int
	Deleted  int
}

type Runner struct {
	store *db.Store
}

func NewRunner(store *db.Store) *Runner {
	return &Runner{store: store}
}

// Run takes the source's advisory lock, asks plan for the run kind, records a
// sync_run row, executes body, and records the outcome.
func (r *Runner) Run(ctx context.Context, source string, plan func(context.Context) (string, error), body func(context.Context, *Run) error) error {
	release, ok, err := r.store.TryLock(ctx, "sync:"+source)
	if err != nil {
		return err
	}
	if !ok {
		return ErrAlreadyRunning
	}
	defer release()

	if n, err := r.store.FailStaleRuns(ctx, source); err != nil {
		return err
	} else if n > 0 {
		slog.Warn("marked interrupted runs as failed", "source", source, "count", n)
	}

	kind, err := plan(ctx)
	if err != nil {
		return err
	}
	id, err := r.store.StartRun(ctx, source, kind)
	if err != nil {
		return err
	}
	run := &Run{Kind: kind}
	start := time.Now()
	slog.Info("sync started", "source", source, "kind", kind, "run", id)

	runErr := body(ctx, run)

	// Record the outcome even if ctx was cancelled (e.g. shutdown mid-run).
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := r.store.FinishRun(finishCtx, id, source, run.Inserted, run.Updated, run.Deleted, runErr); err != nil {
		slog.Error("record sync result", "source", source, "run", id, "err", err)
	}
	attrs := []any{"source", source, "kind", kind, "run", id, "inserted", run.Inserted, "updated", run.Updated,
		"deleted", run.Deleted, "duration", time.Since(start).Round(time.Millisecond)}
	if runErr != nil {
		slog.Error("sync failed", append(attrs, "err", runErr)...)
	} else {
		slog.Info("sync finished", attrs...)
	}
	return runErr
}
