package syncer

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// retryBase is the first retry delay after a failed run; it doubles on each
// consecutive failure, capped at the task's interval.
const retryBase = 5 * time.Minute

type Task struct {
	Name     string
	Interval time.Duration
	Fn       func(context.Context) error
}

// Schedule runs t immediately and then every t.Interval until ctx is done.
func Schedule(ctx context.Context, t Task) {
	failures := 0
	delay := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		err := t.Fn(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil, errors.Is(err, ErrAlreadyRunning):
			failures = 0
			delay = t.Interval
			if err != nil {
				slog.Info("sync skipped: already running elsewhere", "source", t.Name)
			}
		default:
			failures++
			delay = min(t.Interval, retryBase<<min(failures-1, 10))
			slog.Warn("sync will retry", "source", t.Name, "failures", failures, "in", delay)
		}
	}
}
