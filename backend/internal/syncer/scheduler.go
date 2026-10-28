package syncer

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// retryBase is the first retry delay after a failed run; it doubles on each
// consecutive failure, capped at the task's interval.
const retryBase = 5 * time.Minute

// ErrUnknownSource is returned by Trigger for a source with no task.
var ErrUnknownSource = errors.New("unknown source")

type Task struct {
	Name     string
	Interval time.Duration
	Fn       func(context.Context) error
}

// Scheduler runs each task immediately, then every Interval, and on demand.
type Scheduler struct {
	tasks    []Task
	triggers map[string]chan struct{}
}

func NewScheduler(tasks ...Task) *Scheduler {
	s := &Scheduler{tasks: tasks, triggers: make(map[string]chan struct{}, len(tasks))}
	for _, t := range tasks {
		s.triggers[t.Name] = make(chan struct{}, 1)
	}
	return s
}

// Sources lists task names in registration order.
func (s *Scheduler) Sources() []string {
	names := make([]string, len(s.tasks))
	for i, t := range s.tasks {
		names[i] = t.Name
	}
	return names
}

// Trigger asks a task to run as soon as it is idle. Repeated triggers while a
// run is pending collapse into one.
func (s *Scheduler) Trigger(name string) error {
	ch, ok := s.triggers[name]
	if !ok {
		return ErrUnknownSource
	}
	select {
	case ch <- struct{}{}:
	default:
	}
	return nil
}

// Run blocks until ctx is done and every task loop has returned.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range s.tasks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.loop(ctx, t)
		}()
	}
	wg.Wait()
}

func (s *Scheduler) loop(ctx context.Context, t Task) {
	failures := 0
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.triggers[t.Name]:
			slog.Info("sync triggered", "source", t.Name)
		}

		err := t.Fn(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := t.Interval
		switch {
		case err == nil:
			failures = 0
		case errors.Is(err, ErrAlreadyRunning):
			failures = 0
			slog.Info("sync skipped: already running elsewhere", "source", t.Name)
		default:
			failures++
			delay = min(t.Interval, retryBase<<min(failures-1, 10))
			slog.Warn("sync will retry", "source", t.Name, "failures", failures, "in", delay)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
	}
}
