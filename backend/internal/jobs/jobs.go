// Package jobs is a durable, Postgres-backed task queue: work is enqueued as a
// row, a worker pool claims and runs it, and results (and progress) are stored
// back on the row. It replaces per-feature in-memory job maps so work survives
// restarts and can be retried and scheduled. See docs/foundation.md (P2).
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// TaskStore is the persistence the queue needs (implemented by *db.Store).
type TaskStore interface {
	EnqueueTask(ctx context.Context, taskType string, payload []byte, maxAttempts int) (int64, error)
	EnqueueDoneTask(ctx context.Context, taskType string, payload, result []byte) (int64, error)
	ClaimTask(ctx context.Context, worker string) (*db.Task, error)
	SetTaskResult(ctx context.Context, id int64, result []byte) error
	CompleteTask(ctx context.Context, id int64, result []byte) error
	RescheduleTask(ctx context.Context, id int64, runAt time.Time, lastErr string) error
	FailTask(ctx context.Context, id int64, errMsg string) error
	GetTask(ctx context.Context, id int64) (*db.Task, error)
	ReapTasks(ctx context.Context, doneBefore, staleRunning time.Time) error
}

// Progress persists an intermediate result for the running task so clients
// polling the task see live updates.
type Progress func(result any)

// Handler runs one task. payload is the enqueued JSON; the returned value is
// stored as the task's final result.
type Handler func(ctx context.Context, payload json.RawMessage, progress Progress) (result any, err error)

// Queue is the task queue and its handler registry.
type Queue struct {
	store    TaskStore
	log      *slog.Logger
	mu       sync.RWMutex
	handlers map[string]Handler

	// PollInterval is how often an idle worker checks for new work.
	PollInterval time.Duration
	// DoneTTL is how long finished tasks are kept before the reaper deletes them.
	DoneTTL time.Duration
	// StaleAfter recovers tasks stuck 'running' (e.g. a crashed worker) after this.
	StaleAfter time.Duration
}

func New(store TaskStore, log *slog.Logger) *Queue {
	if log == nil {
		log = slog.Default()
	}
	return &Queue{
		store: store, log: log, handlers: map[string]Handler{},
		PollInterval: time.Second, DoneTTL: 24 * time.Hour, StaleAfter: 15 * time.Minute,
	}
}

// Register binds a handler to a task type. Call before Work.
func (q *Queue) Register(taskType string, h Handler) {
	q.mu.Lock()
	q.handlers[taskType] = h
	q.mu.Unlock()
}

// Enqueue adds a task. payload is marshalled to JSON. maxAttempts<1 means 1.
func (q *Queue) Enqueue(ctx context.Context, taskType string, payload any, maxAttempts int) (int64, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	return q.store.EnqueueTask(ctx, taskType, b, maxAttempts)
}

// EnqueueDone records an already-finished task with its result (e.g. a cache
// hit that produced a result without running).
func (q *Queue) EnqueueDone(ctx context.Context, taskType string, payload, result any) (int64, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	rb, err := json.Marshal(result)
	if err != nil {
		return 0, err
	}
	return q.store.EnqueueDoneTask(ctx, taskType, pb, rb)
}

// Get returns a task by id (for status polling).
func (q *Queue) Get(ctx context.Context, id int64) (*db.Task, error) {
	return q.store.GetTask(ctx, id)
}

// Work starts n worker goroutines plus a reaper and blocks until ctx is done.
func (q *Queue) Work(ctx context.Context, n int) {
	if n < 1 {
		n = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		worker := fmt.Sprintf("w%d", i)
		go func() { defer wg.Done(); q.worker(ctx, worker) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); q.reaper(ctx) }()
	q.log.Info("job queue started", "workers", n)
	wg.Wait()
}

func (q *Queue) worker(ctx context.Context, name string) {
	for {
		if ctx.Err() != nil {
			return
		}
		t, err := q.store.ClaimTask(ctx, name)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			q.log.Warn("claim task failed", "err", err)
			sleep(ctx, q.PollInterval)
			continue
		}
		if t == nil {
			sleep(ctx, q.PollInterval)
			continue
		}
		q.run(ctx, t)
	}
}

func (q *Queue) run(ctx context.Context, t *db.Task) {
	q.mu.RLock()
	h := q.handlers[t.Type]
	q.mu.RUnlock()
	if h == nil {
		_ = q.store.FailTask(ctx, t.ID, "no handler for task type "+t.Type)
		return
	}
	progress := func(res any) {
		b, err := json.Marshal(res)
		if err != nil {
			return
		}
		if err := q.store.SetTaskResult(ctx, t.ID, b); err != nil && ctx.Err() == nil {
			q.log.Warn("task progress save failed", "id", t.ID, "err", err)
		}
	}
	result, err := call(ctx, h, t.Payload, progress)
	if err != nil {
		// Reschedule with linear backoff until attempts are exhausted.
		if t.Attempts < t.MaxAttempts {
			backoff := time.Duration(t.Attempts) * 30 * time.Second
			if rerr := q.store.RescheduleTask(ctx, t.ID, time.Now().Add(backoff), err.Error()); rerr != nil {
				q.log.Warn("reschedule failed", "id", t.ID, "err", rerr)
			}
			return
		}
		if ferr := q.store.FailTask(ctx, t.ID, err.Error()); ferr != nil {
			q.log.Warn("fail task failed", "id", t.ID, "err", ferr)
		}
		return
	}
	b, _ := json.Marshal(result)
	if err := q.store.CompleteTask(ctx, t.ID, b); err != nil {
		q.log.Warn("complete task failed", "id", t.ID, "err", err)
	}
}

// call runs a handler, turning a panic into an error.
func call(ctx context.Context, h Handler, payload json.RawMessage, p Progress) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("task panicked: %v", r)
		}
	}()
	return h(ctx, payload, p)
}

func (q *Queue) reaper(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := q.store.ReapTasks(rctx, time.Now().Add(-q.DoneTTL), time.Now().Add(-q.StaleAfter)); err != nil && ctx.Err() == nil {
				q.log.Warn("task reap failed", "err", err)
			}
			cancel()
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
