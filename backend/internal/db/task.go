package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Task is one row of the durable task queue.
type Task struct {
	ID          int64           `json:"id"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"max_attempts"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// EnqueueTask inserts a queued task and returns its id.
func (s *Store) EnqueueTask(ctx context.Context, taskType string, payload []byte, maxAttempts int) (int64, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO task (type, payload, max_attempts) VALUES ($1, $2, $3) RETURNING id`,
		taskType, payload, maxAttempts).Scan(&id)
	return id, err
}

// EnqueueDoneTask inserts a task already completed with a result (used for
// results produced without running, e.g. a cache hit).
func (s *Store) EnqueueDoneTask(ctx context.Context, taskType string, payload, result []byte) (int64, error) {
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO task (type, payload, status, result) VALUES ($1, $2, 'done', $3) RETURNING id`,
		taskType, payload, result).Scan(&id)
	return id, err
}

// ClaimTask atomically claims the oldest due queued task for worker, marking it
// running. Returns nil (no error) when nothing is due.
func (s *Store) ClaimTask(ctx context.Context, worker string) (*Task, error) {
	var t Task
	err := s.pool.QueryRow(ctx, `
		UPDATE task SET status='running', attempts=attempts+1, locked_at=now(), locked_by=$1, updated_at=now()
		WHERE id = (
			SELECT id FROM task
			WHERE status='queued' AND run_at <= now()
			ORDER BY run_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, type, payload, attempts, max_attempts, created_at, updated_at`,
		worker).Scan(&t.ID, &t.Type, &t.Payload, &t.Attempts, &t.MaxAttempts, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SetTaskResult stores an intermediate result for a running task (progress).
func (s *Store) SetTaskResult(ctx context.Context, id int64, result []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE task SET result=$2, updated_at=now() WHERE id=$1`, id, result)
	return err
}

// CompleteTask marks a task done with its final result.
func (s *Store) CompleteTask(ctx context.Context, id int64, result []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE task SET status='done', result=$2, locked_at=NULL, locked_by=NULL, updated_at=now() WHERE id=$1`,
		id, result)
	return err
}

// RescheduleTask puts a task back on the queue to retry at runAt.
func (s *Store) RescheduleTask(ctx context.Context, id int64, runAt time.Time, lastErr string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE task SET status='queued', run_at=$2, error=$3, locked_at=NULL, locked_by=NULL, updated_at=now() WHERE id=$1`,
		id, runAt, lastErr)
	return err
}

// FailTask marks a task permanently failed.
func (s *Store) FailTask(ctx context.Context, id int64, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE task SET status='error', error=$2, locked_at=NULL, locked_by=NULL, updated_at=now() WHERE id=$1`,
		id, errMsg)
	return err
}

// GetTask returns one task by id.
func (s *Store) GetTask(ctx context.Context, id int64) (*Task, error) {
	var t Task
	var errText *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, type, payload, status, attempts, max_attempts, result, error, created_at, updated_at FROM task WHERE id=$1`, id).
		Scan(&t.ID, &t.Type, &t.Payload, &t.Status, &t.Attempts, &t.MaxAttempts, &t.Result, &errText, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if errText != nil {
		t.Error = *errText
	}
	return &t, nil
}

// ReapTasks deletes finished tasks older than cutoff and recovers tasks stuck
// in 'running' past staleness (e.g. a worker crashed) back to 'queued'.
func (s *Store) ReapTasks(ctx context.Context, doneBefore, staleRunning time.Time) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM task WHERE status IN ('done','error') AND updated_at < $1`, doneBefore); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE task SET status='queued', locked_at=NULL, locked_by=NULL, updated_at=now()
		 WHERE status='running' AND locked_at < $1`, staleRunning)
	return err
}
