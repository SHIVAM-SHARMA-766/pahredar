package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SyncCursor returns a source's stored cursor; found is false if the source
// has never completed a run.
func (s *Store) SyncCursor(ctx context.Context, source string) (cursor string, found bool, err error) {
	var c *string
	err = s.pool.QueryRow(ctx, `SELECT cursor FROM sync_state WHERE source = $1`, source).Scan(&c)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && c == nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return *c, true, nil
}

func (s *Store) SetSyncCursor(ctx context.Context, source, cursor string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sync_state (source, cursor) VALUES ($1, $2)
		ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor`, source, cursor)
	return err
}

func (s *Store) StartRun(ctx context.Context, source, kind string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sync_run (source, kind, status) VALUES ($1, $2, 'running') RETURNING id`,
		source, kind).Scan(&id)
	return id, err
}

// FinishRun records a run's outcome; on success it also stamps
// sync_state.last_success_at.
func (s *Store) FinishRun(ctx context.Context, id int64, source string, inserted, updated, deleted int, runErr error) error {
	status, errText := "success", (*string)(nil)
	if runErr != nil {
		status = "failed"
		msg := runErr.Error()
		errText = &msg
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE sync_run SET status = $2, finished_at = now(), inserted = $3, updated = $4, deleted = $5, error = $6
		WHERE id = $1`, id, status, inserted, updated, deleted, errText); err != nil {
		return err
	}
	if runErr == nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sync_state (source, last_success_at) VALUES ($1, now())
			ON CONFLICT (source) DO UPDATE SET last_success_at = now()`, source); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// FailStaleRuns marks a source's runs left 'running' by a process that died
// mid-run as failed. Call only while holding the source's sync lock, which
// guarantees no live run exists.
func (s *Store) FailStaleRuns(ctx context.Context, source string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sync_run SET status = 'failed', finished_at = now(), error = 'interrupted: process exited during run'
		WHERE source = $1 AND status = 'running'`, source)
	return tag.RowsAffected(), err
}

type SyncState struct {
	Source        string     `json:"source"`
	Cursor        *string    `json:"cursor"`
	LastSuccessAt *time.Time `json:"last_success_at"`
}

type SyncRun struct {
	ID         int64      `json:"id"`
	Source     string     `json:"source"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Inserted   int        `json:"inserted"`
	Updated    int        `json:"updated"`
	Deleted    int        `json:"deleted"`
	Error      *string    `json:"error"`
}

func (s *Store) SyncStates(ctx context.Context) ([]SyncState, error) {
	rows, err := s.pool.Query(ctx, `SELECT source, cursor, last_success_at FROM sync_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SyncState])
}

func (s *Store) RecentRuns(ctx context.Context, limit int) ([]SyncRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, source, kind, status, started_at, finished_at, inserted, updated, deleted, error
		FROM sync_run ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SyncRun])
}
