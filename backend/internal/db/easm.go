package db

import (
	"context"
	"encoding/json"
	"time"
)

// ScanRun is one EASM scan of an asset. See docs/scanner-easm.md.
type ScanRun struct {
	ID          int64      `json:"id"`
	AssetID     int64      `json:"asset_id"`
	ClientID    *int64     `json:"client_id,omitempty"`
	Profile     string     `json:"profile"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	RecordCount int        `json:"record_count"`
	Error       string     `json:"error,omitempty"`
}

// AssetRecord is one evidence record (observation) about an asset.
type AssetRecord struct {
	ID           int64           `json:"id"`
	AssetID      int64           `json:"asset_id"`
	ClientID     *int64          `json:"client_id,omitempty"`
	RunID        *int64          `json:"run_id,omitempty"`
	Category     string          `json:"category"`
	Key          string          `json:"key"`
	Method       string          `json:"method"`
	Source       string          `json:"source"`
	Data         json.RawMessage `json:"data"`
	Evidence     string          `json:"evidence,omitempty"`
	Confidence   string          `json:"confidence"`
	Verification string          `json:"verification"`
	Scope        string          `json:"scope"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
}

// CreateScanRun opens a scan run and returns its id.
func (s *Store) CreateScanRun(ctx context.Context, assetID int64, clientID *int64, profile string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO scan_run (asset_id, client_id, profile) VALUES ($1, $2, $3) RETURNING id`,
		assetID, clientID, profile).Scan(&id)
	return id, err
}

// FinishScanRun records the outcome of a scan run.
func (s *Store) FinishScanRun(ctx context.Context, runID int64, status string, recordCount int, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_run SET status = $2, record_count = $3, error = $4, finished_at = now()
		WHERE id = $1`, runID, status, recordCount, errMsg)
	return err
}

// UpsertRecord inserts or refreshes an evidence record. Re-observation bumps
// last_seen and updates data/evidence/run_id (history, not overwrite). Returns
// true when the record is newly seen.
func (s *Store) UpsertRecord(ctx context.Context, r AssetRecord) (bool, error) {
	if len(r.Data) == 0 {
		r.Data = json.RawMessage(`{}`)
	}
	if r.Method == "" {
		r.Method = "passive"
	}
	if r.Confidence == "" {
		r.Confidence = "high"
	}
	if r.Verification == "" {
		r.Verification = "unverified"
	}
	if r.Scope == "" {
		r.Scope = "in_scope"
	}
	var inserted bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO asset_record (asset_id, client_id, run_id, category, key, method, source, data, evidence, confidence, verification, scope)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (asset_id, category, key, source) DO UPDATE SET
			last_seen  = now(),
			run_id     = EXCLUDED.run_id,
			data       = EXCLUDED.data,
			evidence   = EXCLUDED.evidence,
			confidence = EXCLUDED.confidence,
			method     = EXCLUDED.method
		RETURNING (xmax = 0)`,
		r.AssetID, r.ClientID, r.RunID, r.Category, r.Key, r.Method, r.Source, r.Data, r.Evidence, r.Confidence, r.Verification, r.Scope).
		Scan(&inserted)
	return inserted, err
}

// ListRecords returns an asset's records, optionally filtered by category,
// newest observation first.
func (s *Store) ListRecords(ctx context.Context, assetID int64, category string) ([]AssetRecord, error) {
	q := `SELECT id, asset_id, client_id, run_id, category, key, method, source, data, evidence,
	             confidence, verification, scope, first_seen, last_seen
	      FROM asset_record WHERE asset_id = $1`
	args := []any{assetID}
	if category != "" {
		q += ` AND category = $2`
		args = append(args, category)
	}
	q += ` ORDER BY category, last_seen DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetRecord{}
	for rows.Next() {
		var r AssetRecord
		if err := rows.Scan(&r.ID, &r.AssetID, &r.ClientID, &r.RunID, &r.Category, &r.Key, &r.Method, &r.Source,
			&r.Data, &r.Evidence, &r.Confidence, &r.Verification, &r.Scope, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssetsDueForEASM returns domain/URL assets whose most recent EASM scan started
// before `before` (or that were never scanned), oldest first, for scheduling.
func (s *Store) AssetsDueForEASM(ctx context.Context, before time.Time, limit int) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.client_id, a.kind, a.value
		FROM asset a
		LEFT JOIN LATERAL (
			SELECT max(started_at) AS last FROM scan_run WHERE asset_id = a.id
		) sr ON true
		WHERE a.kind IN ('domain','url') AND (sr.last IS NULL OR sr.last < $1)
		ORDER BY sr.last NULLS FIRST
		LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.ClientID, &a.Kind, &a.Value); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListScanRuns returns an asset's scan runs, newest first.
func (s *Store) ListScanRuns(ctx context.Context, assetID int64, limit int) ([]ScanRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, asset_id, client_id, profile, status, started_at, finished_at, record_count, error
		FROM scan_run WHERE asset_id = $1 ORDER BY started_at DESC LIMIT $2`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanRun{}
	for rows.Next() {
		var sr ScanRun
		if err := rows.Scan(&sr.ID, &sr.AssetID, &sr.ClientID, &sr.Profile, &sr.Status, &sr.StartedAt, &sr.FinishedAt, &sr.RecordCount, &sr.Error); err != nil {
			return nil, err
		}
		out = append(out, sr)
	}
	return out, rows.Err()
}
