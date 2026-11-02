package db

import (
	"context"
	"encoding/json"
	"time"
)

// CachedReport is one external_report row.
type CachedReport struct {
	Source    string
	Status    string // ok, not_found
	FetchedAt time.Time
	Payload   json.RawMessage
}

func (s *Store) CachedReports(ctx context.Context, cveID string) (map[string]CachedReport, error) {
	rows, err := s.pool.Query(ctx, `SELECT source, status, fetched_at, payload FROM external_report WHERE cve_id = $1`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CachedReport{}
	for rows.Next() {
		var r CachedReport
		if err := rows.Scan(&r.Source, &r.Status, &r.FetchedAt, &r.Payload); err != nil {
			return nil, err
		}
		out[r.Source] = r
	}
	return out, rows.Err()
}

func (s *Store) SaveReport(ctx context.Context, cveID, source, status string, payload []byte) error {
	var p any
	if payload != nil {
		p = string(payload)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO external_report (cve_id, source, status, fetched_at, payload) VALUES ($1, $2, $3, now(), $4)
		ON CONFLICT (cve_id, source) DO UPDATE SET status = EXCLUDED.status, fetched_at = now(), payload = EXCLUDED.payload`,
		cveID, source, status, p)
	return err
}

// CVEExists reports whether a CVE ID is stored.
func (s *Store) CVEExists(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cve WHERE id = $1)`, id).Scan(&ok)
	return ok, err
}
