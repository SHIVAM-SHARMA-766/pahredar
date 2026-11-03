package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

// MatchTech returns the CVE counts Pahredar has for a fingerprinted product,
// preferring the vendor hint, else the vendor with the most CVEs. It is
// product-level, not matched to the detected version.
func (s *Store) MatchTech(ctx context.Context, vendor, product string) (*scan.TechCVEs, error) {
	var out scan.TechCVEs
	err := s.pool.QueryRow(ctx, `
		SELECT vendor, product, cves, kev, critical FROM product_stats
		WHERE product = $2
		ORDER BY (vendor = $1) DESC, cves DESC LIMIT 1`, vendor, product).
		Scan(&out.Vendor, &out.Product, &out.Total, &out.KEV, &out.Critical)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.severity, (k.cve_id IS NOT NULL)
		FROM cve_affected a JOIN cve c ON c.id = a.cve_id AND c.state = 'PUBLISHED'
		LEFT JOIN kev k ON k.cve_id = c.id
		WHERE a.vendor = $1 AND a.product = $2
		ORDER BY (k.cve_id IS NOT NULL) DESC, (c.severity = 'CRITICAL') DESC, c.date_published DESC NULLS LAST
		LIMIT 6`, out.Vendor, out.Product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out.Examples = []scan.TechCVE{}
	for rows.Next() {
		var e scan.TechCVE
		if err := rows.Scan(&e.ID, &e.Severity, &e.KEV); err != nil {
			return nil, err
		}
		out.Examples = append(out.Examples, e)
	}
	return &out, rows.Err()
}

// SaveScan stores a report and returns its id.
func (s *Store) SaveScan(ctx context.Context, rep *scan.Report) (int64, error) {
	payload, err := json.Marshal(rep)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO scan (target, host, grade, score, report) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		rep.Target, rep.Host, rep.Grade, rep.Score, payload).Scan(&id)
	return id, err
}

type ScanSummary struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	Grade     string    `json:"grade"`
	Score     int       `json:"score"`
	CreatedAt time.Time `json:"created_at"`
}

// RecentScans lists the newest scans.
func (s *Store) RecentScans(ctx context.Context, limit int) ([]ScanSummary, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, target, host, grade, score, created_at FROM scan ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanSummary{}
	for rows.Next() {
		var x ScanSummary
		if err := rows.Scan(&x.ID, &x.Target, &x.Host, &x.Grade, &x.Score, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// GetScan returns one stored report as raw JSON, with its age.
func (s *Store) GetScan(ctx context.Context, id int64) (json.RawMessage, time.Time, error) {
	var payload json.RawMessage
	var at time.Time
	err := s.pool.QueryRow(ctx, `SELECT report, created_at FROM scan WHERE id = $1`, id).Scan(&payload, &at)
	return payload, at, err
}

// LatestScanFor returns the most recent scan of a host newer than cutoff,
// so a repeated request reuses it instead of re-scanning.
func (s *Store) LatestScanFor(ctx context.Context, host string, cutoff time.Time) (int64, json.RawMessage, bool, error) {
	var id int64
	var payload json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT id, report FROM scan WHERE host = $1 AND created_at >= $2 ORDER BY created_at DESC LIMIT 1`, host, cutoff).Scan(&id, &payload)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil, false, nil
	case err != nil:
		return 0, nil, false, err
	}
	return id, payload, true, nil
}
