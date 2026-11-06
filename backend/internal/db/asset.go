package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Asset is one tracked target (domain, URL, IP, product, or repo).
type Asset struct {
	ID            int64      `json:"id"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	Label         string     `json:"label"`
	Tags          []string   `json:"tags"`
	LastScanID    *int64     `json:"last_scan_id,omitempty"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	// LastGrade/LastScore are joined from the latest scan when available.
	LastGrade string `json:"last_grade,omitempty"`
	LastScore *int   `json:"last_score,omitempty"`
	// CVECount/KEVCount summarise the CVEs matched to the asset.
	CVECount int `json:"cve_count"`
	KEVCount int `json:"kev_count"`
}

// CreateAsset inserts an asset (idempotent on kind+value: returns the existing
// one's id if it already exists).
func (s *Store) CreateAsset(ctx context.Context, kind, value, label string, tags []string) (int64, error) {
	if tags == nil {
		tags = []string{}
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO asset (kind, value, label, tags) VALUES ($1, $2, $3, $4)
		ON CONFLICT (kind, value) DO UPDATE SET label = EXCLUDED.label, tags = EXCLUDED.tags
		RETURNING id`, kind, value, label, tags).Scan(&id)
	return id, err
}

// ListAssets returns all assets, newest first, with the latest scan's grade.
func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.kind, a.value, a.label, a.tags, a.last_scan_id, a.last_scanned_at, a.created_at,
		       sc.grade, sc.score,
		       COALESCE(ac.cve_count, 0), COALESCE(ac.kev_count, 0)
		FROM asset a
		LEFT JOIN scan sc ON sc.id = a.last_scan_id
		LEFT JOIN (SELECT asset_id, count(*) AS cve_count, count(*) FILTER (WHERE kev) AS kev_count FROM asset_cve GROUP BY asset_id) ac ON ac.asset_id = a.id
		ORDER BY a.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		var a Asset
		var grade *string
		if err := rows.Scan(&a.ID, &a.Kind, &a.Value, &a.Label, &a.Tags, &a.LastScanID, &a.LastScannedAt, &a.CreatedAt, &grade, &a.LastScore, &a.CVECount, &a.KEVCount); err != nil {
			return nil, err
		}
		if grade != nil {
			a.LastGrade = *grade
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAsset returns one asset by id.
func (s *Store) GetAsset(ctx context.Context, id int64) (*Asset, error) {
	var a Asset
	var grade *string
	err := s.pool.QueryRow(ctx, `
		SELECT a.id, a.kind, a.value, a.label, a.tags, a.last_scan_id, a.last_scanned_at, a.created_at, sc.grade, sc.score,
		       (SELECT count(*) FROM asset_cve WHERE asset_id = a.id),
		       (SELECT count(*) FROM asset_cve WHERE asset_id = a.id AND kev)
		FROM asset a LEFT JOIN scan sc ON sc.id = a.last_scan_id
		WHERE a.id = $1`, id).
		Scan(&a.ID, &a.Kind, &a.Value, &a.Label, &a.Tags, &a.LastScanID, &a.LastScannedAt, &a.CreatedAt, &grade, &a.LastScore, &a.CVECount, &a.KEVCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if grade != nil {
		a.LastGrade = *grade
	}
	return &a, nil
}

// DeleteAsset removes an asset.
func (s *Store) DeleteAsset(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM asset WHERE id = $1`, id)
	return err
}

// LinkAssetScan records scanID as asset assetID's latest scan and tags the
// scan row with the asset, so the asset's scan history can be queried.
func (s *Store) LinkAssetScan(ctx context.Context, assetID, scanID int64) error {
	if _, err := s.pool.Exec(ctx, `UPDATE scan SET asset_id = $1 WHERE id = $2`, assetID, scanID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE asset SET last_scan_id = $2, last_scanned_at = now() WHERE id = $1`, assetID, scanID)
	return err
}

// AssetScans returns an asset's scan history, newest first.
func (s *Store) AssetScans(ctx context.Context, assetID int64, limit int) ([]ScanSummary, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target, host, grade, score, created_at FROM scan WHERE asset_id = $1 ORDER BY created_at DESC LIMIT $2`,
		assetID, limit)
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

// AssetCVE is a CVE matched to an asset.
type AssetCVE struct {
	CVEID     string    `json:"cve_id"`
	Product   string    `json:"product"`
	KEV       bool      `json:"kev"`
	FirstSeen time.Time `json:"first_seen"`
}

// ReplaceAssetCVEs sets the asset's matched CVEs to the given set (keeping
// first_seen for ones already present), and removes ones no longer matched.
func (s *Store) ReplaceAssetCVEs(ctx context.Context, assetID int64, cves []AssetCVE) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ids := make([]string, len(cves))
	for i, c := range cves {
		ids[i] = c.CVEID
	}
	// Remove ones no longer matched.
	if _, err := tx.Exec(ctx, `DELETE FROM asset_cve WHERE asset_id = $1 AND NOT (cve_id = ANY($2))`, assetID, ids); err != nil {
		return err
	}
	for _, c := range cves {
		if _, err := tx.Exec(ctx, `
			INSERT INTO asset_cve (asset_id, cve_id, product, kev) VALUES ($1, $2, $3, $4)
			ON CONFLICT (asset_id, cve_id) DO UPDATE SET product = EXCLUDED.product, kev = EXCLUDED.kev`,
			assetID, c.CVEID, c.Product, c.KEV); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AssetCVEs returns the CVEs matched to an asset, KEV first.
func (s *Store) AssetCVEs(ctx context.Context, assetID int64) ([]AssetCVE, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT cve_id, product, kev, first_seen FROM asset_cve WHERE asset_id = $1 ORDER BY kev DESC, cve_id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetCVE{}
	for rows.Next() {
		var c AssetCVE
		if err := rows.Scan(&c.CVEID, &c.Product, &c.KEV, &c.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AssetsForCVE returns the assets matched to a CVE (the reverse lookup that
// alerting uses).
func (s *Store) AssetsForCVE(ctx context.Context, cveID string) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.kind, a.value, a.label, a.tags, a.last_scan_id, a.last_scanned_at, a.created_at
		FROM asset a JOIN asset_cve ac ON ac.asset_id = a.id
		WHERE ac.cve_id = $1 ORDER BY a.value`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Kind, &a.Value, &a.Label, &a.Tags, &a.LastScanID, &a.LastScannedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AssetsDueForRescan returns scannable assets not scanned since before (or never).
func (s *Store) AssetsDueForRescan(ctx context.Context, before time.Time) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, value, label, tags, last_scan_id, last_scanned_at, created_at
		FROM asset
		WHERE kind IN ('domain','url','ip') AND (last_scanned_at IS NULL OR last_scanned_at < $1)
		ORDER BY last_scanned_at NULLS FIRST`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Kind, &a.Value, &a.Label, &a.Tags, &a.LastScanID, &a.LastScannedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AssetTech is a product fingerprinted on an asset.
type AssetTech struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// ReplaceAssetTech sets the asset's fingerprinted products to the given set.
func (s *Store) ReplaceAssetTech(ctx context.Context, assetID int64, techs []AssetTech) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM asset_tech WHERE asset_id = $1`, assetID); err != nil {
		return err
	}
	for _, t := range techs {
		if t.Vendor == "" || t.Product == "" {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO asset_tech (asset_id, vendor, product, version) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (asset_id, vendor, product) DO UPDATE SET version = EXCLUDED.version`,
			assetID, t.Vendor, t.Product, t.Version); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
