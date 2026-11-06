package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Alert is one notification about a tracked asset.
type Alert struct {
	ID        int64      `json:"id"`
	Type      string     `json:"type"`
	AssetID   *int64     `json:"asset_id,omitempty"`
	CVEID     string     `json:"cve_id,omitempty"`
	Severity  string     `json:"severity"`
	Title     string     `json:"title"`
	Detail    string     `json:"detail,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
	// AssetValue is joined for display.
	AssetValue string `json:"asset_value,omitempty"`
}

// GenerateKEVAlerts raises an alert for every (asset, CVE) pair where the CVE
// matched to the asset is in the CISA KEV catalog and no such alert exists yet.
// Returns the new alerts. This is the "a new KEV matches your asset" trigger;
// it is safe to run repeatedly (deduped on type+asset+cve).
func (s *Store) GenerateKEVAlerts(ctx context.Context) ([]Alert, error) {
	return s.genAlerts(ctx, `
		INSERT INTO alert (type, asset_id, cve_id, severity, title, detail)
		SELECT DISTINCT 'kev_match', at.asset_id, ca.cve_id, 'high',
		       'Known-exploited CVE on ' || a.value,
		       ca.cve_id || ' affects ' || at.product || ' on ' || a.value || ' and is in the CISA Known Exploited Vulnerabilities catalog — patch urgently.'
		FROM asset_tech at
		JOIN cve_affected ca ON ca.vendor = at.vendor AND ca.product = at.product
		JOIN kev k ON k.cve_id = ca.cve_id
		JOIN asset a ON a.id = at.asset_id
		ON CONFLICT (type, asset_id, cve_id) DO NOTHING
		RETURNING id, type, asset_id, cve_id, severity, title, detail, created_at`)
}

// GenerateEPSSAlerts raises an alert for a CVE affecting an asset's products
// that has a high EPSS exploitation probability but is not yet in KEV — the
// "likely to be exploited soon" signal, deduped.
func (s *Store) GenerateEPSSAlerts(ctx context.Context) ([]Alert, error) {
	return s.genAlerts(ctx, `
		INSERT INTO alert (type, asset_id, cve_id, severity, title, detail)
		SELECT DISTINCT ON (at.asset_id, ca.cve_id) 'epss_high', at.asset_id, ca.cve_id, 'medium',
		       'Likely-exploited CVE on ' || a.value,
		       ca.cve_id || ' affects ' || at.product || ' on ' || a.value || ' and has a high EPSS exploitation probability (' || round(e.score * 100) || '%).'
		FROM asset_tech at
		JOIN cve_affected ca ON ca.vendor = at.vendor AND ca.product = at.product
		JOIN epss e ON e.cve_id = ca.cve_id AND e.score >= 0.5
		LEFT JOIN kev k ON k.cve_id = ca.cve_id
		JOIN asset a ON a.id = at.asset_id
		WHERE k.cve_id IS NULL
		ON CONFLICT (type, asset_id, cve_id) DO NOTHING
		RETURNING id, type, asset_id, cve_id, severity, title, detail, created_at`)
}

// genAlerts runs an INSERT ... RETURNING that yields new alert rows.
func (s *Store) genAlerts(ctx context.Context, query string) ([]Alert, error) {
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.Type, &a.AssetID, &a.CVEID, &a.Severity, &a.Title, &a.Detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAlerts returns alerts newest first; unreadOnly limits to unread.
func (s *Store) ListAlerts(ctx context.Context, unreadOnly bool, limit int) ([]Alert, error) {
	q := `SELECT al.id, al.type, al.asset_id, al.cve_id, al.severity, al.title, al.detail, al.created_at, al.read_at, COALESCE(a.value,'')
		FROM alert al LEFT JOIN asset a ON a.id = al.asset_id`
	if unreadOnly {
		q += ` WHERE al.read_at IS NULL`
	}
	q += ` ORDER BY al.created_at DESC LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var al Alert
		if err := rows.Scan(&al.ID, &al.Type, &al.AssetID, &al.CVEID, &al.Severity, &al.Title, &al.Detail, &al.CreatedAt, &al.ReadAt, &al.AssetValue); err != nil {
			return nil, err
		}
		out = append(out, al)
	}
	return out, rows.Err()
}

// UnreadAlertCount returns how many alerts are unread.
func (s *Store) UnreadAlertCount(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM alert WHERE read_at IS NULL`).Scan(&n)
	return n, err
}

// MarkAlertRead marks one alert read (or all when id is 0).
func (s *Store) MarkAlertRead(ctx context.Context, id int64) error {
	if id == 0 {
		_, err := s.pool.Exec(ctx, `UPDATE alert SET read_at = now() WHERE read_at IS NULL`)
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE alert SET read_at = now() WHERE id = $1 AND read_at IS NULL`, id)
	return err
}

// InsertAlerts inserts each alert (deduped on type+asset+cve) and returns the
// ones newly created. Used for scan-triggered alerts (e.g. critical findings).
func (s *Store) InsertAlerts(ctx context.Context, alerts []Alert) ([]Alert, error) {
	out := []Alert{}
	for _, al := range alerts {
		var a Alert
		err := s.pool.QueryRow(ctx, `
			INSERT INTO alert (type, asset_id, cve_id, severity, title, detail)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (type, asset_id, cve_id) DO NOTHING
			RETURNING id, type, asset_id, cve_id, severity, title, detail, created_at`,
			al.Type, al.AssetID, al.CVEID, al.Severity, al.Title, al.Detail).
			Scan(&a.ID, &a.Type, &a.AssetID, &a.CVEID, &a.Severity, &a.Title, &a.Detail, &a.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // already existed
		}
		if err != nil {
			return out, err
		}
		out = append(out, a)
	}
	return out, nil
}

// PendingAlerts returns alerts not yet delivered to the webhook, oldest first.
func (s *Store) PendingAlerts(ctx context.Context, limit int) ([]Alert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, type, asset_id, cve_id, severity, title, detail, created_at
		FROM alert WHERE delivered_at IS NULL ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.Type, &a.AssetID, &a.CVEID, &a.Severity, &a.Title, &a.Detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkAlertsDelivered stamps the given alerts delivered.
func (s *Store) MarkAlertsDelivered(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `UPDATE alert SET delivered_at = now() WHERE id = ANY($1)`, ids)
	return err
}
