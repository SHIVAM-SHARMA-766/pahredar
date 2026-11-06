package db

import (
	"context"
	"time"
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
// Returns the number of new alerts. This is the "a new KEV matches your asset"
// trigger; it is safe to run repeatedly (deduped on type+asset+cve).
func (s *Store) GenerateKEVAlerts(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `
		INSERT INTO alert (type, asset_id, cve_id, severity, title, detail)
		SELECT 'kev_match', ac.asset_id, ac.cve_id, 'high',
		       'Known-exploited CVE on ' || a.value,
		       ac.cve_id || ' matched on ' || a.value || ' is in the CISA Known Exploited Vulnerabilities catalog — patch urgently.'
		FROM asset_cve ac
		JOIN kev k ON k.cve_id = ac.cve_id
		JOIN asset a ON a.id = ac.asset_id
		ON CONFLICT (type, asset_id, cve_id) DO NOTHING
		RETURNING id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
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
