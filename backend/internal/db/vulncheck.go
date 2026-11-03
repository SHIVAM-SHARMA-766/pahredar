package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// VulnCheck KEV snapshot writer and per-CVE reader (migration 00013).

type VulnCheckRow struct {
	CVEID, Name, Vendor, Product string
	DateAdded                    *time.Time
	Ransomware, Canary           bool
	// Reported and XDB are JSON-encodable lists.
	Reported, XDB any
}

func (s *Store) ReplaceVulnCheckKEV(ctx context.Context, rows []VulnCheckRow) (inserted, updated, deleted int, err error) {
	seen := map[string]bool{}
	data := make([][]any, 0, len(rows))
	for _, r := range rows {
		if seen[r.CVEID] {
			continue
		}
		seen[r.CVEID] = true
		data = append(data, []any{r.CVEID, nilIfEmpty(r.Name), nilIfEmpty(r.Vendor), nilIfEmpty(r.Product), r.DateAdded,
			r.Ransomware, r.Canary, r.Reported, r.XDB})
	}
	return s.replaceSnapshot(ctx, snapshot{
		table:   "vulncheck_kev",
		columns: []string{"cve_id", "name", "vendor", "product", "date_added", "ransomware", "canary", "reported", "xdb"},
		key:     []string{"cve_id"}, rows: data,
	})
}

type VulnCheckOut struct {
	Name       *string         `json:"name"`
	DateAdded  *time.Time      `json:"date_added"`
	Ransomware bool            `json:"ransomware"`
	Canary     bool            `json:"canary"`
	Reported   json.RawMessage `json:"reported"`
	XDB        json.RawMessage `json:"xdb"`
}

func (s *Store) readVulnCheck(ctx context.Context, d *CVEDetail) error {
	var v VulnCheckOut
	err := s.pool.QueryRow(ctx, `SELECT name, date_added, ransomware, canary, reported, xdb FROM vulncheck_kev WHERE cve_id = $1`, d.ID).
		Scan(&v.Name, &v.DateAdded, &v.Ransomware, &v.Canary, &v.Reported, &v.XDB)
	switch {
	case err == nil:
		d.VulnCheck = &v
	case err != pgx.ErrNoRows:
		return err
	}
	return nil
}
