package db

import (
	"context"
	"encoding/json"
	"time"
)

// CVEsCitingURL returns CVEs (other than exclude) whose references include
// url, newest first, and how many there are in total. Backed by the
// jsonb_path_ops index on cve.refs.
func (s *Store) CVEsCitingURL(ctx context.Context, url, exclude string, limit int) ([]string, int, error) {
	probe, err := json.Marshal([]map[string]string{{"url": url}})
	if err != nil {
		return nil, 0, err
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM cve WHERE refs @> $1::jsonb AND id <> $2`, string(probe), exclude).Scan(&total); err != nil {
		return nil, 0, err
	}
	ids, err := s.ids(ctx, `SELECT id FROM cve WHERE refs @> $1::jsonb AND id <> $2
		ORDER BY COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) DESC NULLS LAST, date_published DESC LIMIT $3`,
		string(probe), exclude, limit)
	return ids, total, err
}

// CVEsForProductNear returns CVEs (other than exclude) affecting
// vendor/product and published within days of around, most severe first,
// and the total count.
func (s *Store) CVEsForProductNear(ctx context.Context, vendor, product string, around time.Time, days int, exclude string, limit int) ([]string, int, error) {
	from, to := around.AddDate(0, 0, -days), around.AddDate(0, 0, days)
	const where = `FROM cve c WHERE c.id <> $3 AND c.date_published BETWEEN $4 AND $5
		AND EXISTS (SELECT 1 FROM cve_affected a WHERE a.cve_id = c.id AND a.vendor = $1 AND a.product = $2)`
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) `+where, vendor, product, exclude, from, to).Scan(&total); err != nil {
		return nil, 0, err
	}
	ids, err := s.ids(ctx, `SELECT c.id `+where+`
		ORDER BY COALESCE(c.cvss_v4_score, c.cvss_v3_score, c.cvss_v2_score) DESC NULLS LAST, c.date_published DESC LIMIT $6`,
		vendor, product, exclude, from, to, limit)
	return ids, total, err
}

func (s *Store) ids(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
