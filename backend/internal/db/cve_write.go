package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExistingCVE is the stored state a writer needs to merge an incoming record.
type ExistingCVE struct {
	DateUpdated     *time.Time
	NVDLastModified *time.Time
	RawCvelist      []byte
	RawNVD          []byte
}

// CVERow is a fully derived cve row plus its affected products.
type CVERow struct {
	ID              string
	State           string
	Assigner        *string
	DateReserved    *time.Time
	DatePublished   *time.Time
	DateUpdated     *time.Time
	Title           *string
	Description     *string
	CWEIDs          []string
	CVSSv4Score     *float64
	CVSSv4Vector    *string
	CVSSv3Score     *float64
	CVSSv3Vector    *string
	CVSSv2Score     *float64
	CVSSv2Vector    *string
	Severity        string
	SeveritySource  *string
	NVDStatus       *string
	NVDLastModified *time.Time
	Refs            []byte
	ExploitRef      bool
	RawCvelist      []byte
	RawNVD          []byte
	// SearchText is extra text for the full-text index (vendor/product names).
	SearchText string
	Affected   []AffectedRow
}

type AffectedRow struct {
	Source       string
	Vendor       string
	Product      string
	VendorLabel  string
	ProductLabel string
	CPEs         []string
	Versions     []byte
}

var cveColumns = []string{
	"id", "state", "assigner", "date_reserved", "date_published", "date_updated",
	"title", "description", "cwe_ids",
	"cvss_v4_score", "cvss_v4_vector", "cvss_v3_score", "cvss_v3_vector", "cvss_v2_score", "cvss_v2_vector",
	"severity", "severity_source", "nvd_status", "nvd_last_modified",
	"refs", "exploit_ref", "raw_cvelist", "raw_nvd",
}

const searchExpr = `setweight(to_tsvector('simple', id), 'A') ||
	setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
	setweight(to_tsvector('english', coalesce(description, '')), 'B') ||
	setweight(to_tsvector('english', coalesce(search_text, '')), 'C')`

// WriteCVEBatch upserts CVE rows. It locks the existing rows for ids, passes
// their state to build, and writes whatever build returns, replacing each
// written CVE's affected rows. A transaction-scoped advisory lock serialises
// all CVE writers (cvelist and NVD sync) so neither derives from stale data.
func (s *Store) WriteCVEBatch(ctx context.Context, ids []string, build func(map[string]ExistingCVE) ([]CVERow, error)) (inserted, updated int, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('pahredar:cve-write'))`); err != nil {
		return 0, 0, err
	}

	existing := make(map[string]ExistingCVE, len(ids))
	rows, err := tx.Query(ctx, `SELECT id, date_updated, nvd_last_modified, raw_cvelist, raw_nvd FROM cve WHERE id = ANY($1) FOR UPDATE`, ids)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var id string
		var e ExistingCVE
		if err := rows.Scan(&id, &e.DateUpdated, &e.NVDLastModified, &e.RawCvelist, &e.RawNVD); err != nil {
			rows.Close()
			return 0, 0, err
		}
		existing[id] = e
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	out, err := build(existing)
	if err != nil {
		return 0, 0, err
	}
	if len(out) == 0 {
		return 0, 0, tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE stage_cve ON COMMIT DROP AS
		SELECT `+strings.Join(cveColumns, ", ")+`, ''::text AS search_text FROM cve WITH NO DATA`); err != nil {
		return 0, 0, fmt.Errorf("create stage table: %w", err)
	}
	stageCols := append(append([]string{}, cveColumns...), "search_text")
	written := make([]string, len(out))
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"stage_cve"}, stageCols, pgx.CopyFromSlice(len(out), func(i int) ([]any, error) {
		r := out[i]
		written[i] = r.ID
		return []any{
			r.ID, r.State, r.Assigner, r.DateReserved, r.DatePublished, r.DateUpdated,
			r.Title, r.Description, r.CWEIDs,
			r.CVSSv4Score, r.CVSSv4Vector, r.CVSSv3Score, r.CVSSv3Vector, r.CVSSv2Score, r.CVSSv2Vector,
			r.Severity, r.SeveritySource, r.NVDStatus, r.NVDLastModified,
			string(r.Refs), r.ExploitRef, nullJSON(r.RawCvelist), nullJSON(r.RawNVD), r.SearchText,
		}, nil
	})); err != nil {
		return 0, 0, fmt.Errorf("copy stage rows: %w", err)
	}

	var updates []string
	for _, c := range cveColumns[1:] {
		updates = append(updates, c+" = EXCLUDED."+c)
	}
	cols := strings.Join(cveColumns, ", ")
	results, err := tx.Query(ctx, `
		INSERT INTO cve (`+cols+`, search, updated_at)
		SELECT `+cols+`, `+searchExpr+`, now() FROM stage_cve
		ON CONFLICT (id) DO UPDATE SET `+strings.Join(updates, ", ")+`, search = EXCLUDED.search, updated_at = now()
		RETURNING (xmax = 0)`)
	if err != nil {
		return 0, 0, fmt.Errorf("upsert cve: %w", err)
	}
	for results.Next() {
		var isInsert bool
		if err := results.Scan(&isInsert); err != nil {
			results.Close()
			return 0, 0, err
		}
		if isInsert {
			inserted++
		} else {
			updated++
		}
	}
	if err := results.Err(); err != nil {
		return 0, 0, fmt.Errorf("upsert cve: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM cve_affected WHERE cve_id = ANY($1)`, written); err != nil {
		return 0, 0, err
	}
	var affected [][]any
	for _, r := range out {
		for _, a := range r.Affected {
			cpes := a.CPEs
			if cpes == nil {
				cpes = []string{}
			}
			affected = append(affected, []any{r.ID, a.Source, a.Vendor, a.Product, a.VendorLabel, a.ProductLabel, cpes, string(a.Versions)})
		}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_affected"},
		[]string{"cve_id", "source", "vendor", "product", "vendor_label", "product_label", "cpes", "versions"}, pgx.CopyFromRows(affected)); err != nil {
		return 0, 0, fmt.Errorf("copy affected rows: %w", err)
	}

	return inserted, updated, tx.Commit(ctx)
}

// nullJSON maps an empty document to SQL NULL.
func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// CVEIDsAfter returns up to limit CVE IDs greater than after, in order, for
// walking the whole table in batches.
func (s *Store) CVEIDsAfter(ctx context.Context, after string, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM cve WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
