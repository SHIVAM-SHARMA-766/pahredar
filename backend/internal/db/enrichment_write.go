package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// minKeepRatio guards snapshot replaces: a feed that shrinks below this
// fraction of the stored rows is assumed broken (truncated download, format
// change) and is rejected instead of deleting most of the table.
const minKeepRatio = 0.5

type KEVRow struct {
	CVEID              string
	VendorProject      string
	Product            string
	VulnerabilityName  string
	ShortDescription   string
	RequiredAction     string
	DateAdded          time.Time
	DueDate            *time.Time
	KnownRansomwareUse string
	ForensicTriage     string
	Notes              string
}

var kevColumns = []string{
	"cve_id", "vendor_project", "product", "vulnerability_name", "short_description",
	"required_action", "date_added", "due_date", "known_ransomware_use", "forensic_triage", "notes",
}

// ReplaceKEV makes the kev table equal to rows.
func (s *Store) ReplaceKEV(ctx context.Context, rows []KEVRow) (inserted, updated, deleted int, err error) {
	data := make([][]any, len(rows))
	for i, r := range rows {
		data[i] = []any{r.CVEID, r.VendorProject, r.Product, r.VulnerabilityName, r.ShortDescription,
			r.RequiredAction, r.DateAdded, r.DueDate, r.KnownRansomwareUse, r.ForensicTriage, r.Notes}
	}
	return s.replaceSnapshot(ctx, snapshot{
		table: "kev", columns: kevColumns, key: []string{"cve_id"}, rows: data,
	})
}

type ExploitRow struct {
	CVEID       string
	SourceRef   string
	Title       string
	URL         string
	PublishedAt *time.Time
}

// ReplaceExploits makes the exploit rows for one source equal to rows.
// Duplicate (source_ref, cve_id) pairs are dropped.
func (s *Store) ReplaceExploits(ctx context.Context, source string, rows []ExploitRow) (inserted, updated, deleted int, err error) {
	seen := map[[2]string]bool{}
	data := make([][]any, 0, len(rows))
	for _, r := range rows {
		k := [2]string{r.SourceRef, r.CVEID}
		if seen[k] {
			continue
		}
		seen[k] = true
		data = append(data, []any{source, r.SourceRef, r.CVEID, r.Title, r.URL, r.PublishedAt})
	}
	return s.replaceSnapshot(ctx, snapshot{
		table:   "exploit",
		columns: []string{"source", "source_ref", "cve_id", "title", "url", "published_at"},
		key:     []string{"source", "source_ref", "cve_id"},
		scope:   "source", scopeValue: source,
		rows: data,
	})
}

// snapshot describes a full replace of a table, or of the rows of a table
// whose scope column equals scopeValue.
type snapshot struct {
	table      string
	columns    []string
	key        []string
	scope      string
	scopeValue any
	rows       [][]any
}

func (s *Store) replaceSnapshot(ctx context.Context, sn snapshot) (inserted, updated, deleted int, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback(ctx)

	scopeSQL, scopeArgs := "", []any{}
	if sn.scope != "" {
		scopeSQL, scopeArgs = " WHERE "+sn.scope+" = $1", []any{sn.scopeValue}
	}
	var existing int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+sn.table+scopeSQL, scopeArgs...).Scan(&existing); err != nil {
		return 0, 0, 0, err
	}
	if existing > 0 && float64(len(sn.rows)) < float64(existing)*minKeepRatio {
		return 0, 0, 0, fmt.Errorf("refusing to replace %s%s: feed has %d rows, %d stored", sn.table, scopeSQL, len(sn.rows), existing)
	}

	cols := strings.Join(sn.columns, ", ")
	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE stage ON COMMIT DROP AS SELECT "+cols+" FROM "+sn.table+" WITH NO DATA"); err != nil {
		return 0, 0, 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"stage"}, sn.columns, pgx.CopyFromRows(sn.rows)); err != nil {
		return 0, 0, 0, fmt.Errorf("copy %s stage: %w", sn.table, err)
	}

	var nonKey, sets, old, neu []string
	for _, c := range sn.columns {
		if !containsStr(sn.key, c) {
			nonKey = append(nonKey, c)
			sets = append(sets, c+" = EXCLUDED."+c)
			old = append(old, sn.table+"."+c)
			neu = append(neu, "EXCLUDED."+c)
		}
	}
	keys := strings.Join(sn.key, ", ")
	res, err := tx.Query(ctx, fmt.Sprintf(`
		INSERT INTO %s (%s) SELECT %s FROM stage
		ON CONFLICT (%s) DO UPDATE SET %s
		WHERE (%s) IS DISTINCT FROM (%s)
		RETURNING (xmax = 0)`,
		sn.table, cols, cols, keys, strings.Join(sets, ", "), strings.Join(old, ", "), strings.Join(neu, ", ")))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("upsert %s: %w", sn.table, err)
	}
	for res.Next() {
		var isInsert bool
		if err := res.Scan(&isInsert); err != nil {
			res.Close()
			return 0, 0, 0, err
		}
		if isInsert {
			inserted++
		} else {
			updated++
		}
	}
	if err := res.Err(); err != nil {
		return 0, 0, 0, fmt.Errorf("upsert %s: %w", sn.table, err)
	}

	del := fmt.Sprintf("DELETE FROM %s t WHERE NOT EXISTS (SELECT 1 FROM stage s WHERE (%s) = (%s))",
		sn.table, prefixed("s.", sn.key), prefixed("t.", sn.key))
	if sn.scope != "" {
		del += " AND t." + sn.scope + " = $1"
	}
	tag, err := tx.Exec(ctx, del, scopeArgs...)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("delete stale %s: %w", sn.table, err)
	}
	return inserted, updated, int(tag.RowsAffected()), tx.Commit(ctx)
}

type EPSSRow struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// ReplaceEPSS replaces the current scores with one day's snapshot and appends
// a history row for every CVE whose score moved by at least
// historyThreshold since its last history row (or that has none yet).
func (s *Store) ReplaceEPSS(ctx context.Context, scoreDate time.Time, rows []EPSSRow) (current, history int, err error) {
	const historyThreshold = 0.01

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	var existing int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM epss").Scan(&existing); err != nil {
		return 0, 0, err
	}
	if existing > 0 && float64(len(rows)) < float64(existing)*minKeepRatio {
		return 0, 0, fmt.Errorf("refusing to replace epss: feed has %d rows, %d stored", len(rows), existing)
	}

	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE stage_epss (cve_id text PRIMARY KEY, score numeric(6,5), percentile numeric(6,5)) ON COMMIT DROP"); err != nil {
		return 0, 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"stage_epss"}, []string{"cve_id", "score", "percentile"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			return []any{rows[i].CVEID, rows[i].Score, rows[i].Percentile}, nil
		})); err != nil {
		return 0, 0, fmt.Errorf("copy epss stage: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO epss_history (cve_id, score_date, score, percentile)
		SELECT s.cve_id, $1, s.score, s.percentile
		FROM stage_epss s
		LEFT JOIN LATERAL (
			SELECT h.score FROM epss_history h WHERE h.cve_id = s.cve_id ORDER BY h.score_date DESC LIMIT 1
		) last ON true
		WHERE last.score IS NULL OR abs(s.score - last.score) >= $2
		ON CONFLICT (cve_id, score_date) DO NOTHING`, scoreDate, historyThreshold)
	if err != nil {
		return 0, 0, fmt.Errorf("append epss history: %w", err)
	}
	history = int(tag.RowsAffected())

	// TRUNCATE + INSERT is far cheaper than updating ~400k rows; readers
	// block only for the length of this transaction.
	if _, err := tx.Exec(ctx, "TRUNCATE epss"); err != nil {
		return 0, 0, err
	}
	tag, err = tx.Exec(ctx, "INSERT INTO epss (cve_id, score, percentile, score_date) SELECT cve_id, score, percentile, $1 FROM stage_epss", scoreDate)
	if err != nil {
		return 0, 0, fmt.Errorf("load epss: %w", err)
	}
	return int(tag.RowsAffected()), history, tx.Commit(ctx)
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func prefixed(prefix string, cols []string) string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = prefix + c
	}
	return strings.Join(out, ", ")
}
