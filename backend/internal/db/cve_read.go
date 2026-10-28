package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ListCVEParams are validated filters for ListCVEs. Zero values mean "no filter".
type ListCVEParams struct {
	ExactID       string
	Text          string
	Severities    []string
	State         string
	Vendor        string
	Product       string
	CWE           string
	PublishedFrom *time.Time
	// PublishedTo is exclusive.
	PublishedTo *time.Time
	// KEV and Exploit are tri-state: nil means no filter.
	KEV     *bool
	Exploit *bool
	EPSSMin *float64
	Sort    string // relevance, published, updated, cvss, epss
	Desc    bool
	Limit   int
	Offset  int
}

type CVESummary struct {
	ID             string     `json:"id"`
	State          string     `json:"state"`
	Assigner       *string    `json:"assigner"`
	Title          *string    `json:"title"`
	Description    *string    `json:"description"`
	Severity       string     `json:"severity"`
	SeveritySource *string    `json:"severity_source"`
	CVSSv4Score    *float64   `json:"cvss_v4_score"`
	CVSSv3Score    *float64   `json:"cvss_v3_score"`
	CVSSv2Score    *float64   `json:"cvss_v2_score"`
	DatePublished  *time.Time `json:"date_published"`
	DateUpdated    *time.Time `json:"date_updated"`
	KEV            bool       `json:"kev"`
	EPSSScore      *float64   `json:"epss_score"`
	EPSSPercentile *float64   `json:"epss_percentile"`
	HasExploit     bool       `json:"has_exploit"`
}

// hasExploitExpr is the "has public exploit" definition (ARCHITECTURE.md §6).
// It needs the kev join from listFrom.
const hasExploitExpr = `(cve.exploit_ref OR kev.cve_id IS NOT NULL OR EXISTS (SELECT 1 FROM exploit e WHERE e.cve_id = cve.id))`

// listFrom joins the one-row-per-CVE enrichment tables. Postgres removes
// either join when a query does not reference it.
const listFrom = ` FROM cve LEFT JOIN kev ON kev.cve_id = cve.id LEFT JOIN epss ON epss.cve_id = cve.id`

// summaryDescriptionLength truncates descriptions in list responses.
const summaryDescriptionLength = 300

func (s *Store) ListCVEs(ctx context.Context, p ListCVEParams) ([]CVESummary, int, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	rank := ""
	if p.ExactID != "" {
		where = append(where, "cve.id = "+arg(p.ExactID))
	}
	if p.Text != "" {
		q := "websearch_to_tsquery('english', " + arg(p.Text) + ")"
		where = append(where, "cve.search @@ "+q)
		rank = "ts_rank(cve.search, " + q + ")"
	}
	if len(p.Severities) > 0 {
		where = append(where, "severity = ANY("+arg(p.Severities)+")")
	}
	if p.State != "" {
		where = append(where, "state = "+arg(p.State))
	}
	if p.Vendor != "" || p.Product != "" {
		cond := "a.cve_id = cve.id"
		if p.Vendor != "" {
			cond += " AND a.vendor = " + arg(p.Vendor)
		}
		if p.Product != "" {
			cond += " AND a.product = " + arg(p.Product)
		}
		where = append(where, "EXISTS (SELECT 1 FROM cve_affected a WHERE "+cond+")")
	}
	if p.CWE != "" {
		where = append(where, "cwe_ids @> ARRAY["+arg(p.CWE)+"]::text[]")
	}
	if p.PublishedFrom != nil {
		where = append(where, "date_published >= "+arg(*p.PublishedFrom))
	}
	if p.PublishedTo != nil {
		where = append(where, "date_published < "+arg(*p.PublishedTo))
	}
	if p.KEV != nil {
		if *p.KEV {
			where = append(where, "kev.cve_id IS NOT NULL")
		} else {
			where = append(where, "kev.cve_id IS NULL")
		}
	}
	if p.Exploit != nil {
		if *p.Exploit {
			where = append(where, hasExploitExpr)
		} else {
			where = append(where, "NOT "+hasExploitExpr)
		}
	}
	if p.EPSSMin != nil {
		where = append(where, "epss.score >= "+arg(*p.EPSSMin))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(*)"+listFrom+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dir := "ASC"
	if p.Desc {
		dir = "DESC"
	}
	var order string
	switch p.Sort {
	case "relevance":
		if rank != "" {
			order = rank + " DESC, date_published DESC NULLS LAST"
		} else {
			order = "date_published DESC NULLS LAST"
		}
	case "updated":
		order = "date_updated " + dir + " NULLS LAST"
	case "cvss":
		order = "COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) " + dir + " NULLS LAST"
	case "epss":
		order = "epss.score " + dir + " NULLS LAST"
	default:
		order = "date_published " + dir + " NULLS LAST"
	}

	limit, offset := arg(p.Limit), arg(p.Offset)
	pageIDs := fmt.Sprintf("SELECT cve.id%s%s ORDER BY %s, cve.id DESC LIMIT %s OFFSET %s",
		listFrom, whereSQL, order, limit, offset)
	if p.EPSSMin != nil || (p.KEV != nil && *p.KEV) {
		// These filters keep few rows, and those rows (older, exploited
		// CVEs) sit far along the date and CVSS indexes, so walking an index
		// until a page fills scans most of the table. A materialized CTE
		// builds the small matching set first; the sort then runs over it.
		pageIDs = fmt.Sprintf(`WITH matched AS MATERIALIZED (SELECT cve.id%s%s)
			SELECT cve.id FROM matched JOIN cve ON cve.id = matched.id
			LEFT JOIN kev ON kev.cve_id = cve.id LEFT JOIN epss ON epss.cve_id = cve.id
			ORDER BY %s, cve.id DESC LIMIT %s OFFSET %s`,
			listFrom, whereSQL, order, limit, offset)
	}

	// Two steps: pick the page's IDs in order using only the sort columns,
	// then fetch the display columns for just those IDs. Selecting them in
	// one pass made Postgres read every candidate row's TOASTed description
	// and run the has-exploit subquery before the top-N sort.
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT cve.id, state, assigner, title, left(description, %d), severity, severity_source,
		       cvss_v4_score, cvss_v3_score, cvss_v2_score, date_published, date_updated,
		       kev.cve_id IS NOT NULL, epss.score, epss.percentile, %s
		FROM unnest(ARRAY(%s)) WITH ORDINALITY AS page(id, ord)
		JOIN cve ON cve.id = page.id
		LEFT JOIN kev ON kev.cve_id = cve.id
		LEFT JOIN epss ON epss.cve_id = cve.id
		ORDER BY page.ord`,
		summaryDescriptionLength, hasExploitExpr, pageIDs), args...)
	if err != nil {
		return nil, 0, err
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[CVESummary])
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

type CVEDetail struct {
	ID              string
	State           string
	Assigner        *string
	DateReserved    *time.Time
	DatePublished   *time.Time
	DateUpdated     *time.Time
	Title           *string
	Description     *string
	CWEIDs          []string
	Severity        string
	SeveritySource  *string
	NVDStatus       *string
	NVDLastModified *time.Time
	Refs            json.RawMessage
	RawCvelist      []byte
	RawNVD          []byte
	ExploitRef      bool
	Affected        []AffectedOut
	KEV             *KEVOut
	EPSS            *EPSSOut
	Exploits        []ExploitOut
}

type KEVOut struct {
	VendorProject      *string    `json:"vendor_project"`
	Product            *string    `json:"product"`
	VulnerabilityName  *string    `json:"vulnerability_name"`
	ShortDescription   *string    `json:"short_description"`
	RequiredAction     *string    `json:"required_action"`
	DateAdded          time.Time  `json:"date_added"`
	DueDate            *time.Time `json:"due_date"`
	KnownRansomwareUse *string    `json:"known_ransomware_use"`
	ForensicTriage     *string    `json:"forensic_triage"`
	Notes              *string    `json:"notes"`
}

type EPSSOut struct {
	Score      float64     `json:"score"`
	Percentile float64     `json:"percentile"`
	ScoreDate  time.Time   `json:"score_date"`
	History    []EPSSPoint `json:"history"`
}

type EPSSPoint struct {
	ScoreDate  time.Time `json:"score_date"`
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
}

type ExploitOut struct {
	Source      string     `json:"source"`
	SourceRef   string     `json:"source_ref"`
	Title       *string    `json:"title"`
	URL         *string    `json:"url"`
	PublishedAt *time.Time `json:"published_at"`
}

type AffectedOut struct {
	Source   string          `json:"source"`
	Vendor   string          `json:"vendor"`
	Product  string          `json:"product"`
	CPEs     []string        `json:"cpes"`
	Versions json.RawMessage `json:"versions"`
}

func (s *Store) GetCVE(ctx context.Context, id string) (*CVEDetail, error) {
	var d CVEDetail
	err := s.pool.QueryRow(ctx, `
		SELECT id, state, assigner, date_reserved, date_published, date_updated, title, description, cwe_ids,
		       severity, severity_source, nvd_status, nvd_last_modified, refs, raw_cvelist, raw_nvd, exploit_ref
		FROM cve WHERE id = $1`, id).Scan(
		&d.ID, &d.State, &d.Assigner, &d.DateReserved, &d.DatePublished, &d.DateUpdated, &d.Title, &d.Description, &d.CWEIDs,
		&d.Severity, &d.SeveritySource, &d.NVDStatus, &d.NVDLastModified, &d.Refs, &d.RawCvelist, &d.RawNVD, &d.ExploitRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT source, vendor, product, cpes, versions FROM cve_affected
		WHERE cve_id = $1 ORDER BY source, vendor, product, id`, id)
	if err != nil {
		return nil, err
	}
	d.Affected, err = pgx.CollectRows(rows, pgx.RowToStructByPos[AffectedOut])
	if err != nil {
		return nil, err
	}

	var k KEVOut
	err = s.pool.QueryRow(ctx, `
		SELECT vendor_project, product, vulnerability_name, short_description, required_action,
		       date_added, due_date, known_ransomware_use, forensic_triage, notes
		FROM kev WHERE cve_id = $1`, id).Scan(
		&k.VendorProject, &k.Product, &k.VulnerabilityName, &k.ShortDescription, &k.RequiredAction,
		&k.DateAdded, &k.DueDate, &k.KnownRansomwareUse, &k.ForensicTriage, &k.Notes)
	switch {
	case err == nil:
		d.KEV = &k
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}

	var e EPSSOut
	err = s.pool.QueryRow(ctx, `SELECT score, percentile, score_date FROM epss WHERE cve_id = $1`, id).Scan(&e.Score, &e.Percentile, &e.ScoreDate)
	switch {
	case err == nil:
		rows, err := s.pool.Query(ctx, `SELECT score_date, score, percentile FROM epss_history WHERE cve_id = $1 ORDER BY score_date`, id)
		if err != nil {
			return nil, err
		}
		if e.History, err = pgx.CollectRows(rows, pgx.RowToStructByPos[EPSSPoint]); err != nil {
			return nil, err
		}
		d.EPSS = &e
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT source, source_ref, title, url, published_at FROM exploit
		WHERE cve_id = $1 ORDER BY published_at NULLS LAST, source, source_ref`, id)
	if err != nil {
		return nil, err
	}
	if d.Exploits, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ExploitOut]); err != nil {
		return nil, err
	}
	return &d, nil
}
