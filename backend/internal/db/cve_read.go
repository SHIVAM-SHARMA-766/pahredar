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
	Sort        string // relevance, published, updated, cvss
	Desc        bool
	Limit       int
	Offset      int
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
}

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
		where = append(where, "id = "+arg(p.ExactID))
	}
	if p.Text != "" {
		q := "websearch_to_tsquery('english', " + arg(p.Text) + ")"
		where = append(where, "search @@ "+q)
		rank = "ts_rank(search, " + q + ")"
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
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM cve"+whereSQL, args...).Scan(&total); err != nil {
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
	default:
		order = "date_published " + dir + " NULLS LAST"
	}

	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT id, state, assigner, title, left(description, %d), severity, severity_source,
		       cvss_v4_score, cvss_v3_score, cvss_v2_score, date_published, date_updated
		FROM cve%s ORDER BY %s, id DESC LIMIT %s OFFSET %s`,
		summaryDescriptionLength, whereSQL, order, arg(p.Limit), arg(p.Offset)), args...)
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
	Affected        []AffectedOut
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
		       severity, severity_source, nvd_status, nvd_last_modified, refs, raw_cvelist, raw_nvd
		FROM cve WHERE id = $1`, id).Scan(
		&d.ID, &d.State, &d.Assigner, &d.DateReserved, &d.DatePublished, &d.DateUpdated, &d.Title, &d.Description, &d.CWEIDs,
		&d.Severity, &d.SeveritySource, &d.NVDStatus, &d.NVDLastModified, &d.Refs, &d.RawCvelist, &d.RawNVD)
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
	return &d, nil
}
