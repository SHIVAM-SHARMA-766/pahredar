package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

const (
	defaultPageSize = 25
	maxPageSize     = 100
	// maxOffset bounds deep pagination, which gets slow with OFFSET.
	maxOffset = 10000
)

var (
	severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
	sorts      = []string{"relevance", "published", "updated", "cvss"}
	cweParam   = regexp.MustCompile(`^CWE-\d+$`)
)

type listResponse struct {
	Items    []db.CVESummary `json:"items"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

func (s *Server) listCVEs(w http.ResponseWriter, r *http.Request) {
	p, page, err := parseListParams(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, total, err := s.store.ListCVEs(r.Context(), p)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if items == nil {
		items = []db.CVESummary{}
	}
	writeJSON(w, http.StatusOK, listResponse{Items: items, Total: total, Page: page, PageSize: p.Limit})
}

func parseListParams(q url.Values) (db.ListCVEParams, int, error) {
	var p db.ListCVEParams

	if text := strings.TrimSpace(q.Get("q")); text != "" {
		if id := strings.ToUpper(text); cverecord.IDPattern.MatchString(id) {
			p.ExactID = id
		} else {
			p.Text = text
		}
	}
	if v := q.Get("severity"); v != "" {
		for _, sev := range strings.Split(strings.ToUpper(v), ",") {
			if !slices.Contains(severities, sev) {
				return p, 0, fmt.Errorf("severity must be a comma-separated list of %s", strings.Join(severities, ", "))
			}
			p.Severities = append(p.Severities, sev)
		}
	}
	if v := strings.ToUpper(q.Get("state")); v != "" {
		if v != "PUBLISHED" && v != "REJECTED" {
			return p, 0, errors.New("state must be PUBLISHED or REJECTED")
		}
		p.State = v
	}
	p.Vendor = strings.ToLower(strings.TrimSpace(q.Get("vendor")))
	p.Product = strings.ToLower(strings.TrimSpace(q.Get("product")))
	if v := strings.ToUpper(q.Get("cwe")); v != "" {
		if !cweParam.MatchString(v) {
			return p, 0, errors.New("cwe must look like CWE-79")
		}
		p.CWE = v
	}
	for _, d := range []struct {
		name string
		dst  **time.Time
		add  int
	}{{"published_from", &p.PublishedFrom, 0}, {"published_to", &p.PublishedTo, 1}} {
		if v := q.Get(d.name); v != "" {
			t, err := time.Parse("2006-01-02", v)
			if err != nil {
				return p, 0, fmt.Errorf("%s must be YYYY-MM-DD", d.name)
			}
			t = t.AddDate(0, 0, d.add) // published_to is inclusive of that day
			*d.dst = &t
		}
	}

	p.Sort = q.Get("sort")
	if p.Sort == "" {
		p.Sort = "published"
		if p.Text != "" {
			p.Sort = "relevance"
		}
	}
	if !slices.Contains(sorts, p.Sort) {
		return p, 0, fmt.Errorf("sort must be one of %s", strings.Join(sorts, ", "))
	}
	switch q.Get("order") {
	case "", "desc":
		p.Desc = true
	case "asc":
	default:
		return p, 0, errors.New("order must be asc or desc")
	}

	page, err := intParam(q, "page", 1)
	if err != nil || page < 1 {
		return p, 0, errors.New("page must be a positive integer")
	}
	p.Limit, err = intParam(q, "page_size", defaultPageSize)
	if err != nil || p.Limit < 1 || p.Limit > maxPageSize {
		return p, 0, fmt.Errorf("page_size must be between 1 and %d", maxPageSize)
	}
	p.Offset = (page - 1) * p.Limit
	if p.Offset > maxOffset {
		return p, 0, fmt.Errorf("results beyond the first %d are not available; narrow the filters", maxOffset)
	}
	return p, page, nil
}

func intParam(q url.Values, name string, fallback int) (int, error) {
	v := q.Get(name)
	if v == "" {
		return fallback, nil
	}
	return strconv.Atoi(v)
}

type cveDetailResponse struct {
	ID              string             `json:"id"`
	State           string             `json:"state"`
	Assigner        *string            `json:"assigner"`
	DateReserved    *time.Time         `json:"date_reserved"`
	DatePublished   *time.Time         `json:"date_published"`
	DateUpdated     *time.Time         `json:"date_updated"`
	Title           *string            `json:"title"`
	Description     *string            `json:"description"`
	CWEIDs          []string           `json:"cwe_ids"`
	Severity        string             `json:"severity"`
	SeveritySource  *string            `json:"severity_source"`
	CVSS            effectiveCVSS      `json:"cvss"`
	Metrics         []cverecord.Metric `json:"metrics"`
	SSVC            *cverecord.SSVC    `json:"ssvc"`
	NVDStatus       *string            `json:"nvd_status"`
	NVDLastModified *time.Time         `json:"nvd_last_modified"`
	References      json.RawMessage    `json:"references"`
	Affected        []db.AffectedOut   `json:"affected"`
}

type effectiveCVSS struct {
	V4 *cverecord.Metric `json:"v4"`
	V3 *cverecord.Metric `json:"v3"`
	V2 *cverecord.Metric `json:"v2"`
}

func (s *Server) getCVE(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	d, err := s.store.GetCVE(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CVE not found")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}

	// Per-provider metrics and SSVC are read from the raw records rather than
	// stored, so they always reflect the current derivation logic.
	var rec *cverecord.Record
	if d.RawCvelist != nil {
		if rec, err = cverecord.Parse(d.RawCvelist); err != nil {
			slog.Warn("stored cvelist record unparseable", "id", id, "err", err)
		}
	}
	var nvd *cverecord.NVD
	if d.RawNVD != nil {
		if nvd, err = cverecord.ParseNVD(d.RawNVD); err != nil {
			slog.Warn("stored NVD record unparseable", "id", id, "err", err)
		}
	}
	derived := cverecord.Derive(rec, nvd)
	metrics := cverecord.Metrics(rec, nvd)
	if metrics == nil {
		metrics = []cverecord.Metric{}
	}
	if d.Affected == nil {
		d.Affected = []db.AffectedOut{}
	}

	writeJSON(w, http.StatusOK, cveDetailResponse{
		ID: d.ID, State: d.State, Assigner: d.Assigner,
		DateReserved: d.DateReserved, DatePublished: d.DatePublished, DateUpdated: d.DateUpdated,
		Title: d.Title, Description: d.Description, CWEIDs: d.CWEIDs,
		Severity: d.Severity, SeveritySource: d.SeveritySource,
		CVSS:      effectiveCVSS{V4: derived.V4, V3: derived.V3, V2: derived.V2},
		Metrics:   metrics,
		SSVC:      cverecord.CISASSVC(rec),
		NVDStatus: d.NVDStatus, NVDLastModified: d.NVDLastModified,
		References: d.Refs,
		Affected:   d.Affected,
	})
}
