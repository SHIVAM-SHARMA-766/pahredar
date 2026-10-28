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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

const (
	defaultPageSize = 25
	maxPageSize     = 250
	// maxOffset bounds deep pagination, which gets slow with OFFSET.
	maxOffset = 10000
)

var (
	severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
	sorts      = []string{"relevance", "published", "updated", "cvss", "epss", "kev_added"}
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
	p.Vendors = listParam(q.Get("vendor"))
	p.Products = listParam(q.Get("product"))
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

	for _, b := range []struct {
		name string
		dst  **bool
	}{{"kev", &p.KEV}, {"exploit", &p.Exploit}, {"ransomware", &p.Ransomware}} {
		if v := q.Get(b.name); v != "" {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return p, 0, fmt.Errorf("%s must be true or false", b.name)
			}
			*b.dst = &parsed
		}
	}
	for _, r := range []struct {
		name     string
		dst      **float64
		min, max float64
	}{
		{"epss_min", &p.EPSSMin, 0, 1}, {"epss_max", &p.EPSSMax, 0, 1},
		{"cvss_min", &p.CVSSMin, 0, 10}, {"cvss_max", &p.CVSSMax, 0, 10},
	} {
		if v := q.Get(r.name); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < r.min || f > r.max {
				return p, 0, fmt.Errorf("%s must be a number between %g and %g", r.name, r.min, r.max)
			}
			*r.dst = &f
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

// listParam splits a comma-separated, case-insensitive list, dropping blanks.
func listParam(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
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
	HasExploit      bool               `json:"has_exploit"`
	KEV             *db.KEVOut         `json:"kev"`
	EPSS            *db.EPSSOut        `json:"epss"`
	Exploits        []db.ExploitOut    `json:"exploits"`
	Timeline        []timelineEvent    `json:"timeline"`
	References      json.RawMessage    `json:"references"`
	Affected        []db.AffectedOut   `json:"affected"`
}

type timelineEvent struct {
	Date   time.Time `json:"date"`
	Type   string    `json:"type"`
	Detail string    `json:"detail,omitempty"`
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
	if d.Exploits == nil {
		d.Exploits = []db.ExploitOut{}
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
		HasExploit: d.ExploitRef || d.KEV != nil || len(d.Exploits) > 0,
		KEV:        d.KEV,
		EPSS:       d.EPSS,
		Exploits:   d.Exploits,
		Timeline:   timeline(d),
		References: d.Refs,
		Affected:   d.Affected,
	})
}

// epssSpike is the score jump between consecutive history points that the
// timeline reports.
const epssSpike = 0.1

// timeline assembles the dated events for a CVE, oldest first.
func timeline(d *db.CVEDetail) []timelineEvent {
	var ev []timelineEvent
	add := func(t *time.Time, typ, detail string) {
		if t != nil {
			ev = append(ev, timelineEvent{Date: *t, Type: typ, Detail: detail})
		}
	}
	add(d.DateReserved, "reserved", "")
	add(d.DatePublished, "published", "")
	if d.KEV != nil {
		add(&d.KEV.DateAdded, "kev_added", "added to CISA KEV")
		add(d.KEV.DueDate, "kev_due", "CISA remediation due date")
	}
	for _, e := range d.Exploits {
		add(e.PublishedAt, "exploit_published", e.Source+": "+deref(e.Title))
	}
	if d.EPSS != nil {
		for i := 1; i < len(d.EPSS.History); i++ {
			prev, cur := d.EPSS.History[i-1], d.EPSS.History[i]
			if cur.Score-prev.Score >= epssSpike {
				add(&cur.ScoreDate, "epss_spike", fmt.Sprintf("EPSS %.3f -> %.3f", prev.Score, cur.Score))
			}
		}
	}
	add(d.DateUpdated, "updated", "CVE record last updated")
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Date.Before(ev[j].Date) })
	if ev == nil {
		ev = []timelineEvent{}
	}
	return ev
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
