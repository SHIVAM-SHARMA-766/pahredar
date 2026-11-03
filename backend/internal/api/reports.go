package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
)

const (
	// How long cached third-party reports are served before refetching. A
	// "not found" is retried sooner because sources add CVEs over time, and
	// news, social posts, and threat intel are refreshed daily.
	reportTTL         = 7 * 24 * time.Hour
	reportNotFoundTTL = 24 * time.Hour
	newsTTL           = 24 * time.Hour
	// NVD history grows whenever NVD touches the record.
	historyTTL    = 24 * time.Hour
	reportTimeout = 12 * time.Second
)

// remediationTags mark references whose pages are vendor guidance; their
// URLs feed the advisory previews and the shared-advisory related search.
var remediationTags = map[string]bool{
	"vendor-advisory": true, "vendor advisory": true, "patch": true, "mitigation": true,
	"release-notes": true, "release notes": true,
}

// advisoryURLs returns the CVE's vendor-guidance reference URLs, in order.
func advisoryURLs(refs json.RawMessage) []string {
	var list []cverecord.Reference
	if json.Unmarshal(refs, &list) != nil {
		return nil
	}
	var out []string
	for _, r := range list {
		for _, t := range r.Tags {
			if remediationTags[strings.ToLower(t)] {
				out = append(out, r.URL)
				break
			}
		}
	}
	return out
}

// referenceURLs returns every reference URL, in order.
func referenceURLs(refs json.RawMessage) []string {
	var list []cverecord.Reference
	if json.Unmarshal(refs, &list) != nil {
		return nil
	}
	out := make([]string, len(list))
	for i, r := range list {
		out[i] = r.URL
	}
	return out
}

type reportStatus struct {
	Source    string     `json:"source"`
	Status    string     `json:"status"` // ok, not_found, error, disabled (key not set)
	FetchedAt *time.Time `json:"fetched_at"`
	Error     string     `json:"error,omitempty"`
}

type reportsResponse struct {
	Sources []reportStatus             `json:"sources"`
	Reports map[string]json.RawMessage `json:"reports"`
}

// cveReports returns third-party material for a CVE: write-ups (OSV, Red
// Hat, Ubuntu), vendor guidance (MSRC, advisory page previews), and coverage
// (news, discussions). `sources` (comma list) limits which are returned, so
// the UI can load groups independently. Fresh cache entries are served
// as-is; the rest are fetched concurrently and cached. A failing source is
// reported, not fatal.
func (s *Server) cveReports(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	wanted := reports.Sources
	if v := r.URL.Query().Get("sources"); v != "" {
		wanted = nil
		for _, src := range strings.Split(v, ",") {
			if !slices.Contains(reports.Sources, src) {
				writeError(w, http.StatusBadRequest, "sources must be a comma list of "+strings.Join(reports.Sources, ", "))
				return
			}
			wanted = append(wanted, src)
		}
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
	req := reports.Request{CVEID: id, AdvisoryURLs: advisoryURLs(d.Refs), CommitURLs: reports.CommitURLs(referenceURLs(d.Refs))}
	if d.Assigner != nil {
		req.Assigner = *d.Assigner
	}
	for _, a := range d.Affected {
		if a.Vendor != "" && !slices.Contains(req.Vendors, a.Vendor) {
			req.Vendors = append(req.Vendors, a.Vendor)
		}
	}
	cached, err := s.store.CachedReports(r.Context(), id)
	if err != nil {
		internalError(w, r, err)
		return
	}

	resp := reportsResponse{Sources: make([]reportStatus, len(wanted)), Reports: map[string]json.RawMessage{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, src := range wanted {
		if !s.reports.Configured(src) {
			resp.Sources[i] = reportStatus{Source: src, Status: "disabled"}
			continue
		}
		if c, ok := cached[src]; ok && fresh(c) {
			at := c.FetchedAt
			resp.Sources[i] = reportStatus{Source: src, Status: c.Status, FetchedAt: &at}
			if c.Status == "ok" {
				resp.Reports[src] = c.Payload
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, payload := s.fetchReport(r.Context(), src, req)
			mu.Lock()
			defer mu.Unlock()
			resp.Sources[i] = st
			if payload != nil {
				resp.Reports[src] = payload
			}
		}()
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, resp)
}

func fresh(c db.CachedReport) bool {
	ttl := reportTTL
	if c.Status == "not_found" {
		ttl = reportNotFoundTTL
	}
	switch c.Source {
	case reports.SourceNews, reports.SourceDiscussions, reports.SourceBluesky, reports.SourceMastodon, reports.SourceOTX, reports.SourceThreatFox:
		ttl = newsTTL
	case reports.SourceHistory:
		ttl = historyTTL
	}
	return time.Since(c.FetchedAt) < ttl
}

func (s *Server) fetchReport(ctx context.Context, source string, req reports.Request) (reportStatus, json.RawMessage) {
	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	now := time.Now().UTC()
	id := req.CVEID
	report, err := s.reports.Fetch(ctx, source, req)
	// Store with a context that survives the client going away mid-fetch.
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer saveCancel()
	switch {
	case errors.Is(err, reports.ErrNotFound):
		if err := s.store.SaveReport(saveCtx, id, source, "not_found", nil); err != nil {
			slog.Warn("cache report", "source", source, "id", id, "err", err)
		}
		return reportStatus{Source: source, Status: "not_found", FetchedAt: &now}, nil
	case err != nil:
		slog.Warn("fetch report", "source", source, "id", id, "err", err)
		return reportStatus{Source: source, Status: "error", Error: "source unavailable, try again later"}, nil
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return reportStatus{Source: source, Status: "error", Error: "could not encode report"}, nil
	}
	if err := s.store.SaveReport(saveCtx, id, source, "ok", payload); err != nil {
		slog.Warn("cache report", "source", source, "id", id, "err", err)
	}
	return reportStatus{Source: source, Status: "ok", FetchedAt: &now}, payload
}

// series returns a daily metric series for the dashboard chart.
// Parameters: metric (published, kev_added, exploits), from and to
// (YYYY-MM-DD, inclusive; default the last 90 days).
func (s *Server) series(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	metric := q.Get("metric")
	if metric == "" {
		metric = "published"
	}
	if !db.IsMetric(metric) {
		writeError(w, http.StatusBadRequest, "metric must be one of published, kev_added, exploits")
		return
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	to, from := today, today.AddDate(0, 0, -89)
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"from", &from}, {"to", &to}} {
		if v := q.Get(p.name); v != "" {
			t, err := time.Parse("2006-01-02", v)
			if err != nil {
				writeError(w, http.StatusBadRequest, p.name+" must be YYYY-MM-DD")
				return
			}
			*p.dst = t
		}
	}
	if from.After(to) {
		writeError(w, http.StatusBadRequest, "from must not be after to")
		return
	}
	if to.Sub(from) > db.MaxSeriesDays*24*time.Hour {
		writeError(w, http.StatusBadRequest, "range is limited to about three years")
		return
	}
	out, err := s.store.DailySeries(r.Context(), metric, from, to)
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
