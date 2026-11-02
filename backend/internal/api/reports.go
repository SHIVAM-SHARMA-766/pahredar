package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
)

const (
	// How long cached third-party reports are served before refetching. A
	// "not found" is retried sooner because sources add CVEs over time.
	reportTTL         = 7 * 24 * time.Hour
	reportNotFoundTTL = 24 * time.Hour
	reportTimeout     = 10 * time.Second
)

type reportStatus struct {
	Source    string     `json:"source"`
	Status    string     `json:"status"` // ok, not_found, error
	FetchedAt *time.Time `json:"fetched_at"`
	Error     string     `json:"error,omitempty"`
}

type reportsResponse struct {
	Sources []reportStatus             `json:"sources"`
	Reports map[string]json.RawMessage `json:"reports"`
}

// cveReports returns third-party write-ups for a CVE: OSV advisories, Red
// Hat, and Ubuntu. Fresh cache entries are served as-is; the rest are fetched
// concurrently and cached. A failing source is reported, not fatal.
func (s *Server) cveReports(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	ok, err := s.store.CVEExists(r.Context(), id)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "CVE not found")
		return
	}
	cached, err := s.store.CachedReports(r.Context(), id)
	if err != nil {
		internalError(w, r, err)
		return
	}

	resp := reportsResponse{Sources: make([]reportStatus, len(reports.Sources)), Reports: map[string]json.RawMessage{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, src := range reports.Sources {
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
			st, payload := s.fetchReport(r.Context(), src, id)
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
	return time.Since(c.FetchedAt) < ttl
}

func (s *Server) fetchReport(ctx context.Context, source, id string) (reportStatus, json.RawMessage) {
	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	now := time.Now().UTC()
	report, err := s.reports.Fetch(ctx, source, id)
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
