// Package api assembles the HTTP API from the product-service modules
// (intelligence, news, scanner) over the shared platform core, plus /healthz.
// Each service registers its own routes; new services are added to modules()
// without touching the others. See docs/foundation.md and docs/contributing.md.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

// Server holds the shared platform plus the service-specific dependencies.
// The embedded *platform.Platform provides Store and Log to every handler.
type Server struct {
	*platform.Platform
	// sched is nil when the scheduler is disabled (intelligence service).
	sched   *syncer.Scheduler
	reports *reports.Client
	scanner *scan.Scanner
	// scanSem bounds concurrent endpoint scans (scanner service).
	scanSem chan struct{}
	jobsMu  sync.Mutex
	jobs    map[int64]*scanJob
	nextJob int64
}

func New(p *platform.Platform, sched *syncer.Scheduler, rc *reports.Client, allowPrivate bool, active *scan.Nuclei) *Server {
	srv := &Server{
		Platform: p,
		sched:    sched,
		reports:  rc,
		scanner:  scan.NewScanner(p.Store, allowPrivate, active),
		scanSem:  make(chan struct{}, 3),
		jobs:     map[int64]*scanJob{},
	}
	go srv.reapScanJobs()
	return srv
}

// modules lists the product services. Adding a service appends a module here;
// the other services are untouched. (They are route groups on one Server today;
// each can later be extracted into its own package — see docs/roadmap.md P1b.)
func (s *Server) modules() []platform.Module {
	return []platform.Module{
		routeModule{"intelligence", s.intelRoutes},
		routeModule{"news", s.newsRoutes},
		routeModule{"scanner", s.scannerRoutes},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	for _, m := range s.modules() {
		m.Routes(mux)
	}
	return mux
}

// routeModule adapts a service's route registration to platform.Module.
type routeModule struct {
	name   string
	routes func(*http.ServeMux)
}

func (m routeModule) Name() string              { return m.name }
func (m routeModule) Routes(mux *http.ServeMux) { m.routes(mux) }

// intelRoutes — Vulnerability Intelligence: CVEs, vendors, dashboard, sync.
func (s *Server) intelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/cves", s.listCVEs)
	mux.HandleFunc("GET /api/v1/cves/facets", s.cveFacets)
	mux.HandleFunc("GET /api/v1/cves/{id}", s.getCVE)
	mux.HandleFunc("GET /api/v1/cves/{id}/reports", s.cveReports)
	mux.HandleFunc("GET /api/v1/cves/{id}/related", s.relatedCVEs)
	mux.HandleFunc("GET /api/v1/cves/{id}/articles", s.cveArticles)
	mux.HandleFunc("GET /api/v1/cves/{id}/detection", s.cveDetection)
	mux.HandleFunc("GET /api/v1/cves/{id}/attack", s.cveAttack)
	mux.HandleFunc("GET /api/v1/stats/dashboard", s.dashboard)
	mux.HandleFunc("GET /api/v1/stats/series", s.series)
	mux.HandleFunc("GET /api/v1/vendors", s.listVendors)
	mux.HandleFunc("GET /api/v1/products", s.listProducts)
	mux.HandleFunc("GET /api/v1/vendors/{vendor}", s.getVendor)
	mux.HandleFunc("GET /api/v1/vendors/{vendor}/products/{product}", s.getProduct)
	mux.HandleFunc("GET /api/v1/sync/status", s.syncStatus)
	mux.HandleFunc("POST /api/v1/sync/{source}", s.triggerSync)
}

// newsRoutes — Security News: feeds, news, advisories, trending.
func (s *Server) newsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/stats/trending", s.trending)
	mux.HandleFunc("GET /api/v1/feeds", s.feedList)
	mux.HandleFunc("GET /api/v1/feeds/advisories", s.latestAdvisories)
	mux.HandleFunc("GET /api/v1/news", s.news)
	mux.HandleFunc("PUT /api/v1/news/bookmark", s.setBookmark)
}

// scannerRoutes — Endpoint Scanner: scans, request tool, results.
func (s *Server) scannerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/scan", s.runScan)
	mux.HandleFunc("POST /api/v1/scan/request", s.scanRequest)
	mux.HandleFunc("GET /api/v1/scans", s.listScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.getScan)
	mux.HandleFunc("GET /api/v1/scan/jobs/{id}", s.scanJobStatus)
	mux.HandleFunc("GET /api/v1/scan/config", s.scanConfig)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		slog.Warn("health check failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "database": "unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// internalError logs err and returns a generic 500.
func internalError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}
