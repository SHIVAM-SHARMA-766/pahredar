// Package intel is the Vulnerability Intelligence service: the CVE knowledge
// base (search, detail, vendors, dashboard) and the ingestion sync. It is the
// source of truth the other services read from.
package intel

import (
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

// Service holds the intelligence service's dependencies over the platform.
type Service struct {
	*platform.Platform
	// sched is nil when the scheduler is disabled.
	sched   *syncer.Scheduler
	reports *reports.Client
}

// New builds the intelligence service.
func New(p *platform.Platform, sched *syncer.Scheduler, rc *reports.Client) *Service {
	return &Service{Platform: p, sched: sched, reports: rc}
}

func (s *Service) Name() string { return "intelligence" }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/cves", s.listCVEs)
	mux.HandleFunc("GET /api/v1/cves/facets", s.cveFacets)
	mux.HandleFunc("GET /api/v1/cves/{id}", s.getCVE)
	mux.HandleFunc("GET /api/v1/cves/{id}/reports", s.cveReports)
	mux.HandleFunc("GET /api/v1/cves/{id}/related", s.relatedCVEs)
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
