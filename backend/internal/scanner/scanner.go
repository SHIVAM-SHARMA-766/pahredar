// Package scanner is the Endpoint Scanner service: recon, active scanning, and
// stored results. It registers its routes and its scan.run
// job handler against the shared platform.
package scanner

import (
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

// Service holds the scanner's dependencies over the shared platform.
type Service struct {
	*platform.Platform
	scanner *scan.Scanner
	// scanSem bounds concurrent endpoint scans.
	scanSem chan struct{}
}

// New builds the scanner service and registers its job handler.
func New(p *platform.Platform, allowPrivate bool, active *scan.Nuclei) *Service {
	s := &Service{
		Platform: p,
		scanner:  scan.NewScanner(p.Store, allowPrivate, active),
		scanSem:  make(chan struct{}, 3),
	}
	s.registerScanJobs()
	return s
}

func (s *Service) Name() string { return "scanner" }

func (s *Service) Routes(mux *http.ServeMux) {
	// Passive scanning and viewing a result are public; an active scan is
	// gated inside runScan (operator+, content-based). Listing all scans is an
	// operator overview. See docs/auth.md.
	mux.HandleFunc("POST /api/v1/scan", s.runScan)
	mux.HandleFunc("GET /api/v1/scans", platform.Guard(platform.RoleOperator, s.listScans))
	mux.HandleFunc("GET /api/v1/scans/{id}", s.getScan)
	mux.HandleFunc("GET /api/v1/scan/jobs/{id}", s.scanJobStatus)
	mux.HandleFunc("GET /api/v1/scan/config", s.scanConfig)
}
