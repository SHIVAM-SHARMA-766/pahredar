// Package api implements the HTTP API served under /api/v1 plus /healthz.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

type Server struct {
	store *db.Store
	// sched is nil when the scheduler is disabled.
	sched *syncer.Scheduler
}

func New(store *db.Store, sched *syncer.Scheduler) *Server {
	return &Server{store: store, sched: sched}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /api/v1/cves", s.listCVEs)
	mux.HandleFunc("GET /api/v1/cves/{id}", s.getCVE)
	mux.HandleFunc("GET /api/v1/stats/dashboard", s.dashboard)
	mux.HandleFunc("GET /api/v1/vendors", s.listVendors)
	mux.HandleFunc("GET /api/v1/vendors/{vendor}", s.getVendor)
	mux.HandleFunc("GET /api/v1/vendors/{vendor}/products/{product}", s.getProduct)
	mux.HandleFunc("GET /api/v1/sync/status", s.syncStatus)
	mux.HandleFunc("POST /api/v1/sync/{source}", s.triggerSync)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
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
