// Package alerts is the alerting service: it surfaces notifications about
// tracked assets (today, when a CVE matched to an asset is known-exploited)
// and lets the operator read them. See docs/roadmap.md Phase 3.
package alerts

import (
	"context"
	"net/http"
	"strconv"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Service holds the alerts service over the shared platform.
type Service struct {
	*platform.Platform
}

// New builds the alerts service.
func New(p *platform.Platform) *Service { return &Service{Platform: p} }

func (s *Service) Name() string { return "alerts" }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/alerts", s.list)
	mux.HandleFunc("GET /api/v1/alerts/unread-count", s.unreadCount)
	mux.HandleFunc("PUT /api/v1/alerts/read-all", s.readAll)
	mux.HandleFunc("PUT /api/v1/alerts/{id}/read", s.read)
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	unread := r.URL.Query().Get("unread") == "1"
	out, err := s.Store.ListAlerts(r.Context(), unread, platform.BoundedInt(r, "limit", 50, 1, 200))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) unreadCount(w http.ResponseWriter, r *http.Request) {
	n, err := s.Store.UnreadAlertCount(r.Context())
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"unread": n})
}

func (s *Service) read(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	if err := s.Store.MarkAlertRead(r.Context(), id); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) readAll(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.MarkAlertRead(r.Context(), 0); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Check generates alerts for new KEV matches and returns the new ones. Called
// on a schedule.
func Check(ctx context.Context, store *db.Store) ([]db.Alert, error) {
	kev, err := store.GenerateKEVAlerts(ctx)
	if err != nil {
		return nil, err
	}
	epss, err := store.GenerateEPSSAlerts(ctx)
	if err != nil {
		return kev, err
	}
	return append(kev, epss...), nil
}
