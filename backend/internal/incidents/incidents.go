// Package incidents is the incident service (Phase 4B): it rolls each asset's
// alerts up into a single living incident, lists them client-scoped, and tracks
// read state. Generation (KEV/EPSS/finding alerts) stays in the db layer; this
// service aggregates and surfaces them. See docs/phase4.md.
package incidents

import (
	"context"
	"net/http"
	"strconv"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Service holds the incident service over the shared platform.
type Service struct {
	*platform.Platform
}

// New builds the incident service.
func New(p *platform.Platform) *Service { return &Service{Platform: p} }

func (s *Service) Name() string { return "incidents" }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/incidents", platform.Guard(platform.RoleViewer, s.list))
	mux.HandleFunc("GET /api/v1/incidents/unread-count", platform.Guard(platform.RoleViewer, s.unreadCount))
	mux.HandleFunc("GET /api/v1/incidents/{id}", platform.Guard(platform.RoleViewer, s.get))
	mux.HandleFunc("GET /api/v1/incidents/{id}/items", platform.Guard(platform.RoleViewer, s.items))
	mux.HandleFunc("PUT /api/v1/incidents/read-all", platform.Guard(platform.RoleOperator, s.readAll))
	mux.HandleFunc("PUT /api/v1/incidents/{id}/read", platform.Guard(platform.RoleOperator, s.read))
	mux.HandleFunc("PUT /api/v1/incidents/{id}/acknowledge", platform.Guard(platform.RoleOperator, s.acknowledge))
	mux.HandleFunc("PUT /api/v1/incidents/{id}/resolve", platform.Guard(platform.RoleOperator, s.resolve))
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	out, err := s.Store.ListIncidents(r.Context(), p.AllClients, p.ClientIDs, platform.BoundedInt(r, "limit", 100, 1, 500))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) unreadCount(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	n, err := s.Store.UnreadIncidentCount(r.Context(), p.AllClients, p.ClientIDs)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"unread": n})
}

// accessible loads an incident and checks the caller's client access (tenant
// mismatch → 404 so existence does not leak).
func (s *Service) accessible(w http.ResponseWriter, r *http.Request) (*db.Incident, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return nil, false
	}
	inc, err := s.Store.GetIncident(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "incident not found")
		return nil, false
	}
	p := platform.PrincipalFrom(r.Context())
	ok := p.AllClients
	if !ok && inc.ClientID != nil {
		ok = p.CanAccessClient(*inc.ClientID)
	}
	if !ok {
		platform.WriteError(w, http.StatusNotFound, "incident not found")
		return nil, false
	}
	return inc, true
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	inc, ok := s.accessible(w, r)
	if !ok {
		return
	}
	platform.WriteJSON(w, http.StatusOK, inc)
}

func (s *Service) items(w http.ResponseWriter, r *http.Request) {
	inc, ok := s.accessible(w, r)
	if !ok {
		return
	}
	out, err := s.Store.IncidentItems(r.Context(), inc.AssetID)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) read(w http.ResponseWriter, r *http.Request) {
	inc, ok := s.accessible(w, r)
	if !ok {
		return
	}
	if err := s.Store.MarkIncidentRead(r.Context(), inc.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) readAll(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	if err := s.Store.MarkAllIncidentsRead(r.Context(), p.AllClients, p.ClientIDs); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) acknowledge(w http.ResponseWriter, r *http.Request) {
	inc, ok := s.accessible(w, r)
	if !ok {
		return
	}
	if err := s.Store.AcknowledgeIncident(r.Context(), inc.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) resolve(w http.ResponseWriter, r *http.Request) {
	inc, ok := s.accessible(w, r)
	if !ok {
		return
	}
	if err := s.Store.ResolveIncident(r.Context(), inc.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Check runs the detectors (KEV + high-EPSS alerts) and rolls the asset alerts
// up into incidents. Scanner-created critical-finding alerts are folded in by
// the same RefreshIncidents. Called on a schedule.
func Check(ctx context.Context, store *db.Store, epssThreshold float64) error {
	if _, err := store.GenerateKEVAlerts(ctx); err != nil {
		return err
	}
	if _, err := store.GenerateEPSSAlerts(ctx, epssThreshold); err != nil {
		return err
	}
	return store.RefreshIncidents(ctx)
}
