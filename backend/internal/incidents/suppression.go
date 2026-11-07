package incidents

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Suppression windows (Phase 4C-M4). A window over an asset or client needs
// access to that client; a global window (no client, no asset) is admin-only.

func (s *Service) listSuppressions(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	out, err := s.Store.ListSuppressions(r.Context(), p.AllClients, p.ClientIDs)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) createSuppression(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID *int64    `json:"client_id"`
		AssetID  *int64    `json:"asset_id"`
		Reason   string    `json:"reason"`
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body (starts_at/ends_at must be RFC3339)")
		return
	}
	if !body.EndsAt.After(body.StartsAt) {
		platform.WriteError(w, http.StatusBadRequest, "ends_at must be after starts_at")
		return
	}
	p := platform.PrincipalFrom(r.Context())

	// Resolve the scope's client for the access check. An asset narrows to its
	// client; otherwise the given client; otherwise global (admin-only).
	scopeClient := body.ClientID
	if body.AssetID != nil {
		a, err := s.Store.GetAsset(r.Context(), *body.AssetID)
		if err != nil {
			platform.WriteError(w, http.StatusBadRequest, "unknown asset")
			return
		}
		scopeClient = a.ClientID
	} else if body.ClientID != nil {
		if _, err := s.Store.GetClient(r.Context(), *body.ClientID); err != nil {
			platform.WriteError(w, http.StatusBadRequest, "unknown client")
			return
		}
	}
	if !mayManageChannel(p, scopeClient) {
		platform.WriteError(w, http.StatusForbidden, "you cannot suppress that scope")
		return
	}

	sp, err := s.Store.CreateSuppression(r.Context(), body.ClientID, body.AssetID, body.Reason, body.StartsAt, body.EndsAt)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusCreated, sp)
}

func (s *Service) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	sp, err := s.Store.GetSuppression(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "suppression not found")
		return
	}
	// Access: resolve the scope client (asset's client, else the client, else global).
	scopeClient := sp.ClientID
	if sp.AssetID != nil {
		if a, aerr := s.Store.GetAsset(r.Context(), *sp.AssetID); aerr == nil {
			scopeClient = a.ClientID
		}
	}
	if !mayManageChannel(platform.PrincipalFrom(r.Context()), scopeClient) {
		platform.WriteError(w, http.StatusNotFound, "suppression not found")
		return
	}
	if _, err := s.Store.DeleteSuppression(r.Context(), id); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
