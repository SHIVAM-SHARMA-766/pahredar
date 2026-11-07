package incidents

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Channels are the notification targets incidents are delivered to (Phase 4C).
// A global channel (no client) is admin-only; a client channel needs access to
// that client.

func validChannelType(t string) bool { return t == "webhook" || t == "email" }

// mayManageChannel reports whether the principal may create/modify a channel for
// the given client scope (nil = global).
func mayManageChannel(p platform.Principal, clientID *int64) bool {
	if clientID == nil {
		return p.Role == platform.RoleAdmin // global channels are admin-only
	}
	return p.CanAccessClient(*clientID)
}

func (s *Service) listChannels(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	out, err := s.Store.ListChannels(r.Context(), p.AllClients, p.ClientIDs)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) createChannel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID *int64 `json:"client_id"`
		Type     string `json:"type"`
		Name     string `json:"name"`
		Target   string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Type = strings.TrimSpace(body.Type)
	body.Target = strings.TrimSpace(body.Target)
	if !validChannelType(body.Type) {
		platform.WriteError(w, http.StatusBadRequest, "type must be webhook or email")
		return
	}
	if body.Target == "" {
		platform.WriteError(w, http.StatusBadRequest, "target is required (a webhook URL or email address)")
		return
	}
	p := platform.PrincipalFrom(r.Context())
	if body.ClientID != nil {
		if _, err := s.Store.GetClient(r.Context(), *body.ClientID); err != nil {
			platform.WriteError(w, http.StatusBadRequest, "unknown client")
			return
		}
	}
	if !mayManageChannel(p, body.ClientID) {
		platform.WriteError(w, http.StatusForbidden, "you cannot manage channels for that scope")
		return
	}
	c, err := s.Store.CreateChannel(r.Context(), body.ClientID, body.Type, body.Name, body.Target)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("channel created", "channel_id", c.ID, "type", c.Type)
	platform.WriteJSON(w, http.StatusCreated, c)
}

// channelForRequest loads the channel and checks management access.
func (s *Service) channelForRequest(w http.ResponseWriter, r *http.Request) (*db.Channel, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return nil, false
	}
	c, err := s.Store.GetChannel(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "channel not found")
		return nil, false
	}
	if !mayManageChannel(platform.PrincipalFrom(r.Context()), c.ClientID) {
		platform.WriteError(w, http.StatusNotFound, "channel not found")
		return nil, false
	}
	return c, true
}

func (s *Service) patchChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelForRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		Name    *string `json:"name"`
		Target  *string `json:"target"`
		Enabled *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name, target, enabled := c.Name, c.Target, c.Enabled
	if body.Name != nil {
		name = *body.Name
	}
	if body.Target != nil {
		if strings.TrimSpace(*body.Target) == "" {
			platform.WriteError(w, http.StatusBadRequest, "target cannot be empty")
			return
		}
		target = strings.TrimSpace(*body.Target)
	}
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	out, err := s.Store.UpdateChannel(r.Context(), c.ID, name, target, enabled)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) deleteChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelForRequest(w, r)
	if !ok {
		return
	}
	if _, err := s.Store.DeleteChannel(r.Context(), c.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": c.ID})
}
