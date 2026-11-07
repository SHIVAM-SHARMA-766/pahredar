package auth

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// slugify turns a name into a url-safe slug (lowercase, hyphenated).
func slugify(s string) string {
	return strings.Trim(slugStrip.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-"), "-")
}

// listClients returns the clients the caller may access: all of them for an
// admin, the assigned ones otherwise.
func (s *Service) listClients(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	var (
		clients []db.Client
		err     error
	)
	if p.AllClients {
		clients, err = s.Store.ListClients(r.Context())
	} else {
		clients, err = s.Store.ClientsForUser(r.Context(), p.UserID)
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": clients})
}

func (s *Service) createClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		Slug  string `json:"slug"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		platform.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	slug := slugify(body.Slug)
	if slug == "" {
		slug = slugify(body.Name)
	}
	if slug == "" {
		platform.WriteError(w, http.StatusBadRequest, "could not derive a slug; give one explicitly")
		return
	}
	c, err := s.Store.CreateClient(r.Context(), body.Name, slug, body.Notes)
	if err == db.ErrClientExists {
		platform.WriteError(w, http.StatusConflict, "a client with that slug already exists")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("admin created client", "client_id", c.ID, "slug", c.Slug)
	platform.WriteJSON(w, http.StatusCreated, c)
}

func (s *Service) patchClient(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Name  string `json:"name"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	c, err := s.Store.UpdateClient(r.Context(), id, body.Name, body.Notes)
	if db.IsNotFound(err) {
		platform.WriteError(w, http.StatusNotFound, "no such client")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, c)
}

func (s *Service) deleteClient(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	n, err := s.Store.DeleteClient(r.Context(), id)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if n == 0 {
		platform.WriteError(w, http.StatusNotFound, "no such client")
		return
	}
	s.Log.Info("admin deleted client", "client_id", id)
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": 1})
}

// getUserClients returns the clients assigned to a user (admin view).
func (s *Service) getUserClients(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	clients, err := s.Store.ClientsForUser(r.Context(), id)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": clients})
}

// setUserClients replaces a user's client assignments.
func (s *Service) setUserClients(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		ClientIDs []int64 `json:"client_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.Store.SetUserClients(r.Context(), id, body.ClientIDs); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("admin set user clients", "user_id", id, "count", len(body.ClientIDs))
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
