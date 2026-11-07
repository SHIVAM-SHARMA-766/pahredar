package auth

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// minPasswordLen is the shortest password an admin may set for an account.
const minPasswordLen = 8

// validRole reports whether role is one an admin may assign.
func validRole(role string) bool {
	switch platform.Role(role) {
	case platform.RoleViewer, platform.RoleOperator, platform.RoleAdmin:
		return true
	default:
		return false
	}
}

func (s *Service) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Service) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	if !strings.Contains(body.Email, "@") {
		platform.WriteError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	if len(body.Password) < minPasswordLen {
		platform.WriteError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if body.Role == "" {
		body.Role = string(platform.RoleViewer)
	}
	if !validRole(body.Role) {
		platform.WriteError(w, http.StatusBadRequest, "role must be viewer, operator, or admin")
		return
	}
	hash, err := HashPassword(body.Password)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	u, err := s.Store.CreateUser(r.Context(), body.Email, hash, body.Role)
	if err == db.ErrUserExists {
		platform.WriteError(w, http.StatusConflict, "a user with that email already exists")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("admin created user", "user_id", u.ID, "role", u.Role)
	platform.WriteJSON(w, http.StatusCreated, u)
}

func (s *Service) patchUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	target, err := s.Store.UserByID(r.Context(), id)
	if db.IsNotFound(err) {
		platform.WriteError(w, http.StatusNotFound, "no such user")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}

	// Refuse any change that would remove the last enabled admin.
	demoting := body.Role != nil && *body.Role != string(platform.RoleAdmin)
	disabling := body.Disabled != nil && *body.Disabled
	if (demoting || disabling) && target.Role == string(platform.RoleAdmin) && target.DisabledAt == nil {
		others, aerr := s.Store.CountActiveAdmins(r.Context(), target.ID)
		if aerr != nil {
			platform.InternalError(w, r, aerr)
			return
		}
		if others == 0 {
			platform.WriteError(w, http.StatusConflict, "cannot demote or disable the last admin")
			return
		}
	}

	out := target
	if body.Role != nil {
		if !validRole(*body.Role) {
			platform.WriteError(w, http.StatusBadRequest, "role must be viewer, operator, or admin")
			return
		}
		if out, err = s.Store.UpdateUserRole(r.Context(), id, *body.Role); err != nil {
			platform.InternalError(w, r, err)
			return
		}
	}
	if body.Disabled != nil {
		if out, err = s.Store.SetUserDisabled(r.Context(), id, *body.Disabled); err != nil {
			platform.InternalError(w, r, err)
			return
		}
	}
	s.Log.Info("admin updated user", "user_id", id)
	platform.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(body.Password) < minPasswordLen {
		platform.WriteError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	hash, err := HashPassword(body.Password)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if err := s.Store.UpdateUserPassword(r.Context(), id, hash); db.IsNotFound(err) {
		platform.WriteError(w, http.StatusNotFound, "no such user")
		return
	} else if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("admin reset user password", "user_id", id)
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	target, err := s.Store.UserByID(r.Context(), id)
	if db.IsNotFound(err) {
		platform.WriteError(w, http.StatusNotFound, "no such user")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if target.Role == string(platform.RoleAdmin) && target.DisabledAt == nil {
		others, aerr := s.Store.CountActiveAdmins(r.Context(), target.ID)
		if aerr != nil {
			platform.InternalError(w, r, aerr)
			return
		}
		if others == 0 {
			platform.WriteError(w, http.StatusConflict, "cannot delete the last admin")
			return
		}
	}
	if _, err := s.Store.DeleteUser(r.Context(), id); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	s.Log.Info("admin deleted user", "user_id", id)
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": 1})
}

// pathID parses the {id} path value, writing a 400 and returning false on error.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return 0, false
	}
	return id, true
}
