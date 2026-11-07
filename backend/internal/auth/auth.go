package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Options configures the auth service and the resolve middleware.
type Options struct {
	CookieSecure bool          // set the Secure flag on the session cookie (behind HTTPS)
	SessionTTL   time.Duration // session + cookie lifetime
	APIKeys      []string      // automation keys; a matching key is an admin principal
}

// Service is the authentication module: login, logout, and the current
// principal. User management (admin CRUD) lives alongside it in a later
// milestone. See docs/auth.md.
type Service struct {
	*platform.Platform
	opts Options
}

// New builds the auth service.
func New(p *platform.Platform, opts Options) *Service {
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 168 * time.Hour
	}
	return &Service{Platform: p, opts: opts}
}

func (s *Service) Name() string { return "auth" }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("GET /api/v1/auth/me", s.me)

	// User management — admin only (see docs/auth.md).
	mux.HandleFunc("GET /api/v1/users", platform.Guard(platform.RoleAdmin, s.listUsers))
	mux.HandleFunc("POST /api/v1/users", platform.Guard(platform.RoleAdmin, s.createUser))
	mux.HandleFunc("PATCH /api/v1/users/{id}", platform.Guard(platform.RoleAdmin, s.patchUser))
	mux.HandleFunc("PUT /api/v1/users/{id}/password", platform.Guard(platform.RoleAdmin, s.resetUserPassword))
	mux.HandleFunc("DELETE /api/v1/users/{id}", platform.Guard(platform.RoleAdmin, s.deleteUser))
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		platform.WriteError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	acct, err := s.Store.AuthUserByEmail(r.Context(), req.Email)
	if db.IsNotFound(err) {
		platform.WriteError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if acct.DisabledAt != nil {
		platform.WriteError(w, http.StatusForbidden, "this account is disabled")
		return
	}
	if err := VerifyPassword(acct.PasswordHash, req.Password); err != nil {
		platform.WriteError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := newSessionToken()
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	expires := time.Now().Add(s.opts.SessionTTL)
	if err := s.Store.CreateSession(r.Context(), tokenHash(token), acct.ID, expires); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	setSessionCookie(w, token, s.opts.SessionTTL, s.opts.CookieSecure)
	s.Log.Info("user logged in", "user_id", acct.ID, "role", acct.Role)
	platform.WriteJSON(w, http.StatusOK, map[string]any{"user": acct.User})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		if err := s.Store.DeleteSession(r.Context(), tokenHash(c.Value)); err != nil {
			platform.InternalError(w, r, err)
			return
		}
	}
	clearSessionCookie(w, s.opts.CookieSecure)
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// me returns the current principal (anonymous when not logged in).
func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	platform.WriteJSON(w, http.StatusOK, map[string]any{
		"authenticated": p.Role != platform.RoleAnonymous,
		"user_id":       p.UserID,
		"name":          p.Name,
		"role":          p.Role,
	})
}
