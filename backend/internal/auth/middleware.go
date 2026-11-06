package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Resolve returns middleware that sets the caller's principal on the request
// context, from (in order) a valid session cookie, then a matching API key
// (admin, for automation), else the anonymous principal. It never blocks —
// authorization is per-route via platform.Guard. It must wrap the mux so every
// handler, including guards, sees a principal.
func Resolve(store *db.Store, opts Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := platform.Anonymous

			if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
				su, serr := store.SessionUserByToken(r.Context(), tokenHash(c.Value))
				if serr == nil {
					p = platform.Principal{UserID: su.UserID, Name: su.Email, Role: platform.Role(su.Role)}
				} else if db.IsNotFound(serr) {
					clearSessionCookie(w, opts.CookieSecure) // stale/invalid cookie
				}
			}

			if p.Role == platform.RoleAnonymous {
				if key := apiKeyFromRequest(r); key != "" && keyMatches(opts.APIKeys, key) {
					p = platform.Principal{Name: "api-key", Role: platform.RoleAdmin}
				}
			}

			next.ServeHTTP(w, r.WithContext(platform.WithPrincipal(r.Context(), p)))
		})
	}
}

func apiKeyFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

func keyMatches(keys []string, got string) bool {
	gb := []byte(got)
	match := false
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(k), gb) == 1 {
			match = true
		}
	}
	return match
}
