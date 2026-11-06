package platform

import (
	"context"
	"net/http"
)

// Role is a capability tier. Roles are ordered by Rank: a guard requiring a
// minimum role admits that role and every higher one. See docs/auth.md.
type Role string

const (
	RoleAnonymous Role = "anonymous"
	RoleViewer    Role = "viewer"
	RoleOperator  Role = "operator"
	RoleAdmin     Role = "admin"
)

// Rank orders roles; a higher rank is more privileged. Unknown roles rank as
// anonymous so a malformed value never grants access.
func (r Role) Rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether r is at least as privileged as min.
func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() }

// Principal is the caller on a request's context. The resolve middleware always
// sets one; an unauthenticated caller is the anonymous principal.
type Principal struct {
	UserID int64 // 0 for anonymous and the API-key principal
	Name   string
	Role   Role
}

// Anonymous is the principal for an unauthenticated caller.
var Anonymous = Principal{Role: RoleAnonymous}

type ctxKey int

const principalKey ctxKey = 0

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal on ctx, or the anonymous principal when
// none is set (so callers never need to nil-check).
func PrincipalFrom(ctx context.Context) Principal {
	if p, ok := ctx.Value(principalKey).(Principal); ok {
		return p
	}
	return Anonymous
}

// Guard wraps a handler so only callers with at least min may reach it. An
// anonymous caller gets 401 (log in); an authenticated but under-privileged one
// gets 403. The resolve middleware must run before any guard.
func Guard(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if !p.Role.AtLeast(min) {
			if p.Role == RoleAnonymous {
				WriteError(w, http.StatusUnauthorized, "authentication required")
			} else {
				WriteError(w, http.StatusForbidden, "insufficient role")
			}
			return
		}
		next(w, r)
	}
}
