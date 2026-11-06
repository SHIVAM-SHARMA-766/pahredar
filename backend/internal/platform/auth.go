package platform

import "context"

// Principal is the authenticated caller on a request's context. With no auth
// configured the API is open and no principal is set.
type Principal struct {
	Name string
}

type ctxKey int

const principalKey ctxKey = 0

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal on ctx, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}
