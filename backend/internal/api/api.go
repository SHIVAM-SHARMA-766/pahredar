// Package api assembles the HTTP handler from the product-service modules
// (intelligence, news, scanner) over the shared platform core, plus /healthz.
// Adding a service means adding its module to New — the others are untouched.
// See docs/foundation.md and docs/contributing.md.
package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/alerts"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/assets"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/intel"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/news"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scanner"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

// New builds the HTTP handler: each service module registers its own routes.
func New(p *platform.Platform, sched *syncer.Scheduler, rc *reports.Client, allowPrivate bool, active *scan.Nuclei, apiKeys []string) http.Handler {
	modules := []platform.Module{
		intel.New(p, sched, rc),
		news.New(p),
		scanner.New(p, allowPrivate, active),
		assets.New(p),
		alerts.New(p),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz(p))
	for _, m := range modules {
		m.Routes(mux)
	}
	return withAuth(apiKeys, mux)
}

// withAuth gates the API behind an API key when any key is configured; /healthz
// is always open. With no keys the API is open (local use).
func withAuth(keys []string, next http.Handler) http.Handler {
	if len(keys) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := apiKeyFromRequest(r)
		if got == "" || !keyMatches(keys, got) {
			platform.WriteError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next.ServeHTTP(w, r.WithContext(platform.WithPrincipal(r.Context(), platform.Principal{Name: "api-key"})))
	})
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

func healthz(p *platform.Platform) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := p.Store.Ping(ctx); err != nil {
			slog.Warn("health check failed", "err", err)
			platform.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "database": "unreachable"})
			return
		}
		platform.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
	}
}
