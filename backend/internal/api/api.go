// Package api assembles the HTTP handler from the product-service modules
// (intelligence, news, scanner, assets, incidents) plus the auth service, over the
// shared platform core, and wraps it in principal resolution. Adding a service
// means adding its module to New — the others are untouched. Per-route
// authorization is each module's own concern via platform.Guard; the access
// matrix lives in docs/auth.md. See also docs/foundation.md.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/assets"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/auth"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/easm"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/incidents"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/intel"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/news"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scanner"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/sources/reports"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

// New builds the HTTP handler: each service module registers its own routes,
// and the whole mux is wrapped in principal resolution (session cookie / API
// key / anonymous) so every route sees a principal.
func New(p *platform.Platform, sched *syncer.Scheduler, rc *reports.Client, allowPrivate bool, active *scan.Nuclei, authOpts auth.Options) http.Handler {
	modules := []platform.Module{
		intel.New(p, sched, rc),
		news.New(p),
		scanner.New(p, allowPrivate, active),
		assets.New(p),
		incidents.New(p),
		easm.New(p),
		auth.New(p, authOpts),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz(p))
	for _, m := range modules {
		m.Routes(mux)
	}
	return auth.Resolve(p.Store, authOpts)(mux)
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
