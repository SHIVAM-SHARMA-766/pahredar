// Package platform holds the shared core that every product service (module)
// is built on: the datastore and logger (and, from P2, the durable job
// queue). A module receives a *Platform and registers its HTTP routes against
// it, so services grow additively without the core becoming a bottleneck.
// See docs/foundation.md.
package platform

import (
	"log/slog"
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/jobs"
)

// Platform is the shared core handed to every module.
type Platform struct {
	Store *db.Store
	Log   *slog.Logger
	// Jobs is the durable task queue. Modules enqueue work and register
	// handlers on it; the worker pool runs them.
	Jobs *jobs.Queue
}

// Module is one product service plugged into the platform. It registers its
// routes against the shared mux; the platform wires the rest.
type Module interface {
	Name() string
	Routes(mux *http.ServeMux)
}
