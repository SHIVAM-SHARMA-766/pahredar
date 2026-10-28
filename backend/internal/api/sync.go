package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

const recentRunsLimit = 20

type syncStatusResponse struct {
	SchedulerEnabled bool           `json:"scheduler_enabled"`
	Sources          []db.SyncState `json:"sources"`
	RecentRuns       []db.SyncRun   `json:"recent_runs"`
}

func (s *Server) syncStatus(w http.ResponseWriter, r *http.Request) {
	states, err := s.store.SyncStates(r.Context())
	if err != nil {
		internalError(w, r, err)
		return
	}
	runs, err := s.store.RecentRuns(r.Context(), recentRunsLimit)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if states == nil {
		states = []db.SyncState{}
	}
	if runs == nil {
		runs = []db.SyncRun{}
	}
	writeJSON(w, http.StatusOK, syncStatusResponse{SchedulerEnabled: s.sched != nil, Sources: states, RecentRuns: runs})
}

// triggerSync queues an immediate run of one source. The run itself happens
// in the scheduler; poll /sync/status for the outcome.
func (s *Server) triggerSync(w http.ResponseWriter, r *http.Request) {
	if s.sched == nil {
		writeError(w, http.StatusConflict, "sync scheduler is disabled (SYNC_ENABLED=false)")
		return
	}
	source := r.PathValue("source")
	if err := s.sched.Trigger(source); errors.Is(err, syncer.ErrUnknownSource) {
		writeError(w, http.StatusNotFound, "unknown source")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "source": source})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.Dashboard(r.Context(), time.Now())
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
