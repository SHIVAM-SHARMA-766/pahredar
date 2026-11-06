package intel

import (
	"errors"
	"net/http"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/syncer"
)

const recentRunsLimit = 20

type syncStatusResponse struct {
	SchedulerEnabled bool           `json:"scheduler_enabled"`
	Sources          []db.SyncState `json:"sources"`
	RecentRuns       []db.SyncRun   `json:"recent_runs"`
}

func (s *Service) syncStatus(w http.ResponseWriter, r *http.Request) {
	states, err := s.Store.SyncStates(r.Context())
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	runs, err := s.Store.RecentRuns(r.Context(), recentRunsLimit)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if states == nil {
		states = []db.SyncState{}
	}
	if runs == nil {
		runs = []db.SyncRun{}
	}
	platform.WriteJSON(w, http.StatusOK, syncStatusResponse{SchedulerEnabled: s.sched != nil, Sources: states, RecentRuns: runs})
}

// triggerSync queues an immediate run of one source. The run itself happens
// in the scheduler; poll /sync/status for the outcome.
func (s *Service) triggerSync(w http.ResponseWriter, r *http.Request) {
	if s.sched == nil {
		platform.WriteError(w, http.StatusConflict, "sync scheduler is disabled (SYNC_ENABLED=false)")
		return
	}
	source := r.PathValue("source")
	if err := s.sched.Trigger(source); errors.Is(err, syncer.ErrUnknownSource) {
		platform.WriteError(w, http.StatusNotFound, "unknown source")
		return
	}
	platform.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "source": source})
}

func (s *Service) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.Dashboard(r.Context(), time.Now())
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, d)
}
