package api

import (
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

const recentRunsLimit = 20

type syncStatusResponse struct {
	Sources    []db.SyncState `json:"sources"`
	RecentRuns []db.SyncRun   `json:"recent_runs"`
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
	writeJSON(w, http.StatusOK, syncStatusResponse{Sources: states, RecentRuns: runs})
}
