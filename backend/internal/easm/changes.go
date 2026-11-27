package easm

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Change detection is a *derived* view over the record store (no separate
// storage): records carry first_seen/last_seen, so comparing them against two
// scan runs' time windows tells us what appeared and what was not re-observed.
//
// Semantics (comparing a reference run `since` against the latest scan):
//   - added   = records first seen after the `since` run finished — new surface.
//   - removed = records not re-observed by the latest scan (last_seen before it
//     started) — gone, or not covered by the latest scan's profile (noted).
//
// This answers "what changed since last time" without snapshotting every run.

// RecordChange is one record in a change set, trimmed for the diff view.
type RecordChange struct {
	Category  string    `json:"category"`
	Key       string    `json:"key"`
	Source    string    `json:"source"`
	Method    string    `json:"method"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ChangeSet is the diff between a reference run and the latest scan.
type ChangeSet struct {
	AssetID   int64          `json:"asset_id"`
	SinceRun  *db.ScanRun    `json:"since_run,omitempty"`
	LatestRun *db.ScanRun    `json:"latest_run,omitempty"`
	Added     []RecordChange `json:"added"`
	Removed   []RecordChange `json:"removed"`
	AddedBy   map[string]int `json:"added_by_category"`
	RemovedBy map[string]int `json:"removed_by_category"`
	Note      string         `json:"note,omitempty"`
}

// buildChanges diffs an asset's current records against the `since` run, treating
// `latest` as the most recent scan. Pure; no I/O.
func buildChanges(assetID int64, records []db.AssetRecord, since, latest *db.ScanRun) ChangeSet {
	cs := ChangeSet{
		AssetID: assetID, SinceRun: since, LatestRun: latest,
		Added: []RecordChange{}, Removed: []RecordChange{},
		AddedBy: map[string]int{}, RemovedBy: map[string]int{},
	}
	if since == nil || latest == nil {
		cs.Note = "need at least two scan runs to compare"
		return cs
	}
	// A record is "new since" if it was first seen strictly after the reference
	// run completed (records found *by* that run share its window).
	sinceCutoff := since.StartedAt
	if since.FinishedAt != nil {
		sinceCutoff = *since.FinishedAt
	}
	for _, rec := range records {
		rc := RecordChange{
			Category: rec.Category, Key: rec.Key, Source: rec.Source,
			Method: rec.Method, FirstSeen: rec.FirstSeen, LastSeen: rec.LastSeen,
		}
		switch {
		case rec.FirstSeen.After(sinceCutoff):
			cs.Added = append(cs.Added, rc)
			cs.AddedBy[rec.Category]++
		case rec.LastSeen.Before(latest.StartedAt):
			// Present before, not re-observed by the latest scan.
			cs.Removed = append(cs.Removed, rc)
			cs.RemovedBy[rec.Category]++
		}
	}
	sortChanges(cs.Added)
	sortChanges(cs.Removed)
	if len(cs.Removed) > 0 {
		cs.Note = "removed = not re-observed by the latest scan; a narrower scan profile can also leave records unseen"
	}
	return cs
}

func sortChanges(cs []RecordChange) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Category != cs[j].Category {
			return cs[i].Category < cs[j].Category
		}
		return cs[i].Key < cs[j].Key
	})
}

// changes serves the change set for an asset. ?since=<runID> picks the reference
// run; by default it is the run just before the latest.
func (s *Service) changes(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	runs, err := s.Store.ListScanRuns(r.Context(), a.ID, 50)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	var latest, since *db.ScanRun
	if len(runs) > 0 {
		latest = &runs[0]
	}
	if sinceID, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64); sinceID > 0 {
		for i := range runs {
			if runs[i].ID == sinceID {
				since = &runs[i]
				break
			}
		}
	} else if len(runs) > 1 {
		since = &runs[1]
	}
	records, err := s.Store.ListRecords(r.Context(), a.ID, "")
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, buildChanges(a.ID, records, since, latest))
}
