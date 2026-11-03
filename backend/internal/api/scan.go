package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

// scanReuse: a passive scan of a host within this window is reused.
const scanReuse = 60 * time.Second

// scanJobTTL: finished jobs are kept this long so a returning client can
// still read the result.
const scanJobTTL = 15 * time.Minute

// scanJob is one running or finished scan. The scan runs in a background
// goroutine detached from the request, so navigating away does not cancel
// it; the client polls for progress and the result.
type scanJob struct {
	ID       int64         `json:"id"`
	Target   string        `json:"target"`
	Host     string        `json:"host"`
	Active   bool          `json:"active"`
	Status   string        `json:"status"` // queued, running, done, error
	Progress scan.Progress `json:"progress"`
	Report   *scan.Report  `json:"report,omitempty"`
	StoredID int64         `json:"stored_id,omitempty"`
	Error    string        `json:"error,omitempty"`
	Cached   bool          `json:"cached"`
	started  time.Time
	finished time.Time
}

// snapshot returns a copy safe to serialise outside the lock.
func (j *scanJob) snapshot() scanJob {
	c := *j
	return c
}

// runScan starts a scan job and returns its id. Body:
// {"target","active"?,"authorized"?,"fresh"?}.
func (s *Server) runScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target     string `json:"target"`
		Fresh      bool   `json:"fresh"`
		Active     bool   `json:"active"`
		Authorized bool   `json:"authorized"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil || body.Target == "" {
		writeError(w, http.StatusBadRequest, `body must be {"target": "example.com"}`)
		return
	}
	host, _, err := scan.ParseTarget(body.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Active {
		if !s.scanner.ActiveAvailable() {
			writeError(w, http.StatusBadRequest, "active scanning is not enabled on this server (set SCAN_ACTIVE_ENABLED=true)")
			return
		}
		if !body.Authorized {
			writeError(w, http.StatusForbidden, "active scanning sends intrusive requests; confirm you are authorised to test this target")
			return
		}
	}

	// A recent passive scan is reused without re-running.
	if !body.Fresh && !body.Active {
		if id, payload, ok, err := s.store.LatestScanFor(r.Context(), host, time.Now().Add(-scanReuse)); err == nil && ok {
			var rep scan.Report
			if json.Unmarshal(payload, &rep) == nil {
				job := s.newJob(body.Target, host, false)
				job.Status = "done"
				job.Report = &rep
				job.StoredID = id
				job.Cached = true
				job.finished = time.Now()
				writeJSON(w, http.StatusOK, map[string]any{"id": job.ID})
				return
			}
		}
	}

	job := s.newJob(body.Target, host, body.Active)
	go s.execJob(job)
	writeJSON(w, http.StatusAccepted, map[string]any{"id": job.ID})
}

func (s *Server) newJob(target, host string, active bool) *scanJob {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	s.nextJob++
	j := &scanJob{ID: s.nextJob, Target: target, Host: host, Active: active, Status: "queued", started: time.Now()}
	s.jobs[j.ID] = j
	return j
}

func (s *Server) execJob(job *scanJob) {
	// Bound concurrent scans; the job waits (queued) for a slot.
	s.scanSem <- struct{}{}
	defer func() { <-s.scanSem }()

	s.updateJob(job.ID, func(j *scanJob) { j.Status = "running" })

	timeout := 45 * time.Second
	if job.Active {
		timeout = 8 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rep, err := s.scanner.Scan(ctx, job.Target, job.Active, func(p scan.Progress) {
		s.updateJob(job.ID, func(j *scanJob) { j.Progress = p })
	})
	if err != nil {
		s.updateJob(job.ID, func(j *scanJob) { j.Status = "error"; j.Error = err.Error(); j.finished = time.Now() })
		return
	}
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer saveCancel()
	id, _ := s.store.SaveScan(saveCtx, rep)
	s.updateJob(job.ID, func(j *scanJob) {
		j.Status = "done"
		j.Report = rep
		j.StoredID = id
		j.finished = time.Now()
	})
}

func (s *Server) updateJob(id int64, fn func(*scanJob)) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if j, ok := s.jobs[id]; ok {
		fn(j)
	}
}

// scanJobStatus returns a job's current state (for polling).
func (s *Server) scanJobStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	s.jobsMu.Lock()
	j, ok := s.jobs[id]
	var snap scanJob
	if ok {
		snap = j.snapshot()
	}
	s.jobsMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "scan job not found (it may have expired); start a new scan")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// reapScanJobs removes finished jobs past their TTL.
func (s *Server) reapScanJobs() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-scanJobTTL)
		s.jobsMu.Lock()
		for id, j := range s.jobs {
			if !j.finished.IsZero() && j.finished.Before(cutoff) {
				delete(s.jobs, id)
			}
		}
		s.jobsMu.Unlock()
	}
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.RecentScans(r.Context(), boundedInt(r, "limit", 25, 1, 100))
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	payload, _, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

// scanConfig tells the UI which scanner capabilities the server enables and,
// when active scanning is on, the Nuclei template categories it covers (so the
// UI can show what the checks are, not just a total).
func (s *Server) scanConfig(w http.ResponseWriter, r *http.Request) {
	catalog := s.scanner.ActiveCatalog()
	total := 0
	for _, c := range catalog {
		total += c.Count
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active_available": s.scanner.ActiveAvailable(),
		"allow_private":    s.scanner.AllowsPrivate(),
		"active_catalog":   catalog,
		"active_total":     total,
	})
}
