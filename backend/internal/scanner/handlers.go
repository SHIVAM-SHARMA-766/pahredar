package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/jobs"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

// scanReuse: a passive scan of a host within this window is reused.
const scanReuse = 60 * time.Second

// scanTaskType is the durable task queue type for endpoint scans.
const scanTaskType = "scan.run"

// scanTaskPayload is what runScan enqueues.
type scanTaskPayload struct {
	Target string               `json:"target"`
	Host   string               `json:"host"`
	Active bool                 `json:"active"`
	Filter *scan.TemplateFilter `json:"filter,omitempty"`
}

// scanTaskResult is stored on the task as progress accrues and on completion.
type scanTaskResult struct {
	Host     string        `json:"host"`
	Active   bool          `json:"active"`
	Progress scan.Progress `json:"progress"`
	Report   *scan.Report  `json:"report,omitempty"`
	StoredID int64         `json:"stored_id,omitempty"`
	Cached   bool          `json:"cached"`
}

// scanJobView is the shape the UI polls (unchanged from the in-memory version).
type scanJobView struct {
	ID       int64         `json:"id"`
	Target   string        `json:"target"`
	Host     string        `json:"host"`
	Active   bool          `json:"active"`
	Status   string        `json:"status"`
	Progress scan.Progress `json:"progress"`
	Report   *scan.Report  `json:"report,omitempty"`
	StoredID int64         `json:"stored_id,omitempty"`
	Cached   bool          `json:"cached"`
	Error    string        `json:"error,omitempty"`
}

// registerScanJobs wires the scan task handler onto the queue. Called from New.
func (s *Service) registerScanJobs() {
	if s.Jobs != nil {
		s.Jobs.Register(scanTaskType, s.handleScanTask)
	}
}

// runScan enqueues a scan and returns its job id. Body:
// {"target","active"?,"authorized"?,"fresh"?,"templates"?}.
func (s *Service) runScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target     string               `json:"target"`
		Fresh      bool                 `json:"fresh"`
		Active     bool                 `json:"active"`
		Authorized bool                 `json:"authorized"`
		Templates  *scan.TemplateFilter `json:"templates"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil || body.Target == "" {
		platform.WriteError(w, http.StatusBadRequest, `body must be {"target": "example.com"}`)
		return
	}
	host, _, err := scan.ParseTarget(body.Target)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Active {
		if !s.scanner.ActiveAvailable() {
			platform.WriteError(w, http.StatusBadRequest, "active scanning is not enabled on this server (set SCAN_ACTIVE_ENABLED=true)")
			return
		}
		if !body.Authorized {
			platform.WriteError(w, http.StatusForbidden, "active scanning sends intrusive requests; confirm you are authorised to test this target")
			return
		}
	}
	payload := scanTaskPayload{Target: body.Target, Host: host, Active: body.Active, Filter: body.Templates}

	// A recent passive scan is reused without re-running: record it as an
	// already-done task so the client polls it the same way.
	if !body.Fresh && !body.Active {
		if id, raw, ok, lerr := s.Store.LatestScanFor(r.Context(), host, time.Now().Add(-scanReuse)); lerr == nil && ok {
			var rep scan.Report
			if json.Unmarshal(raw, &rep) == nil {
				result := scanTaskResult{Host: host, Report: &rep, StoredID: id, Cached: true}
				if jobID, eerr := s.Jobs.EnqueueDone(r.Context(), scanTaskType, payload, result); eerr == nil {
					platform.WriteJSON(w, http.StatusOK, map[string]any{"id": jobID})
					return
				}
			}
		}
	}

	jobID, err := s.Jobs.Enqueue(r.Context(), scanTaskType, payload, 1)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusAccepted, map[string]any{"id": jobID})
}

// handleScanTask runs one scan task, streaming progress onto the task row and
// storing the final report.
func (s *Service) handleScanTask(ctx context.Context, payload json.RawMessage, progress jobs.Progress) (any, error) {
	var p scanTaskPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	// Bound concurrent scans.
	select {
	case s.scanSem <- struct{}{}:
		defer func() { <-s.scanSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	res := &scanTaskResult{Host: p.Host, Active: p.Active}
	timeout := 45 * time.Second
	if p.Active {
		timeout = 8 * time.Minute
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rep, err := s.scanner.Scan(sctx, p.Target, p.Active, p.Filter, func(pr scan.Progress) {
		res.Progress = pr
		progress(res)
	})
	if err != nil {
		return nil, err
	}
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer saveCancel()
	id, _ := s.Store.SaveScan(saveCtx, rep)
	res.Report = rep
	res.StoredID = id
	return res, nil
}

// scanJobStatus returns a job's current state (for polling), read from the
// durable task row so it survives restarts.
func (s *Service) scanJobStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	t, err := s.Jobs.Get(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "scan job not found (it may have expired); start a new scan")
		return
	}
	view := scanJobView{ID: t.ID, Status: t.Status, Error: t.Error}
	var p scanTaskPayload
	if json.Unmarshal(t.Payload, &p) == nil {
		view.Target, view.Host, view.Active = p.Target, p.Host, p.Active
	}
	if len(t.Result) > 0 {
		var res scanTaskResult
		if json.Unmarshal(t.Result, &res) == nil {
			view.Progress = res.Progress
			view.Report = res.Report
			view.StoredID = res.StoredID
			view.Cached = res.Cached
			if res.Host != "" {
				view.Host = res.Host
			}
		}
	}
	platform.WriteJSON(w, http.StatusOK, view)
}

func (s *Service) listScans(w http.ResponseWriter, r *http.Request) {
	out, err := s.Store.RecentScans(r.Context(), platform.BoundedInt(r, "limit", 25, 1, 100))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	payload, _, err := s.Store.GetScan(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "scan not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

// scanRequest sends one user-defined HTTP request (the request tool) and
// returns the raw request and response for inspection.
func (s *Service) scanRequest(w http.ResponseWriter, r *http.Request) {
	var spec scan.RequestSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&spec); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.scanner.SendRequest(ctx, spec)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, res)
}

// scanConfig tells the UI which scanner capabilities the server enables and,
// when active scanning is on, the Nuclei template categories it covers.
func (s *Service) scanConfig(w http.ResponseWriter, r *http.Request) {
	catalog := s.scanner.ActiveCatalog()
	total := 0
	for _, c := range catalog {
		total += c.Count
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{
		"active_available": s.scanner.ActiveAvailable(),
		"allow_private":    s.scanner.AllowsPrivate(),
		"active_catalog":   catalog,
		"active_total":     total,
	})
}
