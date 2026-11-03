package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
)

// scanReuse: a request for a host scanned within this window returns the
// stored report instead of scanning again.
const scanReuse = 60 * time.Second

// runScan assesses a public endpoint. Body: {"target": "example.com"}. It is
// non-intrusive (see package scan). A recent scan of the same host is reused.
func (s *Server) runScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
		Fresh  bool   `json:"fresh"`
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
	if !body.Fresh {
		if id, payload, ok, err := s.store.LatestScanFor(r.Context(), host, time.Now().Add(-scanReuse)); err == nil && ok {
			writeJSON(w, http.StatusOK, scanResponse{ID: id, Cached: true, Report: payload})
			return
		}
	}

	// Bound concurrent scans so the service cannot be used to fan out.
	select {
	case s.scanSem <- struct{}{}:
		defer func() { <-s.scanSem }()
	default:
		writeError(w, http.StatusTooManyRequests, "too many scans in progress; try again shortly")
		return
	}

	// A scan makes several slow requests; give it its own deadline and
	// extend the response write deadline to match.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 40*time.Second)
	defer cancel()

	rep, err := s.scanner.Scan(ctx, body.Target)
	if err != nil {
		if errors.Is(err, scan.ErrPrivate) || errors.Is(err, scan.ErrNoResolve) || errors.Is(err, scan.ErrBadTarget) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		internalError(w, r, err)
		return
	}
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer saveCancel()
	id, err := s.store.SaveScan(saveCtx, rep)
	if err != nil {
		internalError(w, r, err)
		return
	}
	payload, _ := json.Marshal(rep)
	writeJSON(w, http.StatusOK, scanResponse{ID: id, Report: payload})
}

type scanResponse struct {
	ID     int64           `json:"id"`
	Cached bool            `json:"cached"`
	Report json.RawMessage `json:"report"`
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
	payload, at, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, scanResponse{ID: id, Cached: time.Since(at) > scanReuse, Report: payload})
}
