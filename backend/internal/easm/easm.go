package easm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/jobs"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// TaskType is the durable job type for a passive EASM scan.
const TaskType = "easm.passive"

// Service is the EASM module: it runs attack-surface scans against assets and
// stores evidence records. S1 is the passive Domain Intelligence engine.
type Service struct {
	*platform.Platform
}

// New builds the EASM service and registers its passive-scan job handler.
func New(p *platform.Platform) *Service {
	s := &Service{Platform: p}
	if s.Jobs != nil {
		s.Jobs.Register(TaskType, s.handlePassiveTask)
	}
	return s
}

func (s *Service) Name() string { return "easm" }

func (s *Service) Routes(mux *http.ServeMux) {
	// Passive discovery is an action (external lookups + writes records): operator+.
	mux.HandleFunc("POST /api/v1/easm/scan", platform.Guard(platform.RoleOperator, s.scan))
	// Evidence is private monitoring data: viewer+ within the asset's client.
	mux.HandleFunc("GET /api/v1/easm/assets/{id}/records", platform.Guard(platform.RoleViewer, s.records))
	mux.HandleFunc("GET /api/v1/easm/assets/{id}/runs", platform.Guard(platform.RoleViewer, s.runs))
	mux.HandleFunc("GET /api/v1/easm/assets/{id}/summary", platform.Guard(platform.RoleViewer, s.summary))
	// Promote a discovered hostname to a tracked asset (operator decision).
	mux.HandleFunc("POST /api/v1/easm/promote", platform.Guard(platform.RoleOperator, s.promote))
}

type passivePayload struct {
	AssetID  int64  `json:"asset_id"`
	ClientID *int64 `json:"client_id"`
	Domain   string `json:"domain"`
}

// scan enqueues a passive EASM scan for an accessible, domain-like asset.
func (s *Service) scan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AssetID int64 `json:"asset_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.AssetID == 0 {
		platform.WriteError(w, http.StatusBadRequest, `body must be {"asset_id": <id>}`)
		return
	}
	a, ok := s.accessibleAsset(w, r, body.AssetID)
	if !ok {
		return
	}
	domain := domainOf(a)
	if domain == "" {
		platform.WriteError(w, http.StatusBadRequest, "passive scan needs a domain or URL asset")
		return
	}
	jobID, err := s.Jobs.Enqueue(r.Context(), TaskType, passivePayload{AssetID: a.ID, ClientID: a.ClientID, Domain: domain}, 1)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID})
}

func (s *Service) records(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	out, err := s.Store.ListRecords(r.Context(), a.ID, r.URL.Query().Get("category"))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) runs(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	out, err := s.Store.ListScanRuns(r.Context(), a.ID, platform.BoundedInt(r, "limit", 20, 1, 100))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handlePassiveTask runs a queued passive scan.
func (s *Service) handlePassiveTask(ctx context.Context, payload json.RawMessage, _ jobs.Progress) (any, error) {
	var p passivePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	if err := s.runScan(ctx, p.AssetID, p.ClientID, p.Domain); err != nil {
		return nil, err
	}
	return map[string]any{"asset_id": p.AssetID}, nil
}

// accessibleAsset loads an asset by id and checks the caller's client access
// (tenant mismatch → 404).
func (s *Service) accessibleAsset(w http.ResponseWriter, r *http.Request, id int64) (*db.Asset, bool) {
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "asset not found")
		return nil, false
	}
	p := platform.PrincipalFrom(r.Context())
	ok := p.AllClients
	if !ok {
		ok = a.ClientID != nil && p.CanAccessClient(*a.ClientID)
	}
	if !ok {
		platform.WriteError(w, http.StatusNotFound, "asset not found")
		return nil, false
	}
	return a, true
}

func (s *Service) accessibleAssetByPath(w http.ResponseWriter, r *http.Request) (*db.Asset, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return nil, false
	}
	return s.accessibleAsset(w, r, id)
}

// domainOf returns the registrable hostname for a domain or URL asset, else "".
func domainOf(a *db.Asset) string {
	switch a.Kind {
	case "domain":
		return strings.ToLower(strings.TrimSpace(a.Value))
	case "url":
		if u, err := url.Parse(a.Value); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return ""
}
