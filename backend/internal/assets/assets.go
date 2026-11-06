// Package assets is the Asset Inventory service: the things the operator tracks
// (domains, URLs, IPs, products, repos) and the hub that ties scanner results
// and CVE matches to them. See docs/roadmap.md Phase 2.
package assets

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scan"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/scanner"
)

// Service holds the asset inventory over the shared platform.
type Service struct {
	*platform.Platform
}

// New builds the assets service.
func New(p *platform.Platform) *Service { return &Service{Platform: p} }

func (s *Service) Name() string { return "assets" }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/assets", s.list)
	mux.HandleFunc("POST /api/v1/assets", s.create)
	mux.HandleFunc("GET /api/v1/assets/{id}", s.get)
	mux.HandleFunc("DELETE /api/v1/assets/{id}", s.delete)
	mux.HandleFunc("POST /api/v1/assets/{id}/scan", s.scan)
	mux.HandleFunc("GET /api/v1/assets/{id}/scans", s.scans)
}

// validKinds are the asset kinds; domain/url/ip are scannable endpoints.
var validKinds = map[string]bool{"domain": true, "url": true, "ip": true, "product": true, "repo": true}

func scannable(kind string) bool { return kind == "domain" || kind == "url" || kind == "ip" }

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	out, err := s.Store.ListAssets(r.Context())
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind  string   `json:"kind"`
		Value string   `json:"value"`
		Label string   `json:"label"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Kind = strings.ToLower(strings.TrimSpace(body.Kind))
	body.Value = strings.TrimSpace(body.Value)
	if body.Value == "" || !validKinds[body.Kind] {
		platform.WriteError(w, http.StatusBadRequest, "kind must be one of domain, url, ip, product, repo and value is required")
		return
	}
	id, err := s.Store.CreateAsset(r.Context(), body.Kind, body.Value, body.Label, body.Tags)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "asset not found")
		return
	}
	platform.WriteJSON(w, http.StatusOK, a)
}

func (s *Service) delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	if err := s.Store.DeleteAsset(r.Context(), id); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// scans returns an asset's scan history.
func (s *Service) scans(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	out, err := s.Store.AssetScans(r.Context(), id, platform.BoundedInt(r, "limit", 25, 1, 100))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// scan enqueues a passive scan for a scannable asset and links the result.
func (s *Service) scan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "asset not found")
		return
	}
	if !scannable(a.Kind) {
		platform.WriteError(w, http.StatusBadRequest, "only domain, url, and ip assets can be scanned")
		return
	}
	host, _, perr := scan.ParseTarget(a.Value)
	if perr != nil {
		platform.WriteError(w, http.StatusBadRequest, perr.Error())
		return
	}
	payload := scanner.TaskPayload{Target: a.Value, Host: host, AssetID: a.ID}
	jobID, err := s.Jobs.Enqueue(r.Context(), scanner.TaskType, payload, 1)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID})
}
