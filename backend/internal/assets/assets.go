// Package assets is the Asset Inventory service: the things the operator tracks
// (domains, URLs, IPs, products, repos) and the hub that ties scanner results
// and CVE matches to them. Assets belong to a client and access is client-scoped
// (Phase 4 tenancy). See docs/roadmap.md Phase 2 and docs/phase4.md.
package assets

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
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
	// Inventory is private: viewer+ reads, operator+ mutates/scans. Every asset
	// belongs to a client; a caller only reaches assets of clients they may
	// access. See docs/auth.md and docs/phase4.md.
	mux.HandleFunc("GET /api/v1/assets", platform.Guard(platform.RoleViewer, s.list))
	mux.HandleFunc("POST /api/v1/assets", platform.Guard(platform.RoleOperator, s.create))
	mux.HandleFunc("GET /api/v1/assets/{id}", platform.Guard(platform.RoleViewer, s.get))
	mux.HandleFunc("DELETE /api/v1/assets/{id}", platform.Guard(platform.RoleOperator, s.delete))
	mux.HandleFunc("POST /api/v1/assets/{id}/scan", platform.Guard(platform.RoleOperator, s.scan))
	mux.HandleFunc("GET /api/v1/assets/{id}/scans", platform.Guard(platform.RoleViewer, s.scans))
	mux.HandleFunc("GET /api/v1/assets/{id}/cves", platform.Guard(platform.RoleViewer, s.cves))
}

// validKinds are the asset kinds; domain/url/ip are scannable endpoints.
var validKinds = map[string]bool{"domain": true, "url": true, "ip": true, "product": true, "repo": true}

func scannable(kind string) bool { return kind == "domain" || kind == "url" || kind == "ip" }

// canAccessAsset reports whether the principal may act on an asset. A legacy
// asset with no client is admin-only.
func canAccessAsset(p platform.Principal, a *db.Asset) bool {
	if a.ClientID == nil {
		return p.AllClients
	}
	return p.CanAccessClient(*a.ClientID)
}

// accessibleAsset parses {id}, loads the asset, and checks client access. On any
// failure it writes the response and returns false. A tenant mismatch is a 404
// so an asset's existence does not leak across clients.
func (s *Service) accessibleAsset(w http.ResponseWriter, r *http.Request) (*db.Asset, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return nil, false
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "asset not found")
		return nil, false
	}
	if !canAccessAsset(platform.PrincipalFrom(r.Context()), a) {
		platform.WriteError(w, http.StatusNotFound, "asset not found")
		return nil, false
	}
	return a, true
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	out, err := s.Store.ListAssets(r.Context(), p.AllClients, p.ClientIDs)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID int64    `json:"client_id"`
		Kind     string   `json:"kind"`
		Value    string   `json:"value"`
		Label    string   `json:"label"`
		Tags     []string `json:"tags"`
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
	if body.ClientID == 0 {
		platform.WriteError(w, http.StatusBadRequest, "client_id is required: an asset must belong to a client")
		return
	}
	// The client must exist and be one the caller may access.
	if _, err := s.Store.GetClient(r.Context(), body.ClientID); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "unknown client")
		return
	}
	if !platform.PrincipalFrom(r.Context()).CanAccessClient(body.ClientID) {
		platform.WriteError(w, http.StatusForbidden, "you do not have access to that client")
		return
	}
	id, err := s.Store.CreateAsset(r.Context(), body.ClientID, body.Kind, body.Value, body.Label, body.Tags)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAsset(w, r)
	if !ok {
		return
	}
	platform.WriteJSON(w, http.StatusOK, a)
}

func (s *Service) delete(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAsset(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteAsset(r.Context(), a.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": a.ID})
}

// cves returns the CVEs matched to an asset (persisted from its scans).
func (s *Service) cves(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAsset(w, r)
	if !ok {
		return
	}
	out, err := s.Store.AssetCVEs(r.Context(), a.ID)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// scans returns an asset's scan history.
func (s *Service) scans(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAsset(w, r)
	if !ok {
		return
	}
	out, err := s.Store.AssetScans(r.Context(), a.ID, platform.BoundedInt(r, "limit", 25, 1, 100))
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// scan enqueues a passive scan for a scannable asset and links the result.
func (s *Service) scan(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAsset(w, r)
	if !ok {
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
