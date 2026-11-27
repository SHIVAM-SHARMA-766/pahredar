package easm

import (
	"encoding/json"
	"net/http"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Software dependency inventory (spec P08/P10 + the roadmap's stack matching):
// an operator loads a project's dependencies (from its manifests), stored as
// `dependency` evidence records, and OSV is queried to turn vulnerable versions
// into findings → the asset's incident.

type depInput struct {
	Ecosystem string `json:"ecosystem"` // OSV ecosystem: Go, npm, PyPI, ...
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// ingestDependencies stores a project's dependency inventory as evidence records.
func (s *Service) ingestDependencies(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Components []depInput `json:"components"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	n := 0
	for _, c := range body.Components {
		if c.Name == "" || c.Version == "" || c.Ecosystem == "" {
			continue
		}
		data, _ := json.Marshal(map[string]string{"ecosystem": c.Ecosystem, "name": c.Name, "version": c.Version})
		rec := db.AssetRecord{
			AssetID: a.ID, ClientID: a.ClientID,
			Category: "dependency", Key: c.Ecosystem + ":" + c.Name,
			Method: "passive", Source: "manifest", Data: data,
			Confidence: "high", Verification: "verified", Scope: "in_scope",
		}
		if _, err := s.Store.UpsertRecord(r.Context(), rec); err == nil {
			n++
		}
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ingested": n})
}

// analyzeDependencies queries OSV for the asset's dependency records and writes
// the vulnerable ones as findings (which roll into the asset's incident).
func (s *Service) analyzeDependencies(w http.ResponseWriter, r *http.Request) {
	a, ok := s.accessibleAssetByPath(w, r)
	if !ok {
		return
	}
	records, err := s.Store.ListRecords(r.Context(), a.ID, "dependency")
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	findings := s.analyzeDeps(r.Context(), a.ID, records)
	newOnes := []db.Alert{}
	if len(findings) > 0 {
		if newOnes, err = s.Store.InsertAlerts(r.Context(), findings); err != nil {
			platform.InternalError(w, r, err)
			return
		}
	}
	s.Log.Info("easm dependency analysis", "asset_id", a.ID, "deps", len(records), "findings", len(findings), "new", len(newOnes))
	platform.WriteJSON(w, http.StatusOK, map[string]any{"dependencies": len(records), "findings": len(findings), "new": len(newOnes)})
}
