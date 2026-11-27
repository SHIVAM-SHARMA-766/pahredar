package easm

import (
	"context"
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

// analyzeDependencies queues an OSV analysis of the asset's dependency records;
// vulnerable ones become findings that roll into the asset's incident. Queued
// (not inline) so a large SBOM does not hit the request timeout.
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
	jobID, err := s.Jobs.Enqueue(r.Context(), AnalyzeTaskType, analyzePayload{AssetID: a.ID}, 1)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID, "dependencies": len(records)})
}

// runDependencyAnalysis queries OSV for the asset's dependencies and writes the
// vulnerable ones as findings.
func (s *Service) runDependencyAnalysis(ctx context.Context, assetID int64) error {
	records, err := s.Store.ListRecords(ctx, assetID, "dependency")
	if err != nil {
		return err
	}
	findings := s.analyzeDeps(ctx, assetID, records)
	// Refresh: clear prior dependency findings so fixed vulns disappear.
	if derr := s.Store.DeleteAlertsByType(ctx, assetID, "dependency"); derr != nil {
		s.Log.Warn("clear old dependency findings failed", "err", derr)
	}
	newOnes := []db.Alert{}
	if len(findings) > 0 {
		if newOnes, err = s.Store.InsertAlerts(ctx, findings); err != nil {
			return err
		}
	}
	s.Log.Info("easm dependency analysis", "asset_id", assetID, "deps", len(records), "findings", len(findings), "new", len(newOnes))
	return nil
}
