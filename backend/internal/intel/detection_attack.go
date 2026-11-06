package intel

import (
	"errors"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/cverecord"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// cveDetection lists the Sigma, Suricata, and Nmap rules naming a CVE. Scan
// commands built from exploit modules and affected packages are assembled
// by the frontend from data it already has.
func (s *Service) cveDetection(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		platform.WriteError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	out, err := s.Store.DetectionForCVE(r.Context(), id, 500)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if out == nil {
		out = []db.DetectionOut{}
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"rules": out})
}

// cveAttack places a CVE in an attack: CTID's ATT&CK mappings (KEV CVEs)
// and the CAPEC attack patterns related to its CWEs.
func (s *Service) cveAttack(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cverecord.IDPattern.MatchString(id) {
		platform.WriteError(w, http.StatusBadRequest, "id must look like CVE-2024-12345")
		return
	}
	d, err := s.Store.GetCVE(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		platform.WriteError(w, http.StatusNotFound, "CVE not found")
		return
	}
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	mappings, err := s.Store.AttackMappings(r.Context(), id)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	patterns, err := s.Store.CAPECForCWEs(r.Context(), d.CWEIDs, 8)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"mappings": orEmpty(mappings), "capec": orEmpty(patterns)})
}
