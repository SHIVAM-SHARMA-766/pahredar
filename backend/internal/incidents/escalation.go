package incidents

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// Escalation policies (Phase 4C-M2). Global policies (no client) are admin-only;
// client policies need access to that client — same rule as channels.

func (s *Service) listPolicies(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	out, err := s.Store.ListEscalationPolicies(r.Context(), p.AllClients, p.ClientIDs)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type policyBody struct {
	ClientID  *int64              `json:"client_id"`
	Name      string              `json:"name"`
	IsDefault bool                `json:"is_default"`
	Steps     []db.EscalationStep `json:"steps"`
}

func (s *Service) createPolicy(w http.ResponseWriter, r *http.Request) {
	var body policyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		platform.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	p := platform.PrincipalFrom(r.Context())
	if body.ClientID != nil {
		if _, err := s.Store.GetClient(r.Context(), *body.ClientID); err != nil {
			platform.WriteError(w, http.StatusBadRequest, "unknown client")
			return
		}
	}
	if !mayManageChannel(p, body.ClientID) {
		platform.WriteError(w, http.StatusForbidden, "you cannot manage policies for that scope")
		return
	}
	pol, err := s.Store.CreateEscalationPolicy(r.Context(), body.ClientID, body.Name, body.IsDefault)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	if len(body.Steps) > 0 {
		if err := s.Store.ReplacePolicySteps(r.Context(), pol.ID, body.Steps); err != nil {
			platform.InternalError(w, r, err)
			return
		}
		pol.Steps, _ = s.Store.StepsForPolicy(r.Context(), pol.ID)
	}
	s.Log.Info("escalation policy created", "policy_id", pol.ID)
	platform.WriteJSON(w, http.StatusCreated, pol)
}

// policyForRequest loads a policy and checks management access.
func (s *Service) policyForRequest(w http.ResponseWriter, r *http.Request) (*db.EscalationPolicy, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return nil, false
	}
	pol, err := s.Store.GetEscalationPolicy(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "policy not found")
		return nil, false
	}
	if !mayManageChannel(platform.PrincipalFrom(r.Context()), pol.ClientID) {
		platform.WriteError(w, http.StatusNotFound, "policy not found")
		return nil, false
	}
	return pol, true
}

func (s *Service) getPolicy(w http.ResponseWriter, r *http.Request) {
	pol, ok := s.policyForRequest(w, r)
	if !ok {
		return
	}
	platform.WriteJSON(w, http.StatusOK, pol)
}

func (s *Service) patchPolicy(w http.ResponseWriter, r *http.Request) {
	pol, ok := s.policyForRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		Name      *string `json:"name"`
		IsDefault *bool   `json:"is_default"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name, isDefault := pol.Name, pol.IsDefault
	if body.Name != nil {
		name = strings.TrimSpace(*body.Name)
	}
	if body.IsDefault != nil {
		isDefault = *body.IsDefault
	}
	out, err := s.Store.UpdateEscalationPolicy(r.Context(), pol.ID, name, isDefault)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	out.Steps, _ = s.Store.StepsForPolicy(r.Context(), pol.ID)
	platform.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) setPolicySteps(w http.ResponseWriter, r *http.Request) {
	pol, ok := s.policyForRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		Steps []db.EscalationStep `json:"steps"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.Store.ReplacePolicySteps(r.Context(), pol.ID, body.Steps); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) deletePolicy(w http.ResponseWriter, r *http.Request) {
	pol, ok := s.policyForRequest(w, r)
	if !ok {
		return
	}
	if _, err := s.Store.DeleteEscalationPolicy(r.Context(), pol.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": pol.ID})
}
