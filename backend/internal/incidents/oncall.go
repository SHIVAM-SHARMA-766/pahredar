package incidents

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/platform"
)

// On-call schedules (Phase 4C-M3). Same scope rule as channels/policies: global
// schedules are admin-only, client schedules need access to that client.

func (s *Service) listSchedules(w http.ResponseWriter, r *http.Request) {
	p := platform.PrincipalFrom(r.Context())
	out, err := s.Store.ListOnCallSchedules(r.Context(), p.AllClients, p.ClientIDs)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) createSchedule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID *int64 `json:"client_id"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
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
		platform.WriteError(w, http.StatusForbidden, "you cannot manage schedules for that scope")
		return
	}
	sc, err := s.Store.CreateOnCallSchedule(r.Context(), body.ClientID, body.Name)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusCreated, sc)
}

func (s *Service) scheduleForRequest(w http.ResponseWriter, r *http.Request) (*db.OnCallSchedule, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return nil, false
	}
	sc, err := s.Store.GetOnCallSchedule(r.Context(), id)
	if err != nil {
		platform.WriteError(w, http.StatusNotFound, "schedule not found")
		return nil, false
	}
	if !mayManageChannel(platform.PrincipalFrom(r.Context()), sc.ClientID) {
		platform.WriteError(w, http.StatusNotFound, "schedule not found")
		return nil, false
	}
	return sc, true
}

func (s *Service) getSchedule(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.scheduleForRequest(w, r)
	if !ok {
		return
	}
	platform.WriteJSON(w, http.StatusOK, sc)
}

func (s *Service) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.scheduleForRequest(w, r)
	if !ok {
		return
	}
	if _, err := s.Store.DeleteOnCallSchedule(r.Context(), sc.ID); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": sc.ID})
}

func (s *Service) addShift(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.scheduleForRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		UserID   int64     `json:"user_id"`
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		platform.WriteError(w, http.StatusBadRequest, "invalid request body (starts_at/ends_at must be RFC3339)")
		return
	}
	if body.UserID == 0 || !body.EndsAt.After(body.StartsAt) {
		platform.WriteError(w, http.StatusBadRequest, "user_id and starts_at < ends_at are required")
		return
	}
	sh, err := s.Store.AddOnCallShift(r.Context(), sc.ID, body.UserID, body.StartsAt, body.EndsAt)
	if err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusCreated, sh)
}

func (s *Service) deleteShift(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, "id must be a number")
		return
	}
	sid, serr := s.Store.ScheduleOfShift(r.Context(), id)
	if serr != nil {
		platform.WriteError(w, http.StatusNotFound, "shift not found")
		return
	}
	sc, err := s.Store.GetOnCallSchedule(r.Context(), sid)
	if err != nil || !mayManageChannel(platform.PrincipalFrom(r.Context()), sc.ClientID) {
		platform.WriteError(w, http.StatusNotFound, "shift not found")
		return
	}
	if _, err := s.Store.DeleteOnCallShift(r.Context(), id); err != nil {
		platform.InternalError(w, r, err)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
