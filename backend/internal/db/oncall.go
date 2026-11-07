package db

import (
	"context"
	"time"
)

// OnCallSchedule is a named rota for a client (or global).
type OnCallSchedule struct {
	ID        int64         `json:"id"`
	ClientID  *int64        `json:"client_id,omitempty"`
	Name      string        `json:"name"`
	CreatedAt time.Time     `json:"created_at"`
	Shifts    []OnCallShift `json:"shifts,omitempty"`
}

// OnCallShift is one user on call for a window.
type OnCallShift struct {
	ID         int64     `json:"id"`
	ScheduleID int64     `json:"schedule_id"`
	UserID     int64     `json:"user_id"`
	UserEmail  string    `json:"user_email,omitempty"`
	StartsAt   time.Time `json:"starts_at"`
	EndsAt     time.Time `json:"ends_at"`
}

// CreateOnCallSchedule inserts a schedule.
func (s *Store) CreateOnCallSchedule(ctx context.Context, clientID *int64, name string) (OnCallSchedule, error) {
	var sc OnCallSchedule
	err := s.pool.QueryRow(ctx, `
		INSERT INTO oncall_schedule (client_id, name) VALUES ($1, $2)
		RETURNING id, client_id, name, created_at`, clientID, name).
		Scan(&sc.ID, &sc.ClientID, &sc.Name, &sc.CreatedAt)
	return sc, err
}

// ListOnCallSchedules returns schedules (with shifts) scoped to the caller.
func (s *Store) ListOnCallSchedules(ctx context.Context, allClients bool, clientIDs []int64) ([]OnCallSchedule, error) {
	q := `SELECT id, client_id, name, created_at FROM oncall_schedule`
	args := []any{}
	if !allClients {
		q += ` WHERE client_id IS NULL OR client_id = ANY($1)`
		args = append(args, clientIDs)
	}
	q += ` ORDER BY id`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OnCallSchedule{}
	for rows.Next() {
		var sc OnCallSchedule
		if err := rows.Scan(&sc.ID, &sc.ClientID, &sc.Name, &sc.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		sh, err := s.ShiftsForSchedule(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Shifts = sh
	}
	return out, nil
}

// GetOnCallSchedule returns one schedule (with shifts), or pgx.ErrNoRows.
func (s *Store) GetOnCallSchedule(ctx context.Context, id int64) (*OnCallSchedule, error) {
	var sc OnCallSchedule
	err := s.pool.QueryRow(ctx, `SELECT id, client_id, name, created_at FROM oncall_schedule WHERE id = $1`, id).
		Scan(&sc.ID, &sc.ClientID, &sc.Name, &sc.CreatedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sc.Shifts, err = s.ShiftsForSchedule(ctx, id)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

// DeleteOnCallSchedule removes a schedule (its shifts cascade).
func (s *Store) DeleteOnCallSchedule(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM oncall_schedule WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ShiftsForSchedule returns a schedule's shifts (with user email) by start time.
func (s *Store) ShiftsForSchedule(ctx context.Context, scheduleID int64) ([]OnCallShift, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sh.id, sh.schedule_id, sh.user_id, COALESCE(u.email,''), sh.starts_at, sh.ends_at
		FROM oncall_shift sh LEFT JOIN app_user u ON u.id = sh.user_id
		WHERE sh.schedule_id = $1 ORDER BY sh.starts_at`, scheduleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OnCallShift{}
	for rows.Next() {
		var sh OnCallShift
		if err := rows.Scan(&sh.ID, &sh.ScheduleID, &sh.UserID, &sh.UserEmail, &sh.StartsAt, &sh.EndsAt); err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

// AddOnCallShift inserts a shift.
func (s *Store) AddOnCallShift(ctx context.Context, scheduleID, userID int64, startsAt, endsAt time.Time) (OnCallShift, error) {
	var sh OnCallShift
	err := s.pool.QueryRow(ctx, `
		INSERT INTO oncall_shift (schedule_id, user_id, starts_at, ends_at) VALUES ($1, $2, $3, $4)
		RETURNING id, schedule_id, user_id, starts_at, ends_at`, scheduleID, userID, startsAt, endsAt).
		Scan(&sh.ID, &sh.ScheduleID, &sh.UserID, &sh.StartsAt, &sh.EndsAt)
	return sh, err
}

// DeleteOnCallShift removes one shift. Returns the schedule it belonged to (for
// access checks) and rows deleted.
func (s *Store) DeleteOnCallShift(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM oncall_shift WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ScheduleOfShift returns the schedule id a shift belongs to (for access checks).
func (s *Store) ScheduleOfShift(ctx context.Context, shiftID int64) (int64, error) {
	var sid int64
	err := s.pool.QueryRow(ctx, `SELECT schedule_id FROM oncall_shift WHERE id = $1`, shiftID).Scan(&sid)
	return sid, err
}

// OnCallEmail returns the email of whoever is on call for a client at time at —
// a shift covering at in the client's schedule, else a global schedule. Returns
// ok=false when nobody is on call.
func (s *Store) OnCallEmail(ctx context.Context, clientID *int64, at time.Time) (string, bool) {
	var email string
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(u.email, '')
		FROM oncall_shift sh
		JOIN oncall_schedule sc ON sc.id = sh.schedule_id
		JOIN app_user u ON u.id = sh.user_id
		WHERE sh.starts_at <= $2 AND sh.ends_at > $2 AND u.disabled_at IS NULL
		  AND (sc.client_id = $1 OR sc.client_id IS NULL)
		ORDER BY (sc.client_id IS NOT NULL) DESC, sh.starts_at DESC
		LIMIT 1`, clientID, at).Scan(&email)
	if err != nil || email == "" {
		return "", false
	}
	return email, true
}
