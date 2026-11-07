package db

import (
	"context"
	"time"
)

// EscalationStep is one level of a policy: notify a channel and/or the on-call
// user, then wait delay_minutes for an acknowledgement before the next step.
type EscalationStep struct {
	ID           int64  `json:"id"`
	Position     int    `json:"position"`
	DelayMinutes int    `json:"delay_minutes"`
	ChannelID    *int64 `json:"channel_id,omitempty"`
	NotifyOncall bool   `json:"notify_oncall"`
}

// EscalationPolicy is an ordered set of steps, global or per-client.
type EscalationPolicy struct {
	ID        int64            `json:"id"`
	ClientID  *int64           `json:"client_id,omitempty"`
	Name      string           `json:"name"`
	IsDefault bool             `json:"is_default"`
	CreatedAt time.Time        `json:"created_at"`
	Steps     []EscalationStep `json:"steps"`
}

// CreateEscalationPolicy inserts a policy. When isDefault, it first clears any
// existing default in the same scope.
func (s *Store) CreateEscalationPolicy(ctx context.Context, clientID *int64, name string, isDefault bool) (EscalationPolicy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return EscalationPolicy{}, err
	}
	defer tx.Rollback(ctx)
	if isDefault {
		if _, err := tx.Exec(ctx, `UPDATE escalation_policy SET is_default = false WHERE is_default AND COALESCE(client_id,0) = COALESCE($1::bigint,0)`, clientID); err != nil {
			return EscalationPolicy{}, err
		}
	}
	var p EscalationPolicy
	err = tx.QueryRow(ctx, `
		INSERT INTO escalation_policy (client_id, name, is_default) VALUES ($1, $2, $3)
		RETURNING id, client_id, name, is_default, created_at`, clientID, name, isDefault).
		Scan(&p.ID, &p.ClientID, &p.Name, &p.IsDefault, &p.CreatedAt)
	if err != nil {
		return EscalationPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return EscalationPolicy{}, err
	}
	p.Steps = []EscalationStep{}
	return p, nil
}

// ListEscalationPolicies returns policies (with steps) scoped to the caller.
func (s *Store) ListEscalationPolicies(ctx context.Context, allClients bool, clientIDs []int64) ([]EscalationPolicy, error) {
	q := `SELECT id, client_id, name, is_default, created_at FROM escalation_policy`
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
	out := []EscalationPolicy{}
	for rows.Next() {
		var p EscalationPolicy
		if err := rows.Scan(&p.ID, &p.ClientID, &p.Name, &p.IsDefault, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		steps, err := s.StepsForPolicy(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Steps = steps
	}
	return out, nil
}

// GetEscalationPolicy returns one policy with its steps, or pgx.ErrNoRows.
func (s *Store) GetEscalationPolicy(ctx context.Context, id int64) (*EscalationPolicy, error) {
	var p EscalationPolicy
	err := s.pool.QueryRow(ctx, `
		SELECT id, client_id, name, is_default, created_at FROM escalation_policy WHERE id = $1`, id).
		Scan(&p.ID, &p.ClientID, &p.Name, &p.IsDefault, &p.CreatedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	steps, err := s.StepsForPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Steps = steps
	return &p, nil
}

// StepsForPolicy returns a policy's steps ordered by position.
func (s *Store) StepsForPolicy(ctx context.Context, policyID int64) ([]EscalationStep, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, position, delay_minutes, channel_id, notify_oncall
		FROM escalation_step WHERE policy_id = $1 ORDER BY position`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EscalationStep{}
	for rows.Next() {
		var st EscalationStep
		if err := rows.Scan(&st.ID, &st.Position, &st.DelayMinutes, &st.ChannelID, &st.NotifyOncall); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// UpdateEscalationPolicy updates name and default flag (clearing a prior default).
func (s *Store) UpdateEscalationPolicy(ctx context.Context, id int64, name string, isDefault bool) (EscalationPolicy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return EscalationPolicy{}, err
	}
	defer tx.Rollback(ctx)
	var p EscalationPolicy
	if err := tx.QueryRow(ctx, `SELECT client_id FROM escalation_policy WHERE id = $1`, id).Scan(&p.ClientID); err != nil {
		return EscalationPolicy{}, err
	}
	if isDefault {
		if _, err := tx.Exec(ctx, `UPDATE escalation_policy SET is_default = false WHERE is_default AND COALESCE(client_id,0) = COALESCE($1::bigint,0) AND id <> $2`, p.ClientID, id); err != nil {
			return EscalationPolicy{}, err
		}
	}
	err = tx.QueryRow(ctx, `
		UPDATE escalation_policy SET name = $2, is_default = $3 WHERE id = $1
		RETURNING id, client_id, name, is_default, created_at`, id, name, isDefault).
		Scan(&p.ID, &p.ClientID, &p.Name, &p.IsDefault, &p.CreatedAt)
	if err != nil {
		return EscalationPolicy{}, err
	}
	return p, tx.Commit(ctx)
}

// DeleteEscalationPolicy removes a policy (its steps cascade).
func (s *Store) DeleteEscalationPolicy(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM escalation_policy WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ReplacePolicySteps replaces a policy's steps with the given ordered list.
func (s *Store) ReplacePolicySteps(ctx context.Context, policyID int64, steps []EscalationStep) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM escalation_step WHERE policy_id = $1`, policyID); err != nil {
		return err
	}
	for i, st := range steps {
		if _, err := tx.Exec(ctx, `
			INSERT INTO escalation_step (policy_id, position, delay_minutes, channel_id, notify_oncall)
			VALUES ($1, $2, $3, $4, $5)`, policyID, i, st.DelayMinutes, st.ChannelID, st.NotifyOncall); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DefaultPolicyID returns the policy that should drive an incident for clientID:
// the client's default if set, else the global default. Returns 0 when none.
func (s *Store) DefaultPolicyID(ctx context.Context, clientID *int64) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM escalation_policy
		WHERE is_default AND (client_id = $1 OR client_id IS NULL)
		ORDER BY (client_id IS NOT NULL) DESC LIMIT 1`, clientID).Scan(&id)
	if IsNotFound(err) {
		return 0, nil
	}
	return id, err
}

// IncidentEsc carries an incident plus its escalation state for the walk.
type IncidentEsc struct {
	Incident
	PolicyID      *int64
	EscStep       int
	EscNotifiedAt *time.Time
	Delivered     bool
}

// OpenIncidentsForEscalation returns non-resolved incidents with their
// escalation state, for the delivery walk.
func (s *Store) OpenIncidentsForEscalation(ctx context.Context, limit int) ([]IncidentEsc, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.asset_id, i.client_id, i.status, i.severity, i.title, i.item_count, i.last_event_at,
		       COALESCE(a.value,''), COALESCE(c.name,''),
		       i.policy_id, i.esc_step, i.esc_notified_at, (i.delivered_at IS NOT NULL)
		FROM incident i
		JOIN asset a ON a.id = i.asset_id
		LEFT JOIN client c ON c.id = i.client_id
		WHERE i.status <> 'resolved'
		ORDER BY i.last_event_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IncidentEsc{}
	for rows.Next() {
		var e IncidentEsc
		if err := rows.Scan(&e.ID, &e.AssetID, &e.ClientID, &e.Status, &e.Severity, &e.Title, &e.ItemCount, &e.LastEventAt,
			&e.AssetValue, &e.ClientName, &e.PolicyID, &e.EscStep, &e.EscNotifiedAt, &e.Delivered); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetIncidentEscalation records that an incident was notified at a step, and
// stamps it delivered.
func (s *Store) SetIncidentEscalation(ctx context.Context, id int64, step int, policyID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE incident SET esc_step = $2, esc_notified_at = now(), policy_id = $3, delivered_at = now()
		WHERE id = $1`, id, step, policyID)
	return err
}
