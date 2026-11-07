package db

import (
	"context"
	"time"
)

// Suppression mutes notifications for a scope during a window. A nil AssetID
// covers the whole client; a nil ClientID (and AssetID) is global.
type Suppression struct {
	ID        int64     `json:"id"`
	ClientID  *int64    `json:"client_id,omitempty"`
	AssetID   *int64    `json:"asset_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedAt time.Time `json:"created_at"`
	// Joined for display.
	ClientName string `json:"client_name,omitempty"`
	AssetValue string `json:"asset_value,omitempty"`
}

// CreateSuppression inserts a suppression window.
func (s *Store) CreateSuppression(ctx context.Context, clientID, assetID *int64, reason string, startsAt, endsAt time.Time) (Suppression, error) {
	var sp Suppression
	err := s.pool.QueryRow(ctx, `
		INSERT INTO suppression (client_id, asset_id, reason, starts_at, ends_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, client_id, asset_id, reason, starts_at, ends_at, created_at`,
		clientID, assetID, reason, startsAt, endsAt).
		Scan(&sp.ID, &sp.ClientID, &sp.AssetID, &sp.Reason, &sp.StartsAt, &sp.EndsAt, &sp.CreatedAt)
	return sp, err
}

// ListSuppressions returns suppression windows scoped to the caller (global ones
// plus those of clients they may access), newest first.
func (s *Store) ListSuppressions(ctx context.Context, allClients bool, clientIDs []int64) ([]Suppression, error) {
	q := `
		SELECT sp.id, sp.client_id, sp.asset_id, sp.reason, sp.starts_at, sp.ends_at, sp.created_at,
		       COALESCE(c.name,''), COALESCE(a.value,'')
		FROM suppression sp
		LEFT JOIN client c ON c.id = sp.client_id
		LEFT JOIN asset a ON a.id = sp.asset_id`
	args := []any{}
	if !allClients {
		q += ` WHERE sp.client_id IS NULL OR sp.client_id = ANY($1)`
		args = append(args, clientIDs)
	}
	q += ` ORDER BY sp.created_at DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Suppression{}
	for rows.Next() {
		var sp Suppression
		if err := rows.Scan(&sp.ID, &sp.ClientID, &sp.AssetID, &sp.Reason, &sp.StartsAt, &sp.EndsAt, &sp.CreatedAt, &sp.ClientName, &sp.AssetValue); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// GetSuppression returns one row or pgx.ErrNoRows.
func (s *Store) GetSuppression(ctx context.Context, id int64) (*Suppression, error) {
	var sp Suppression
	err := s.pool.QueryRow(ctx, `
		SELECT id, client_id, asset_id, reason, starts_at, ends_at, created_at
		FROM suppression WHERE id = $1`, id).
		Scan(&sp.ID, &sp.ClientID, &sp.AssetID, &sp.Reason, &sp.StartsAt, &sp.EndsAt, &sp.CreatedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sp, nil
}

// DeleteSuppression removes a window.
func (s *Store) DeleteSuppression(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM suppression WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// IncidentSuppressed reports whether an active suppression window currently
// covers the incident (its asset, its client, or global).
func (s *Store) IncidentSuppressed(ctx context.Context, clientID *int64, assetID int64) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM suppression
			WHERE now() >= starts_at AND now() < ends_at AND (
			    (client_id IS NULL AND asset_id IS NULL)          -- global
			 OR (asset_id = $2)                                   -- this asset
			 OR (client_id = $1 AND asset_id IS NULL)             -- whole client
			)
		)`, clientID, assetID).Scan(&exists)
	return exists, err
}
