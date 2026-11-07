package db

import (
	"context"
	"time"
)

// Channel is a notification target. A nil ClientID is global (serves every
// client); otherwise it serves one client. See docs/phase4.md (4C).
type Channel struct {
	ID        int64     `json:"id"`
	ClientID  *int64    `json:"client_id,omitempty"`
	Type      string    `json:"type"` // webhook | email
	Name      string    `json:"name"`
	Target    string    `json:"target"` // webhook URL or email address
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

func scanChannels(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Channel, error) {
	out := []Channel{}
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.ClientID, &c.Type, &c.Name, &c.Target, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateChannel inserts a channel.
func (s *Store) CreateChannel(ctx context.Context, clientID *int64, typ, name, target string) (Channel, error) {
	var c Channel
	err := s.pool.QueryRow(ctx, `
		INSERT INTO channel (client_id, type, name, target) VALUES ($1, $2, $3, $4)
		RETURNING id, client_id, type, name, target, enabled, created_at`,
		clientID, typ, name, target).
		Scan(&c.ID, &c.ClientID, &c.Type, &c.Name, &c.Target, &c.Enabled, &c.CreatedAt)
	return c, err
}

// ListChannels returns channels scoped to the caller: global ones plus those of
// clients they may access (admins see all).
func (s *Store) ListChannels(ctx context.Context, allClients bool, clientIDs []int64) ([]Channel, error) {
	if allClients {
		rows, err := s.pool.Query(ctx, `SELECT id, client_id, type, name, target, enabled, created_at FROM channel ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanChannels(rows)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, client_id, type, name, target, enabled, created_at FROM channel
		WHERE client_id IS NULL OR client_id = ANY($1) ORDER BY id`, clientIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChannels(rows)
}

// ChannelsForClient returns the enabled channels that should receive an
// incident for the given client: the client's own channels plus global ones. A
// nil clientID yields only global channels.
func (s *Store) ChannelsForClient(ctx context.Context, clientID *int64) ([]Channel, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, client_id, type, name, target, enabled, created_at FROM channel
		WHERE enabled AND (client_id IS NULL OR client_id = $1)`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChannels(rows)
}

// GetChannel returns one channel or pgx.ErrNoRows.
func (s *Store) GetChannel(ctx context.Context, id int64) (*Channel, error) {
	var c Channel
	err := s.pool.QueryRow(ctx, `
		SELECT id, client_id, type, name, target, enabled, created_at FROM channel WHERE id = $1`, id).
		Scan(&c.ID, &c.ClientID, &c.Type, &c.Name, &c.Target, &c.Enabled, &c.CreatedAt)
	if IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateChannel updates a channel's name, target, and enabled flag.
func (s *Store) UpdateChannel(ctx context.Context, id int64, name, target string, enabled bool) (Channel, error) {
	var c Channel
	err := s.pool.QueryRow(ctx, `
		UPDATE channel SET name = $2, target = $3, enabled = $4 WHERE id = $1
		RETURNING id, client_id, type, name, target, enabled, created_at`,
		id, name, target, enabled).
		Scan(&c.ID, &c.ClientID, &c.Type, &c.Name, &c.Target, &c.Enabled, &c.CreatedAt)
	return c, err
}

// DeleteChannel removes a channel. Returns rows deleted.
func (s *Store) DeleteChannel(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM channel WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
