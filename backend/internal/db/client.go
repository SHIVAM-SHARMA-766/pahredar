package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Client is a tenant — an organisation whose assets are watched.
type Client struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ErrClientExists is returned when a slug is already taken.
var ErrClientExists = errors.New("a client with that slug already exists")

func scanClient(row pgx.Row) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.Name, &c.Slug, &c.Notes, &c.CreatedAt)
	return c, err
}

// CreateClient inserts a tenant. Returns ErrClientExists on a duplicate slug.
func (s *Store) CreateClient(ctx context.Context, name, slug, notes string) (Client, error) {
	c, err := scanClient(s.pool.QueryRow(ctx, `
		INSERT INTO client (name, slug, notes) VALUES ($1, $2, $3)
		RETURNING id, name, slug, notes, created_at`,
		strings.TrimSpace(name), strings.TrimSpace(slug), notes))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Client{}, ErrClientExists
	}
	return c, err
}

// ListClients returns all clients, oldest first.
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	return s.queryClients(ctx, `SELECT id, name, slug, notes, created_at FROM client ORDER BY id`)
}

// ClientsForUser returns the clients a user is assigned to.
func (s *Store) ClientsForUser(ctx context.Context, userID int64) ([]Client, error) {
	return s.queryClients(ctx, `
		SELECT c.id, c.name, c.slug, c.notes, c.created_at
		FROM client c JOIN user_client uc ON uc.client_id = c.id
		WHERE uc.user_id = $1 ORDER BY c.id`, userID)
}

func (s *Store) queryClients(ctx context.Context, q string, args ...any) ([]Client, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.Name, &c.Slug, &c.Notes, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetClient returns one client, or pgx.ErrNoRows.
func (s *Store) GetClient(ctx context.Context, id int64) (Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `
		SELECT id, name, slug, notes, created_at FROM client WHERE id = $1`, id))
}

// UpdateClient updates a client's name and notes.
func (s *Store) UpdateClient(ctx context.Context, id int64, name, notes string) (Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `
		UPDATE client SET name = $2, notes = $3 WHERE id = $1
		RETURNING id, name, slug, notes, created_at`, id, strings.TrimSpace(name), notes))
}

// DeleteClient removes a client. Returns rows deleted (0 if unknown).
func (s *Store) DeleteClient(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM client WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ClientIDsForUser returns the ids of the clients a user may access (used to
// build the principal's scope).
func (s *Store) ClientIDsForUser(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT client_id FROM user_client WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetUserClients replaces a user's client assignments with the given ids.
func (s *Store) SetUserClients(ctx context.Context, userID int64, clientIDs []int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM user_client WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, cid := range clientIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_client (user_id, client_id) VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, userID, cid); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
