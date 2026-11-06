package db

import (
	"context"
	"time"
)

// SessionUser is the identity a valid session resolves to.
type SessionUser struct {
	UserID int64
	Email  string
	Role   string
}

// CreateSession stores a session keyed by the SHA-256 (hex) of the cookie
// token. Only the hash is stored, so a database leak does not yield live
// cookies.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO session (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expiresAt)
	return err
}

// SessionUserByToken resolves a session token hash to its user, provided the
// session has not expired and the account is not disabled. Returns
// pgx.ErrNoRows when there is no usable session.
func (s *Store) SessionUserByToken(ctx context.Context, tokenHash string) (SessionUser, error) {
	var su SessionUser
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.role
		FROM session s JOIN app_user u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now() AND u.disabled_at IS NULL`,
		tokenHash).Scan(&su.UserID, &su.Email, &su.Role)
	return su, err
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM session WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteExpiredSessions clears expired rows; returns how many were removed.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM session WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
