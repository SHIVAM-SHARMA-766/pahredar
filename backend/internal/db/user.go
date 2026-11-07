package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// User is an account. The password hash is never included in JSON.
type User struct {
	ID         int64      `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
}

// ErrUserExists is returned when an email is already taken.
var ErrUserExists = errors.New("a user with that email already exists")

// CountUsers returns how many accounts exist (used to seed the first admin).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&n)
	return n, err
}

// CreateUser inserts an account. Email is stored trimmed; uniqueness is
// case-insensitive. Returns ErrUserExists on a duplicate email.
func (s *Store) CreateUser(ctx context.Context, email, passwordHash, role string) (User, error) {
	email = strings.TrimSpace(email)
	var u User
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app_user (email, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id, email, role, created_at, disabled_at`,
		email, passwordHash, role).
		Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt, &u.DisabledAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return User{}, ErrUserExists
	}
	return u, err
}

// UserAuth holds what login needs: the stored hash plus the resolved identity.
type UserAuth struct {
	User
	PasswordHash string
}

// AuthUserByEmail returns the account (with its hash) for a login attempt, or
// pgx.ErrNoRows when no such email exists. Disabled accounts are returned too;
// the caller refuses them so the reason can be logged.
func (s *Store) AuthUserByEmail(ctx context.Context, email string) (UserAuth, error) {
	var a UserAuth
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, role, created_at, disabled_at, password_hash
		FROM app_user WHERE lower(email) = lower($1)`, strings.TrimSpace(email)).
		Scan(&a.ID, &a.Email, &a.Role, &a.CreatedAt, &a.DisabledAt, &a.PasswordHash)
	return a, err
}

// ListUsers returns all accounts, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, role, created_at, disabled_at FROM app_user ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt, &u.DisabledAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserRole sets a user's role. Returns pgx.ErrNoRows if the id is unknown.
func (s *Store) UpdateUserRole(ctx context.Context, id int64, role string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		UPDATE app_user SET role = $2 WHERE id = $1
		RETURNING id, email, role, created_at, disabled_at`, id, role).
		Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt, &u.DisabledAt)
	return u, err
}

// SetUserDisabled disables or re-enables a user. Disabling also drops their
// sessions so access stops at once. Returns pgx.ErrNoRows if the id is unknown.
func (s *Store) SetUserDisabled(ctx context.Context, id int64, disabled bool) (User, error) {
	var u User
	q := `UPDATE app_user SET disabled_at = CASE WHEN $2 THEN now() ELSE NULL END
		WHERE id = $1 RETURNING id, email, role, created_at, disabled_at`
	err := s.pool.QueryRow(ctx, q, id, disabled).
		Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt, &u.DisabledAt)
	if err == nil && disabled {
		_, _ = s.pool.Exec(ctx, `DELETE FROM session WHERE user_id = $1`, id)
	}
	return u, err
}

// UpdateUserPassword sets a new password hash and drops the user's sessions
// (a reset forces re-login everywhere).
func (s *Store) UpdateUserPassword(ctx context.Context, id int64, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE app_user SET password_hash = $2 WHERE id = $1`, id, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	_, _ = s.pool.Exec(ctx, `DELETE FROM session WHERE user_id = $1`, id)
	return nil
}

// DeleteUser removes an account (its sessions cascade). Returns the number of
// rows deleted (0 if the id was unknown).
func (s *Store) DeleteUser(ctx context.Context, id int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM app_user WHERE id = $1`, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CountActiveAdmins returns the number of enabled admins, excluding one id
// (pass 0 to exclude none). Used to refuse an operation that would lock out the
// last admin.
func (s *Store) CountActiveAdmins(ctx context.Context, excludeID int64) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM app_user
		WHERE role = 'admin' AND disabled_at IS NULL AND id <> $1`, excludeID).Scan(&n)
	return n, err
}

// UserByID returns an account by id (used to resolve a session), or
// pgx.ErrNoRows.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, role, created_at, disabled_at
		FROM app_user WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt, &u.DisabledAt)
	return u, err
}

// IsNotFound reports whether err is a "no rows" result.
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
