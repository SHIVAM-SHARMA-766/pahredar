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
