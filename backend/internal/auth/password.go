// Package auth is the authentication service: accounts, password hashing,
// sessions, login/logout, and principal resolution. See docs/auth.md.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. Encoded into every hash so they can be raised later
// without invalidating existing hashes (an old hash verifies with its own
// params). Tuned for an interactive login on a modest self-hosted box.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrMismatch is returned when a password does not match the hash.
var ErrMismatch = errors.New("password does not match")

// HashPassword returns an argon2id PHC-style string:
// $argon2id$v=19$m=65536,t=2,p=2$<salt>$<hash> (base64, no padding).
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64(salt), b64(hash)), nil
}

// VerifyPassword checks password against an encoded argon2id string in constant
// time. Returns ErrMismatch on a wrong password, or an error on a malformed
// hash.
func VerifyPassword(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("malformed password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("unsupported argon2 version")
	}
	var mem uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
		return errors.New("malformed argon2 params")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("malformed argon2 salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("malformed argon2 hash")
	}
	got := argon2.IDKey([]byte(password), salt, time, mem, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}
