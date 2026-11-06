-- +goose Up

-- Accounts and sessions for multi-user auth. Roles are a fixed capability tier
-- (anonymous < viewer < operator < admin); anonymous is the absence of a row,
-- not stored here. No public signup: an admin creates users. See docs/auth.md.
CREATE TABLE app_user (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email         text NOT NULL,
    password_hash text NOT NULL,              -- argon2id encoded string
    role          text NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('viewer', 'operator', 'admin')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    disabled_at   timestamptz                 -- non-null = login refused
);

-- Case-insensitive unique email.
CREATE UNIQUE INDEX app_user_email_idx ON app_user (lower(email));

CREATE TABLE session (
    token_hash text PRIMARY KEY,              -- sha256(cookie token), hex
    user_id    bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX session_user_idx ON session (user_id);
CREATE INDEX session_expires_idx ON session (expires_at);

-- +goose Down

DROP TABLE session;
DROP TABLE app_user;
