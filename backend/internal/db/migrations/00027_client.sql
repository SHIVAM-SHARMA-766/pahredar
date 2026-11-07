-- +goose Up

-- Clients are tenants: the organisations whose assets an operator watches.
-- Assets (and, through them, scans and alerts) belong to a client. Access is
-- client-scoped — see docs/phase4.md. Scoping of asset.client_id lands in 4A-M2.
CREATE TABLE client (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text NOT NULL,
    slug       text NOT NULL,
    notes      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX client_slug_idx ON client (lower(slug));

-- Which clients a user may access. Admins implicitly access all clients and are
-- not listed here. Operators/viewers see only their assigned clients.
CREATE TABLE user_client (
    user_id   bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    client_id bigint NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX user_client_client_idx ON user_client (client_id);

-- +goose Down

DROP TABLE user_client;
DROP TABLE client;
