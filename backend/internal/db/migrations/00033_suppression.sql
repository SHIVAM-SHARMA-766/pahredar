-- +goose Up

-- Suppression windows (Phase 4C-M4): mute notifications for a scope during a
-- time window (maintenance), without losing the incident. Scope widens from
-- asset → client → global as the id columns are null.
CREATE TABLE suppression (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id  bigint REFERENCES client(id) ON DELETE CASCADE,  -- NULL = all clients
    asset_id   bigint REFERENCES asset(id) ON DELETE CASCADE,   -- NULL = whole client/global
    reason     text NOT NULL DEFAULT '',
    starts_at  timestamptz NOT NULL,
    ends_at    timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX suppression_window_idx ON suppression (starts_at, ends_at);

-- +goose Down

DROP TABLE suppression;
