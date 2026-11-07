-- +goose Up

-- Notification channels (Phase 4C): where incident notifications go. A channel
-- with a NULL client_id is global (all clients); otherwise it serves one client.
-- Delivery routes an incident to its client's channels plus the global ones.
-- Escalation policies and on-call build on this in later milestones.
CREATE TABLE channel (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id  bigint REFERENCES client(id) ON DELETE CASCADE,  -- NULL = global
    type       text NOT NULL CHECK (type IN ('webhook', 'email')),
    name       text NOT NULL DEFAULT '',
    target     text NOT NULL,                                    -- webhook URL or email address
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX channel_client_idx ON channel (client_id);

-- +goose Down

DROP TABLE channel;
