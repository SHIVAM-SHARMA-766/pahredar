-- +goose Up

-- Escalation policies (Phase 4C-M2): ordered steps notify channels (and, from
-- M3, the on-call user); if an incident is not acknowledged within a step's
-- delay, delivery escalates to the next step. A policy is global (no client) or
-- per-client; one may be the default for its scope.
CREATE TABLE escalation_policy (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id  bigint REFERENCES client(id) ON DELETE CASCADE,  -- NULL = global
    name       text NOT NULL,
    is_default boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- At most one default policy per scope (per client, and one global).
CREATE UNIQUE INDEX escalation_policy_default_idx ON escalation_policy (COALESCE(client_id, 0)) WHERE is_default;

-- Each step notifies one channel and/or the on-call user, then waits
-- delay_minutes for an acknowledgement before the next step fires.
CREATE TABLE escalation_step (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id     bigint NOT NULL REFERENCES escalation_policy(id) ON DELETE CASCADE,
    position      int NOT NULL,
    delay_minutes int NOT NULL DEFAULT 0,
    channel_id    bigint REFERENCES channel(id) ON DELETE SET NULL,  -- channel to notify (optional)
    notify_oncall boolean NOT NULL DEFAULT false,                    -- also notify the on-call user (M3)
    UNIQUE (policy_id, position)
);

-- Per-incident escalation state.
ALTER TABLE incident ADD COLUMN policy_id        bigint REFERENCES escalation_policy(id) ON DELETE SET NULL;
ALTER TABLE incident ADD COLUMN esc_step         int NOT NULL DEFAULT -1;  -- -1 = not yet notified
ALTER TABLE incident ADD COLUMN esc_notified_at  timestamptz;

-- +goose Down

ALTER TABLE incident DROP COLUMN esc_notified_at;
ALTER TABLE incident DROP COLUMN esc_step;
ALTER TABLE incident DROP COLUMN policy_id;
DROP TABLE escalation_step;
DROP TABLE escalation_policy;
