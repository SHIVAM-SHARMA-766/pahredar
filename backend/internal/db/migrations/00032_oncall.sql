-- +goose Up

-- On-call schedules (Phase 4C-M3): who is on call for a client (or globally) at
-- a given time, as explicit shifts. An escalation step with notify_oncall emails
-- whoever's shift covers "now" in the incident's client schedule (else global).
CREATE TABLE oncall_schedule (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id  bigint REFERENCES client(id) ON DELETE CASCADE,  -- NULL = global
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oncall_shift (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schedule_id bigint NOT NULL REFERENCES oncall_schedule(id) ON DELETE CASCADE,
    user_id     bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    starts_at   timestamptz NOT NULL,
    ends_at     timestamptz NOT NULL
);

CREATE INDEX oncall_shift_window_idx ON oncall_shift (schedule_id, starts_at, ends_at);

-- +goose Down

DROP TABLE oncall_shift;
DROP TABLE oncall_schedule;
