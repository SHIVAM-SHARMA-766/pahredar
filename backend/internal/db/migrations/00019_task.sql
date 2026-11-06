-- +goose Up

-- Durable background task queue (see internal/jobs). Replaces per-feature
-- in-memory job maps so work survives restarts and can be retried.
CREATE TABLE task (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type         text        NOT NULL,          -- e.g. 'scan.run'
    payload      jsonb       NOT NULL DEFAULT '{}',
    status       text        NOT NULL DEFAULT 'queued',  -- queued|running|done|error
    attempts     int         NOT NULL DEFAULT 0,
    max_attempts int         NOT NULL DEFAULT 1,
    run_at       timestamptz NOT NULL DEFAULT now(),
    locked_at    timestamptz,
    locked_by    text,
    result       jsonb,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Claiming scans queued, due tasks oldest-first.
CREATE INDEX task_claim_idx ON task (run_at) WHERE status = 'queued';
CREATE INDEX task_created_idx ON task (created_at DESC);

-- +goose Down

DROP TABLE task;
