-- +goose Up

-- External endpoint scan results (see internal/scan). The full report is
-- stored as JSON; grade and score are promoted for the history list.
CREATE TABLE scan (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target     text NOT NULL,
    host       text NOT NULL,
    grade      text NOT NULL,
    score      int NOT NULL,
    report     jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_created_idx ON scan (created_at DESC);
CREATE INDEX scan_host_idx ON scan (host, created_at DESC);

-- +goose Down

DROP TABLE scan;
