-- +goose Up

-- Alerts: notifications raised when something matters for a tracked asset
-- (today: a CVE matched to an asset is known-exploited). See docs Phase 3.
CREATE TABLE alert (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type       text NOT NULL,                 -- 'kev_match'
    asset_id   bigint REFERENCES asset(id) ON DELETE CASCADE,
    cve_id     text,
    severity   text NOT NULL DEFAULT 'high',
    title      text NOT NULL,
    detail     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    read_at    timestamptz,
    UNIQUE (type, asset_id, cve_id)
);

CREATE INDEX alert_created_idx ON alert (created_at DESC);
CREATE INDEX alert_unread_idx ON alert (read_at) WHERE read_at IS NULL;

-- +goose Down

DROP TABLE alert;
