-- +goose Up

-- Track external delivery (webhook) separately from creation, so any alert —
-- periodic (KEV/EPSS) or scan-triggered (findings) — is delivered once.
ALTER TABLE alert ADD COLUMN delivered_at timestamptz;
CREATE INDEX alert_undelivered_idx ON alert (created_at) WHERE delivered_at IS NULL;

-- +goose Down

DROP INDEX alert_undelivered_idx;
ALTER TABLE alert DROP COLUMN delivered_at;
