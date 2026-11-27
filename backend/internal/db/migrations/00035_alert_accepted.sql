-- +goose Up

-- Per-finding acceptance (false-positive / accepted-risk management): an operator
-- can mark one alert row (a finding) as intended, so it stops counting toward the
-- asset's incident while other findings still alert. Distinct from a suppression
-- window, which mutes a whole scope for a time range.
ALTER TABLE alert ADD COLUMN accepted_at     timestamptz;
ALTER TABLE alert ADD COLUMN accepted_reason text NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE alert DROP COLUMN accepted_reason;
ALTER TABLE alert DROP COLUMN accepted_at;
