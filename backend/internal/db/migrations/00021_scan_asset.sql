-- +goose Up

-- Link a stored scan to the asset it ran against, for per-asset scan history.
ALTER TABLE scan ADD COLUMN asset_id bigint;
CREATE INDEX scan_asset_idx ON scan (asset_id, created_at DESC);

-- +goose Down

DROP INDEX scan_asset_idx;
ALTER TABLE scan DROP COLUMN asset_id;
