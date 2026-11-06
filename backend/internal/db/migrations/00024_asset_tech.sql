-- +goose Up

-- Products fingerprinted on an asset (from its scans). Lets alerting match any
-- new KEV for the asset's products, not only the CVEs already in asset_cve.
CREATE TABLE asset_tech (
    asset_id   bigint NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    vendor     text NOT NULL,
    product    text NOT NULL,
    version    text NOT NULL DEFAULT '',
    first_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, vendor, product)
);

-- +goose Down

DROP TABLE asset_tech;
