-- +goose Up

-- CVEs matched to an asset (from its scans' technology fingerprint). Enables
-- the reverse lookup "which assets are affected by CVE X" that alerting needs.
CREATE TABLE asset_cve (
    asset_id   bigint NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    cve_id     text NOT NULL,
    product    text NOT NULL DEFAULT '',
    kev        boolean NOT NULL DEFAULT false,
    first_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, cve_id)
);

CREATE INDEX asset_cve_cve_idx ON asset_cve (cve_id);

-- +goose Down

DROP TABLE asset_cve;
