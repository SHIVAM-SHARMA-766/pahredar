-- +goose Up

-- Cache of per-CVE reports fetched on demand from third parties (OSV, Red
-- Hat, Ubuntu). payload is Pahredar's normalized form, not the raw response,
-- so a change to the normalization takes effect as entries expire.
CREATE TABLE external_report (
    cve_id     text NOT NULL,
    source     text NOT NULL CHECK (source IN ('osv', 'redhat', 'ubuntu')),
    status     text NOT NULL CHECK (status IN ('ok', 'not_found')),
    fetched_at timestamptz NOT NULL DEFAULT now(),
    payload    jsonb,
    PRIMARY KEY (cve_id, source)
);

-- +goose Down

DROP TABLE external_report;
