-- +goose Up

-- Assets: the things the operator tracks (a domain, URL, IP, product, or repo).
-- The hub entity that ties scanner results and CVE matches together — see
-- docs/foundation.md (P3) and docs/roadmap.md Phase 2.
CREATE TABLE asset (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind            text NOT NULL,                 -- domain|url|ip|product|repo
    value           text NOT NULL,
    label           text NOT NULL DEFAULT '',
    tags            text[] NOT NULL DEFAULT '{}',
    last_scan_id    bigint,                        -- latest scan.id, if scanned
    last_scanned_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

CREATE INDEX asset_created_idx ON asset (created_at DESC);

-- +goose Down

DROP TABLE asset;
