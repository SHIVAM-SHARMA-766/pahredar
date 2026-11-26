-- +goose Up

-- EASM evidence store (docs/scanner-easm.md, S1). A scan_run is one attack-
-- surface scan of an asset; asset_record is one observation (dedup on
-- asset+category+key+source, last_seen bumped on re-observation so history is
-- kept, not overwritten). Records attach to the Phase 4 asset/client model.
CREATE TABLE scan_run (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id     bigint NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    client_id    bigint REFERENCES client(id) ON DELETE CASCADE,
    profile      text NOT NULL DEFAULT 'passive',              -- passive | active | full
    status       text NOT NULL DEFAULT 'running'
                 CHECK (status IN ('running', 'done', 'failed')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    record_count int  NOT NULL DEFAULT 0,
    error        text NOT NULL DEFAULT ''
);

CREATE INDEX scan_run_asset_idx ON scan_run (asset_id, started_at DESC);

CREATE TABLE asset_record (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id     bigint NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    client_id    bigint REFERENCES client(id) ON DELETE CASCADE,
    run_id       bigint REFERENCES scan_run(id) ON DELETE SET NULL,
    category     text NOT NULL,                                -- dns | cert | subdomain | ip | whois | email | ...
    key          text NOT NULL,                                -- the specific item (a subdomain, a record value, ...)
    method       text NOT NULL DEFAULT 'passive',              -- passive | active
    source       text NOT NULL,                                -- rdap | crtsh | dns_resolve | ...
    data         jsonb NOT NULL DEFAULT '{}',
    evidence     text NOT NULL DEFAULT '',
    confidence   text NOT NULL DEFAULT 'high',                 -- high | medium | low
    verification text NOT NULL DEFAULT 'unverified',           -- verified | unverified
    scope        text NOT NULL DEFAULT 'in_scope',             -- in_scope | pending | out_of_scope
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, category, key, source)
);

CREATE INDEX asset_record_asset_idx ON asset_record (asset_id, category);

-- +goose Down

DROP TABLE asset_record;
DROP TABLE scan_run;
