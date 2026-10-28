-- +goose Up

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- One row per CVE ID. Core fields come from cvelistV5; NVD fields are merged in.
-- `search` is maintained by the application (it includes vendor/product names
-- from cve_affected, so it cannot be a generated column).
CREATE TABLE cve (
    id                text PRIMARY KEY CHECK (id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    state             text NOT NULL CHECK (state IN ('PUBLISHED', 'REJECTED')),
    assigner          text,
    date_reserved     timestamptz,
    date_published    timestamptz,
    date_updated      timestamptz,
    title             text,
    description       text,
    cwe_ids           text[] NOT NULL DEFAULT '{}',
    cvss_v4_score     numeric(3, 1),
    cvss_v4_vector    text,
    cvss_v3_score     numeric(3, 1),
    cvss_v3_vector    text,
    cvss_v2_score     numeric(3, 1),
    cvss_v2_vector    text,
    severity          text NOT NULL DEFAULT 'UNKNOWN'
                      CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN')),
    severity_source   text,
    nvd_status        text,
    nvd_last_modified timestamptz,
    refs              jsonb NOT NULL DEFAULT '[]',
    raw_cvelist       jsonb,
    raw_nvd           jsonb,
    search            tsvector,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX cve_date_published_idx ON cve (date_published DESC);
CREATE INDEX cve_date_updated_idx ON cve (date_updated DESC);
CREATE INDEX cve_severity_idx ON cve (severity);
CREATE INDEX cve_cvss_v3_score_idx ON cve (cvss_v3_score DESC NULLS LAST);
CREATE INDEX cve_nvd_last_modified_idx ON cve (nvd_last_modified);
CREATE INDEX cve_cwe_ids_idx ON cve USING gin (cwe_ids);
CREATE INDEX cve_search_idx ON cve USING gin (search);

-- Affected products, normalized from CNA data and NVD CPE configurations.
-- All rows for a (cve_id, source) pair are replaced together on upsert.
CREATE TABLE cve_affected (
    id       bigserial PRIMARY KEY,
    cve_id   text NOT NULL REFERENCES cve (id) ON DELETE CASCADE,
    source   text NOT NULL CHECK (source IN ('cna', 'nvd')),
    vendor   text NOT NULL,
    product  text NOT NULL,
    cpe      text,
    versions jsonb NOT NULL DEFAULT '[]'
);

CREATE INDEX cve_affected_cve_id_idx ON cve_affected (cve_id, source);
CREATE INDEX cve_affected_vendor_product_idx ON cve_affected (vendor, product);
CREATE INDEX cve_affected_vendor_trgm_idx ON cve_affected USING gin (vendor gin_trgm_ops);
CREATE INDEX cve_affected_product_trgm_idx ON cve_affected USING gin (product gin_trgm_ops);

-- Enrichment tables carry no foreign key to cve: a source can reference a CVE
-- before the cvelist sync has stored it, and bulk loads must not fail on that.

CREATE TABLE kev (
    cve_id               text PRIMARY KEY,
    vendor_project       text,
    product              text,
    vulnerability_name   text,
    short_description    text,
    required_action      text,
    date_added           date NOT NULL,
    due_date             date,
    known_ransomware_use text,
    notes                text
);

CREATE INDEX kev_date_added_idx ON kev (date_added DESC);

CREATE TABLE epss (
    cve_id     text PRIMARY KEY,
    score      numeric(6, 5) NOT NULL,
    percentile numeric(6, 5) NOT NULL,
    score_date date NOT NULL
);

CREATE INDEX epss_score_idx ON epss (score DESC);

-- Written only when a score moves by >= 0.01 from the CVE's last history row.
CREATE TABLE epss_history (
    cve_id     text NOT NULL,
    score_date date NOT NULL,
    score      numeric(6, 5) NOT NULL,
    percentile numeric(6, 5) NOT NULL,
    PRIMARY KEY (cve_id, score_date)
);

CREATE TABLE exploit (
    id           bigserial PRIMARY KEY,
    cve_id       text NOT NULL,
    source       text NOT NULL CHECK (source IN ('exploitdb', 'metasploit', 'nuclei')),
    source_ref   text NOT NULL,
    title        text,
    url          text,
    published_at timestamptz,
    UNIQUE (source, source_ref, cve_id)
);

CREATE INDEX exploit_cve_id_idx ON exploit (cve_id);

CREATE TABLE sync_state (
    source          text PRIMARY KEY,
    cursor          text,
    last_success_at timestamptz
);

CREATE TABLE sync_run (
    id          bigserial PRIMARY KEY,
    source      text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('bootstrap', 'incremental')),
    status      text NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    inserted    integer NOT NULL DEFAULT 0,
    updated     integer NOT NULL DEFAULT 0,
    deleted     integer NOT NULL DEFAULT 0,
    error       text
);

CREATE INDEX sync_run_source_started_idx ON sync_run (source, started_at DESC);

-- +goose Down

DROP TABLE sync_run;
DROP TABLE sync_state;
DROP TABLE exploit;
DROP TABLE epss_history;
DROP TABLE epss;
DROP TABLE kev;
DROP TABLE cve_affected;
DROP TABLE cve;
