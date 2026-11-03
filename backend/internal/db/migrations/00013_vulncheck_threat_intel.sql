-- +goose Up

-- New on-demand report sources: AlienVault OTX pulses, abuse.ch ThreatFox
-- IOCs, and Bluesky posts.
ALTER TABLE external_report DROP CONSTRAINT external_report_source_check;
ALTER TABLE external_report ADD CONSTRAINT external_report_source_check
    CHECK (source IN ('osv', 'redhat', 'ubuntu', 'news', 'discussions', 'msrc', 'advisories', 'history', 'commits', 'otx', 'threatfox', 'bluesky'));

-- VulnCheck KEV: known exploited vulnerabilities from VulnCheck's research,
-- a superset of CISA KEV. reported is [{url, date_added}] (public reports of
-- exploitation); xdb is [{id, url, type, repo, date_added}] (exploit code).
CREATE TABLE vulncheck_kev (
    cve_id     text PRIMARY KEY,
    name       text,
    vendor     text,
    product    text,
    date_added date,
    ransomware boolean NOT NULL DEFAULT false,
    canary     boolean NOT NULL DEFAULT false,
    reported   jsonb NOT NULL DEFAULT '[]',
    xdb        jsonb NOT NULL DEFAULT '[]'
);

-- +goose Down

DROP TABLE vulncheck_kev;
DELETE FROM external_report WHERE source IN ('otx', 'threatfox', 'bluesky');
ALTER TABLE external_report DROP CONSTRAINT external_report_source_check;
ALTER TABLE external_report ADD CONSTRAINT external_report_source_check
    CHECK (source IN ('osv', 'redhat', 'ubuntu', 'news', 'discussions', 'msrc', 'advisories', 'history', 'commits'));
