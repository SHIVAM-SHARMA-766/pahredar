-- +goose Up

-- New on-demand report sources: news (Google News RSS), discussions (Hacker
-- News), msrc (Microsoft Security Response Center), advisories (previews of
-- the vendor advisory and patch pages a CVE references).
ALTER TABLE external_report DROP CONSTRAINT external_report_source_check;
ALTER TABLE external_report ADD CONSTRAINT external_report_source_check
    CHECK (source IN ('osv', 'redhat', 'ubuntu', 'news', 'discussions', 'msrc', 'advisories'));

-- "Related CVEs" finds CVEs that cite the same advisory or patch URL with
-- refs @> '[{"url": …}]'; jsonb_path_ops keeps the index compact.
CREATE INDEX cve_refs_path_idx ON cve USING gin (refs jsonb_path_ops);

-- +goose Down

DROP INDEX cve_refs_path_idx;
DELETE FROM external_report WHERE source IN ('news', 'discussions', 'msrc', 'advisories');
ALTER TABLE external_report DROP CONSTRAINT external_report_source_check;
ALTER TABLE external_report ADD CONSTRAINT external_report_source_check CHECK (source IN ('osv', 'redhat', 'ubuntu'));
