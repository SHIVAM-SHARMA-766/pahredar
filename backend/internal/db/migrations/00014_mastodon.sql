-- +goose Up

-- On-demand report source: Mastodon posts tagged with the CVE ID.
ALTER TABLE external_report DROP CONSTRAINT external_report_source_check;
ALTER TABLE external_report ADD CONSTRAINT external_report_source_check
    CHECK (source IN ('osv', 'redhat', 'ubuntu', 'news', 'discussions', 'msrc', 'advisories', 'history', 'commits', 'otx', 'threatfox', 'bluesky', 'mastodon'));

-- +goose Down

DELETE FROM external_report WHERE source = 'mastodon';
ALTER TABLE external_report DROP CONSTRAINT external_report_source_check;
ALTER TABLE external_report ADD CONSTRAINT external_report_source_check
    CHECK (source IN ('osv', 'redhat', 'ubuntu', 'news', 'discussions', 'msrc', 'advisories', 'history', 'commits', 'otx', 'threatfox', 'bluesky'));
