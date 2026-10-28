-- +goose Up

-- CISA's ADP container also lists affected products (often with CPEs when the
-- CNA gave none), and one affected entry can carry several CPEs.
ALTER TABLE cve_affected DROP CONSTRAINT cve_affected_source_check;
ALTER TABLE cve_affected ADD CONSTRAINT cve_affected_source_check CHECK (source IN ('cna', 'adp', 'nvd'));
ALTER TABLE cve_affected DROP COLUMN cpe;
ALTER TABLE cve_affected ADD COLUMN cpes text[] NOT NULL DEFAULT '{}';

-- +goose Down

ALTER TABLE cve_affected DROP COLUMN cpes;
ALTER TABLE cve_affected ADD COLUMN cpe text;
DELETE FROM cve_affected WHERE source = 'adp';
ALTER TABLE cve_affected DROP CONSTRAINT cve_affected_source_check;
ALTER TABLE cve_affected ADD CONSTRAINT cve_affected_source_check CHECK (source IN ('cna', 'nvd'));
