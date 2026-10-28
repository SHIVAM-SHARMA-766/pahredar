-- +goose Up

-- The list API orders by "<col> DESC NULLS LAST, id DESC". A plain DESC index
-- is NULLS FIRST, so the planner could not use it and sorted the whole table
-- on every request. These match the API's ORDER BY exactly.
DROP INDEX cve_date_published_idx;
DROP INDEX cve_date_updated_idx;
DROP INDEX cve_cvss_v3_score_idx;

CREATE INDEX cve_date_published_idx ON cve (date_published DESC NULLS LAST, id DESC);
CREATE INDEX cve_date_updated_idx ON cve (date_updated DESC NULLS LAST, id DESC);
CREATE INDEX cve_cvss_idx ON cve ((COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score)) DESC NULLS LAST, id DESC);

-- +goose Down

DROP INDEX cve_cvss_idx;
DROP INDEX cve_date_updated_idx;
DROP INDEX cve_date_published_idx;

CREATE INDEX cve_date_published_idx ON cve (date_published DESC);
CREATE INDEX cve_date_updated_idx ON cve (date_updated DESC);
CREATE INDEX cve_cvss_v3_score_idx ON cve (cvss_v3_score DESC NULLS LAST);
