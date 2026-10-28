-- +goose Up

-- Per-vendor and per-product aggregates for the vendor pages. Aggregating
-- cve_affected (~1.6M rows) live takes seconds; these are refreshed by the
-- "stats" sync source after CVE or KEV data changes. Only published CVEs
-- count. Vendor counts are distinct CVEs across all of the vendor's
-- products, so they are not the sum of product rows.

CREATE MATERIALIZED VIEW product_stats AS
SELECT a.vendor, a.product,
       count(DISTINCT a.cve_id)                                          AS cves,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'CRITICAL')   AS critical,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'HIGH')       AS high,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'MEDIUM')     AS medium,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'LOW')        AS low,
       count(DISTINCT a.cve_id) FILTER (WHERE k.cve_id IS NOT NULL)      AS kev,
       max(c.date_published)                                             AS latest_published
FROM cve_affected a
JOIN cve c ON c.id = a.cve_id AND c.state = 'PUBLISHED'
LEFT JOIN kev k ON k.cve_id = a.cve_id
WHERE a.vendor <> ''
GROUP BY a.vendor, a.product;

CREATE UNIQUE INDEX product_stats_key ON product_stats (vendor, product);
CREATE INDEX product_stats_vendor_cves_idx ON product_stats (vendor, cves DESC);

CREATE MATERIALIZED VIEW vendor_stats AS
SELECT a.vendor,
       count(DISTINCT a.product)                                         AS products,
       count(DISTINCT a.cve_id)                                          AS cves,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'CRITICAL')   AS critical,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'HIGH')       AS high,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'MEDIUM')     AS medium,
       count(DISTINCT a.cve_id) FILTER (WHERE c.severity = 'LOW')        AS low,
       count(DISTINCT a.cve_id) FILTER (WHERE k.cve_id IS NOT NULL)      AS kev,
       max(c.date_published)                                             AS latest_published
FROM cve_affected a
JOIN cve c ON c.id = a.cve_id AND c.state = 'PUBLISHED'
LEFT JOIN kev k ON k.cve_id = a.cve_id
WHERE a.vendor <> ''
GROUP BY a.vendor;

CREATE UNIQUE INDEX vendor_stats_key ON vendor_stats (vendor);
CREATE INDEX vendor_stats_cves_idx ON vendor_stats (cves DESC);
CREATE INDEX vendor_stats_vendor_trgm_idx ON vendor_stats USING gin (vendor gin_trgm_ops);

-- Published CVEs per vendor per year, for the vendor trend chart.
CREATE MATERIALIZED VIEW vendor_year_stats AS
SELECT a.vendor, extract(year FROM c.date_published)::int AS year, count(DISTINCT a.cve_id) AS cves
FROM cve_affected a
JOIN cve c ON c.id = a.cve_id AND c.state = 'PUBLISHED' AND c.date_published IS NOT NULL
WHERE a.vendor <> ''
GROUP BY 1, 2;

CREATE UNIQUE INDEX vendor_year_stats_key ON vendor_year_stats (vendor, year);

-- +goose Down

DROP MATERIALIZED VIEW vendor_year_stats;
DROP MATERIALIZED VIEW vendor_stats;
DROP MATERIALIZED VIEW product_stats;
