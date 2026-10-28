-- +goose Up

-- The score as of 7 days before score_date (the CVE's latest history point on
-- or before that day), written when EPSS loads. Precomputing it makes the
-- dashboard's "EPSS movers" an index lookup instead of a lateral scan over
-- every history row (~1.7 s). NULL until a CVE has history that old.
ALTER TABLE epss ADD COLUMN score_7d_ago numeric(6, 5);
ALTER TABLE epss ADD COLUMN delta_7d numeric(6, 5) GENERATED ALWAYS AS (score - score_7d_ago) STORED;
CREATE INDEX epss_delta_7d_idx ON epss (delta_7d DESC NULLS LAST);

-- +goose Down

DROP INDEX epss_delta_7d_idx;
ALTER TABLE epss DROP COLUMN delta_7d;
ALTER TABLE epss DROP COLUMN score_7d_ago;
