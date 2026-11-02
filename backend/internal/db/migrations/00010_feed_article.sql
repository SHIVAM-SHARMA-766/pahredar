-- +goose Up

-- Items from security news, research, vendor PSIRT, and government feeds,
-- with the CVE IDs each mentions (from the feed text, or from the article
-- page for feeds that omit them). Drives per-CVE articles, "trending", and
-- the latest-advisories list. CVE IDs here may not exist in cve yet: vendor
-- advisories often precede publication in the CVE List.
CREATE TABLE feed_article (
    id            bigserial PRIMARY KEY,
    feed          text NOT NULL,
    url           text NOT NULL UNIQUE,
    title         text NOT NULL,
    summary       text,
    published_at  timestamptz,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    cve_ids       text[] NOT NULL DEFAULT '{}',
    -- true once the article page has been read for CVE IDs (or never needs to be).
    page_checked  boolean NOT NULL DEFAULT false
);

CREATE INDEX feed_article_cve_ids_idx ON feed_article USING gin (cve_ids);
CREATE INDEX feed_article_date_idx ON feed_article ((COALESCE(published_at, first_seen_at)) DESC);
CREATE INDEX feed_article_feed_idx ON feed_article (feed);

-- +goose Down

DROP TABLE feed_article;
