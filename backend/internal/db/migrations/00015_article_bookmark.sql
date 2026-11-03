-- +goose Up

-- Bookmarked articles are kept past their feed kind's retention.
ALTER TABLE feed_article ADD COLUMN bookmarked_at timestamptz;
CREATE INDEX feed_article_bookmarked_idx ON feed_article (bookmarked_at) WHERE bookmarked_at IS NOT NULL;

-- +goose Down

DROP INDEX feed_article_bookmarked_idx;
ALTER TABLE feed_article DROP COLUMN bookmarked_at;
