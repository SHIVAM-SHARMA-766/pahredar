package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// articleDate is the date an article is ordered and windowed by: its
// published date, else when Pahredar first saw it.
const articleDate = `COALESCE(published_at, first_seen_at)`

// roundupLimit: articles naming more CVEs than this are roundups (monthly
// patch reviews, bulletin digests) and are left out of "trending".
const roundupLimit = 15

type ArticleRow struct {
	Feed        string
	URL         string
	Title       string
	Summary     string
	Published   *time.Time
	CVEIDs      []string
	PageChecked bool
}

type KnownArticle struct {
	CVEIDs      []string
	PageChecked bool
}

// KnownArticles returns stored state for the given URLs.
func (s *Store) KnownArticles(ctx context.Context, urls []string) (map[string]KnownArticle, error) {
	rows, err := s.pool.Query(ctx, `SELECT url, cve_ids, page_checked FROM feed_article WHERE url = ANY($1)`, urls)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]KnownArticle{}
	for rows.Next() {
		var u string
		var k KnownArticle
		if err := rows.Scan(&u, &k.CVEIDs, &k.PageChecked); err != nil {
			return nil, err
		}
		out[u] = k
	}
	return out, rows.Err()
}

// UpsertArticles inserts new articles and merges CVE IDs into existing ones
// (IDs are only ever added). Unchanged rows are not rewritten.
func (s *Store) UpsertArticles(ctx context.Context, rows []ArticleRow) (inserted, updated int, err error) {
	batch := &pgx.Batch{}
	for _, r := range rows {
		ids := r.CVEIDs
		if ids == nil {
			ids = []string{}
		}
		batch.Queue(`
			INSERT INTO feed_article (feed, url, title, summary, published_at, cve_ids, page_checked)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7)
			ON CONFLICT (url) DO UPDATE SET
				title = EXCLUDED.title,
				summary = COALESCE(EXCLUDED.summary, feed_article.summary),
				published_at = COALESCE(feed_article.published_at, EXCLUDED.published_at),
				cve_ids = ARRAY(SELECT DISTINCT unnest(feed_article.cve_ids || EXCLUDED.cve_ids) ORDER BY 1),
				page_checked = feed_article.page_checked OR EXCLUDED.page_checked
			WHERE feed_article.title IS DISTINCT FROM EXCLUDED.title
			   OR NOT (feed_article.cve_ids @> EXCLUDED.cve_ids)
			   OR (EXCLUDED.page_checked AND NOT feed_article.page_checked)
			RETURNING (xmax = 0)`, r.Feed, r.URL, r.Title, r.Summary, r.Published, ids, r.PageChecked)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range rows {
		var isInsert bool
		switch err := br.QueryRow().Scan(&isInsert); {
		case err == pgx.ErrNoRows:
			continue // unchanged
		case err != nil:
			return inserted, updated, err
		case isInsert:
			inserted++
		default:
			updated++
		}
	}
	return inserted, updated, br.Close()
}

type ArticleOut struct {
	Feed      string    `json:"feed"`
	URL       string    `json:"url"`
	Title     string    `json:"title"`
	Summary   *string   `json:"summary"`
	Published time.Time `json:"published"`
	CVEIDs    []string  `json:"cve_ids"`
	// Filled in by the API from the feed list.
	FeedName string `json:"feed_name"`
	FeedKind string `json:"feed_kind"`
}

func (s *Store) articles(ctx context.Context, sql string, args ...any) ([]ArticleOut, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArticleOut
	for rows.Next() {
		var a ArticleOut
		if err := rows.Scan(&a.Feed, &a.URL, &a.Title, &a.Summary, &a.Published, &a.CVEIDs); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

const articleCols = `feed, url, title, summary, ` + articleDate + `, cve_ids`

// ArticlesForCVE returns feed articles mentioning a CVE, newest first.
func (s *Store) ArticlesForCVE(ctx context.Context, id string, limit int) ([]ArticleOut, error) {
	return s.articles(ctx, `SELECT `+articleCols+` FROM feed_article WHERE cve_ids @> ARRAY[$1]::text[]
		ORDER BY `+articleDate+` DESC LIMIT $2`, id, limit)
}

// LatestArticles returns the newest articles from the given feeds that
// mention at least one CVE.
func (s *Store) LatestArticles(ctx context.Context, feeds []string, limit int) ([]ArticleOut, error) {
	return s.articles(ctx, `SELECT `+articleCols+` FROM feed_article WHERE feed = ANY($1) AND cardinality(cve_ids) > 0
		ORDER BY `+articleDate+` DESC LIMIT $2`, feeds, limit)
}

type Trending struct {
	CVEID    string    `json:"id"`
	Sources  int       `json:"sources"`
	Articles int       `json:"articles"`
	Latest   time.Time `json:"latest"`
	// Headline is the newest article's title.
	Headline string `json:"headline"`
	URL      string `json:"url"`
}

// TrendingCVEs ranks CVEs by how many distinct feeds mentioned them since
// `since`, ignoring roundup articles.
func (s *Store) TrendingCVEs(ctx context.Context, since time.Time, limit int) ([]Trending, error) {
	rows, err := s.pool.Query(ctx, `
		WITH m AS (
			SELECT c AS cve_id, a.feed, a.title, a.url, `+articleDate+` AS at
			FROM feed_article a, unnest(a.cve_ids) c
			WHERE `+articleDate+` >= $1 AND cardinality(a.cve_ids) <= $2
		)
		SELECT cve_id, count(DISTINCT feed), count(*), max(at),
		       (array_agg(title ORDER BY at DESC))[1], (array_agg(url ORDER BY at DESC))[1]
		FROM m GROUP BY cve_id
		ORDER BY count(DISTINCT feed) DESC, count(*) DESC, max(at) DESC, cve_id
		LIMIT $3`, since, roundupLimit, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Trending])
}

type FeedStat struct {
	Feed     string     `json:"feed"`
	Articles int        `json:"articles"`
	WithCVE  int        `json:"with_cve"`
	Latest   *time.Time `json:"latest"`
}

func (s *Store) FeedStats(ctx context.Context) ([]FeedStat, error) {
	rows, err := s.pool.Query(ctx, `SELECT feed, count(*), count(*) FILTER (WHERE cardinality(cve_ids) > 0), max(`+articleDate+`)
		FROM feed_article GROUP BY feed ORDER BY feed`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FeedStat])
}
