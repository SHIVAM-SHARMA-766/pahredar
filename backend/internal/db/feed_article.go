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

// NewsParams filters the news list. Feeds nil means every feed; Since zero
// means no time window.
type NewsParams struct {
	Feeds       []string
	Since       time.Time
	Query       string
	WithCVEOnly bool
	// Top ranks by the importance of the CVEs an article names instead of
	// by date (see NewsArticles).
	Top bool
	// Bookmarked lists only bookmarked articles.
	Bookmarked    bool
	Limit, Offset int
}

type NewsArticle struct {
	ArticleOut
	// Score is the top-story score: the best of the article's CVEs, where an
	// exploited CVE (CISA KEV, EUVD, VulnCheck KEV) counts 3, critical 2,
	// high 1, plus 1 per other feed covering that CVE in the window (at
	// most 4). Roundups score 0.
	Score      int  `json:"score"`
	Bookmarked bool `json:"bookmarked"`
}

// NewsArticles lists feed articles for the news page, with the total
// matching count.
func (s *Store) NewsArticles(ctx context.Context, p NewsParams) ([]NewsArticle, int, error) {
	order := `at DESC, url`
	if p.Top {
		order = `score DESC, ` + order
	}
	rows, err := s.pool.Query(ctx, `
		WITH a AS (
			SELECT feed, url, title, summary, `+articleDate+` AS at, cve_ids, bookmarked_at IS NOT NULL AS bookmarked FROM feed_article
			WHERE ($1::text[] IS NULL OR feed = ANY($1))
			  AND (NOT $8 OR bookmarked_at IS NOT NULL)
			  AND `+articleDate+` >= $2
			  AND ($3 = '' OR strpos(lower(title || ' ' || COALESCE(summary, '')), lower($3)) > 0)
			  AND (NOT $4 OR cardinality(cve_ids) > 0)
		),
		coverage AS (
			SELECT c AS cve_id, count(DISTINCT feed) AS feeds
			FROM feed_article, unnest(cve_ids) c
			WHERE `+articleDate+` >= $2 AND cardinality(cve_ids) <= $5
			GROUP BY c
		),
		-- Each CVE named by a listed article, scored once.
		cve_score AS (
			SELECT x.id,
				CASE WHEN EXISTS (SELECT 1 FROM kev WHERE kev.cve_id = x.id)
				       OR EXISTS (SELECT 1 FROM euvd_exploited e WHERE e.cve_id = x.id)
				       OR EXISTS (SELECT 1 FROM vulncheck_kev v WHERE v.cve_id = x.id) THEN 3
				     WHEN cve.severity = 'CRITICAL' THEN 2
				     WHEN cve.severity = 'HIGH' THEN 1
				     ELSE 0 END
				+ LEAST(COALESCE(cov.feeds, 1) - 1, 4) AS score
			FROM (SELECT DISTINCT unnest(cve_ids) AS id FROM a WHERE cardinality(cve_ids) <= $5) x
			LEFT JOIN cve ON cve.id = x.id
			LEFT JOIN coverage cov ON cov.cve_id = x.id
		),
		scored AS (
			SELECT a.*, CASE WHEN cardinality(a.cve_ids) BETWEEN 1 AND $5
				THEN (SELECT max(cs.score) FROM unnest(a.cve_ids) x JOIN cve_score cs ON cs.id = x)
				ELSE 0 END AS score
			FROM a
		)
		SELECT feed, url, title, summary, at, cve_ids, score, bookmarked, count(*) OVER ()
		FROM scored ORDER BY `+order+` LIMIT $6 OFFSET $7`,
		p.Feeds, p.Since, p.Query, p.WithCVEOnly, roundupLimit, p.Limit, p.Offset, p.Bookmarked)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []NewsArticle{}
	total := 0
	for rows.Next() {
		var a NewsArticle
		if err := rows.Scan(&a.Feed, &a.URL, &a.Title, &a.Summary, &a.Published, &a.CVEIDs, &a.Score, &a.Bookmarked, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// CVEBadge is what a CVE chip shows: severity, best CVSS score, and
// whether it is known exploited.
type CVEBadge struct {
	Severity  string   `json:"severity"`
	Score     *float64 `json:"score"`
	KEV       bool     `json:"kev"`
	Exploited bool     `json:"exploited"`
}

func (s *Store) CVEBadges(ctx context.Context, ids []string) (map[string]CVEBadge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, severity, COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score)::float8,
		       EXISTS (SELECT 1 FROM kev WHERE kev.cve_id = cve.id),
		       EXISTS (SELECT 1 FROM kev WHERE kev.cve_id = cve.id)
		       OR EXISTS (SELECT 1 FROM euvd_exploited e WHERE e.cve_id = cve.id)
		       OR EXISTS (SELECT 1 FROM vulncheck_kev v WHERE v.cve_id = cve.id)
		FROM cve WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CVEBadge{}
	for rows.Next() {
		var id string
		var b CVEBadge
		if err := rows.Scan(&id, &b.Severity, &b.Score, &b.KEV, &b.Exploited); err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, rows.Err()
}

// PageCheckedArticles lists articles from the given feeds whose pages were
// read, for re-extracting their CVE IDs.
func (s *Store) PageCheckedArticles(ctx context.Context, feeds []string) ([]ArticleRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT feed, url, title, COALESCE(summary, ''), published_at, cve_ids, page_checked
		FROM feed_article WHERE feed = ANY($1) AND page_checked ORDER BY url`, feeds)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ArticleRow])
}

// SetArticleCVEs replaces an article's CVE IDs (UpsertArticles only adds).
func (s *Store) SetArticleCVEs(ctx context.Context, url string, ids []string) (bool, error) {
	if ids == nil {
		ids = []string{}
	}
	tag, err := s.pool.Exec(ctx, `UPDATE feed_article SET cve_ids = $2 WHERE url = $1 AND cve_ids IS DISTINCT FROM $2`, url, ids)
	return tag.RowsAffected() > 0, err
}

// PruneArticles deletes articles of the given feeds dated before cutoff,
// except bookmarked ones.
func (s *Store) PruneArticles(ctx context.Context, feeds []string, cutoff time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM feed_article
		WHERE feed = ANY($1) AND `+articleDate+` < $2 AND bookmarked_at IS NULL`, feeds, cutoff)
	return int(tag.RowsAffected()), err
}

// SetBookmark bookmarks or un-bookmarks an article; false means no article
// has that URL.
func (s *Store) SetBookmark(ctx context.Context, url string, on bool) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE feed_article
		SET bookmarked_at = CASE WHEN $2 THEN COALESCE(bookmarked_at, now()) END WHERE url = $1`, url, on)
	return tag.RowsAffected() > 0, err
}
