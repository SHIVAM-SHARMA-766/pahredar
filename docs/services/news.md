# Service: Security News

Ingests security feeds (vendor PSIRTs, government advisories, research, news),
and presents a readable news stream with advisories, bookmarks, and a "trending
CVEs" view. A thin service that leans on Intelligence for CVE context.

## Owns

**API routes**

- `GET /api/v1/news`, `PUT /api/v1/news/bookmark`
- `GET /api/v1/feeds`, `GET /api/v1/feeds/advisories`
- `GET /api/v1/stats/trending`

**Backend**

- `internal/api/`: `feeds.go`, `news.go`
- `internal/db/`: `feed_article.go`
- `internal/sources/feeds` — the feed reader (RSS/Atom + per-source parsing),
  run by the syncer scheduler

**Frontend**

- Page: `NewsPage`
- Components: `FeedCards` (trending card, latest-advisories card, article list)

**Tables** (new migrations use the next sequential number — see [../contributing.md](../contributing.md))

- `feed`, `feed_article`, `article_bookmark`

## Dependencies

- **Core:** store, config, logger, HTTP server, `sources/fetch`, scheduler.
- **Reads from Intel:** trending and article views resolve CVE IDs to badges
  (severity, score, KEV/exploited) and summaries from the `cve` data. Read-only.

## How to add a feature

- **A new feed source:** add it to the feeds source config/registry in
  `internal/sources/feeds`, classify it (`vendor` / `government` / `research` /
  `news`), and it flows into `feed_article` and the news/advisories endpoints.
- **A new news filter or sort:** extend `api/news.go` (`NewsQuery`) and the
  `NewsPage` URL params.
- **Retention changes:** article retention is enforced by kind (government 2
  months, vendor 30 days, news/research 7 days) with bookmarks exempt — change
  it in the feeds retention logic, not ad hoc.

## Gotchas

- An article naming more than ~15 CVEs is treated as a roundup and scored 0 for
  trending — keep that threshold in sync between backend and `NewsPage`.
- Trending ranks CVEs by distinct covering feeds in a window; it is cheap but
  depends on Intel's CVE rows existing for the badge data.
- Feeds are read hourly by the scheduler; failures are per-source and logged,
  not fatal to the run.
