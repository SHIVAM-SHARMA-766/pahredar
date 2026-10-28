# Pahredar — Architecture

> Status: **milestone 4 done** (2026-10-28): all seven sources sync, the API serves search, enriched detail, and vendor/product stats, and the web UI runs at `127.0.0.1:3001`. The dashboard is next. See §13. This document is the source of truth for the design and is updated in the same change as any code, schema, or decision it describes.

## 1. Purpose

Pahredar is a personal, self-hosted CVE intelligence application. It keeps a local copy of **every published CVE**, enriches each one with severity, exploitation, and exploit-availability signals from free public sources, keeps that data in sync on a schedule, and presents it through a web UI (dashboard, search, CVE detail, vendor pages).

It is modelled loosely on SOCRadar CVE Radar (https://cve.socradar.io/), but built for a single user, running locally at zero cost.

### Goals (v1)

- Store the full CVE corpus (~300k+ records), including rejected IDs.
- Keep it current automatically: new CVEs within ~1 hour, enrichment within ~1 day.
- Fast search and filtering across the full corpus.
- A detail page that answers "how bad is this, is it being exploited, is there a public exploit, what does it affect".
- Observable sync: every run is logged with counts and errors.

### Non-goals (v1)

- **Tech-stack / watchlist matching** against the user's applications. Planned for a later phase; the schema keeps normalized affected-product data so it can be added without migration pain.
- Alerts / notifications (Telegram, ntfy, email) — later phase.
- Multi-user support and authentication — the app binds to localhost only.
- Cloud deployment — local Docker Compose only for now; OCI VM later.
- A dedicated search engine (Elasticsearch / OpenSearch / Meilisearch). Postgres full-text search is expected to be sufficient; revisit only if it measurably falls short.

## 2. System overview

```
                ┌───────────────────────── external sources ─────────────────────────┐
                │ cvelistV5 (GitHub)  NVD API 2.0  CISA KEV  EPSS  Exploit-DB  MSF  Nuclei │
                └──────────────┬──────────────────────────────────────────────────────┘
                               │ HTTPS pulls (scheduled)
┌──────────────────────────────▼───────────────────────────────┐
│ backend (Go, single binary)                                   │
│                                                               │
│  scheduler ──► sync jobs (one per source) ──► upsert          │
│                                                  │            │
│  HTTP API  (/api/v1/...) ◄──── read queries ─────┤            │
└───────────────▲──────────────────────────────────┼────────────┘
                │ JSON                             │ SQL (pgx)
┌───────────────┴──────────┐            ┌──────────▼───────────┐
│ frontend (React + Vite)  │            │ Postgres             │
│ served by nginx,         │            │ source of truth      │
│ proxies /api → backend   │            │ + full-text search   │
└──────────────────────────┘            └──────────────────────┘
```

One Go binary runs both the scheduler and the HTTP API. Postgres is the only stateful component. The frontend is a static build.

## 3. Repository layout

```
pahredar/
├── README.md               user-facing: what it is, how to run it
├── ARCHITECTURE.md         this file
├── docker-compose.yml      postgres + backend + frontend
├── .env.example            every config variable, documented
├── backend/                Go module (see backend/README.md)
│   ├── cmd/pahredar/       main; subcommands: serve, migrate, sync <source>, healthcheck
│   ├── internal/config/    env parsing and validation
│   ├── internal/cverecord/ parse CVE JSON 5 and NVD records; derive scores, severity, CWEs, refs, affected
│   ├── internal/db/        migrations (embedded SQL) and all queries
│   ├── internal/sources/   one package per upstream feed (fetch + unpack only): cvelist, nvd, kev, epss, exploits; fetch = shared HTTP
│   ├── internal/syncer/    job runner, scheduler, per-source jobs (named syncer to avoid shadowing stdlib sync)
│   └── internal/api/       HTTP handlers, request validation, JSON shapes
└── frontend/               React + Vite + TypeScript SPA (see frontend/README.md)
```

Each important directory gets its own `README.md` once it contains code.

## 4. Technology choices

| Concern | Choice | Reason |
|---|---|---|
| Backend language | Go | Single static binary for API and worker; already in use in the user's other projects. |
| HTTP routing | Go stdlib `net/http` (method + path patterns) | Enough for a small REST API; no framework dependency. |
| DB driver | `pgx/v5` | Native Postgres driver with `COPY` support for bulk loads. |
| Migrations | `goose`, SQL files embedded in the binary | Plain SQL, versioned, runs on startup. |
| Database | Postgres 17 | Transactions, JSONB, `tsvector` full-text search, `pg_trgm` fuzzy matching. |
| Frontend | React + Vite + TypeScript | Rich interactive UI (charts, filters). |
| Frontend data | TanStack Query | Caching, pagination, loading/error states. |
| Routing (UI) | React Router 7 | Standard. Version 8 needs Node ≥ 22.22; the dev machine has Node 20. |
| Styling | Tailwind CSS | Fast iteration, no component-library lock-in. |
| Charts | Recharts | Sufficient for dashboard trends and distributions. |
| Runtime | Docker Compose | One command to run locally; same images move to a VM later. |

## 5. Data sources

All sources are free. Only NVD needs an API key (free, raises rate limit).

| Source | Provides | Format / access | Cadence |
|---|---|---|---|
| **CVEProject/cvelistV5** | Canonical CVE records (CNA data): description, affected products/versions, references, CWE, CNA CVSS, and CISA ADP "Vulnrichment" (CVSS, CWE, affected CPEs, SSVC) | GitHub releases (see §7 for the exact release layout) | Hourly |
| **NVD API 2.0** | NVD analysis: CVSS v2/v3.x/v4 scores, CPE match configurations, CWE, `vulnStatus` | REST, `resultsPerPage` ≤ 2000, `lastModStartDate`/`lastModEndDate` window ≤ 120 days, rate limit 50 req / 30 s with key | Every 2 hours |
| **CISA KEV** | Known-exploited vulnerabilities: date added, due date, required action, ransomware use, forensic triage | `known_exploited_vulnerabilities.json` (~1.8k entries, 1.8 MB) | Every 6 h |
| **EPSS (FIRST / Empirical Security)** | Exploit-prediction score and percentile per CVE | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` (~400k rows, 2.7 MB); first line is `#model_version:…,score_date:<RFC3339>` | Every 6 h (no-op unless the score date changed) |
| **Exploit-DB** | Public exploits mapped to CVE IDs | `files_exploits.csv` on GitLab; CVEs in the `;`-separated `codes` column (~27k of ~47k exploits) | Daily |
| **Metasploit** | Modules referencing CVEs | `db/modules_metadata_base.json` (~7k modules, ~3k with CVEs) | Daily |
| **Nuclei templates** | Detection templates per CVE | `cves.json`, one JSON object per line (~4.5k) | Daily |

Exact URLs live as constants in `backend/internal/sources/*` and are verified when each source is implemented (EPSS in particular has changed hosts before).

## 6. Data model

All CVE IDs are stored in canonical upper-case form (`CVE-2024-12345`) and are the join key across every table.

### `cve` — one row per CVE ID

| Column | Type | Notes |
|---|---|---|
| `id` | text PK | `CVE-YYYY-NNNN+` |
| `state` | text | `PUBLISHED` or `REJECTED` |
| `assigner` | text | CNA short name |
| `date_reserved`, `date_published`, `date_updated` | timestamptz | From cvelistV5 |
| `title` | text | CNA title, nullable |
| `description` | text | English description |
| `cwe_ids` | text[] | Union of CNA, CISA ADP, and NVD CWEs (`CWE-n` only; NVD placeholders like `NVD-CWE-noinfo` dropped) |
| `cvss_v4_score`, `cvss_v4_vector` | numeric, text | Effective (see precedence) |
| `cvss_v3_score`, `cvss_v3_vector` | numeric, text | Effective (v3.1 preferred over v3.0) |
| `cvss_v2_score`, `cvss_v2_vector` | numeric, text | Legacy, mostly NVD |
| `severity` | text | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`/`UNKNOWN`, derived |
| `severity_source` | text | Which metric/provider `severity` came from |
| `nvd_status` | text | NVD `vulnStatus` (e.g. `Analyzed`, `Awaiting Analysis`) |
| `nvd_last_modified` | timestamptz | Drives incremental NVD sync |
| `refs` | jsonb | `[{url, name, tags[]}]`, merged and de-duplicated. Named `refs` because `references` is a reserved word in SQL |
| `exploit_ref` | boolean | Any reference tagged `exploit` (case-insensitive; CNA uses `exploit`, NVD `Exploit`). Added in migration 00004 |
| `raw_cvelist` | jsonb | Original cvelistV5 record |
| `raw_nvd` | jsonb | Original NVD record, nullable |
| `search` | tsvector | Weighted: id (`simple` config, A) + title (A) + description (B) + vendor/product names (C), `english` config. GIN index. Written by the upsert, not a generated column, because it draws on affected products |
| `created_at`, `updated_at` | timestamptz | Local bookkeeping |

Raw source JSON is kept so derived columns can be recomputed after a logic change without re-downloading (estimated a few GB in total).

**Severity precedence** (first available wins): CNA v4.0 → NVD v4.0 → CNA v3.1 → CNA v3.0 → NVD v3.1 → NVD v3.0 → ADP v4.0 → ADP v3.1 → ADP v3.0 → CNA v2.0 → NVD v2.0. Within NVD, `Primary` (NVD's own analysis) beats `Secondary`. The same order picks the effective `cvss_v4_*`, `cvss_v3_*`, and `cvss_v2_*` columns. A metric's severity is the provider's stated `baseSeverity`, else the standard score band for its version. `severity_source` records the winner as `<provider>:cvss<version>`, e.g. `cna:cvss4.0`. Rejected CVEs are always `UNKNOWN`. Implemented in `internal/cverecord/derive.go`.

**Computed at read time, not stored:** the full per-provider metric list and CISA SSVC decision points (`exploitation`, `automatable`, `technical_impact`) are parsed from the raw records by the detail endpoint, so they always reflect current logic.

### `cve_affected` — affected products (normalized)

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `cve_id` | text FK → `cve` | |
| `source` | text | `cna`, `adp` (CISA Vulnrichment), or `nvd` (vulnerable `cpeMatch` criteria from NVD configurations, grouped by CPE vendor/product) |
| `vendor`, `product` | text | Lower-cased, trimmed; indexed with `pg_trgm`. Placeholders (`n/a`, `unknown`, …) become `''`; entries with no product are dropped |
| `cpes` | text[] | CPE 2.3 strings when the provider gives them (migration 00002 replaced the single `cpe` column) |
| `versions` | jsonb | Shape depends on `source`. `cna`/`adp`: CVE JSON 5 version entries (`version`, `lessThan`, `lessThanOrEqual`, `status`, …). `nvd`: NVD `cpeMatch` objects (`criteria`, `versionStartIncluding`, `versionEndExcluding`, …) |

All rows for a CVE are replaced together whenever that CVE is upserted. This table powers vendor/product pages now and stack matching later. Note that NVD names come from CPEs (`apache` / `log4j`) while CNA names are free text (`apache software foundation` / `apache log4j2`); they are not reconciled.

### `kev`

`cve_id` (PK), `vendor_project`, `product`, `vulnerability_name`, `short_description`, `required_action`, `date_added`, `due_date`, `known_ransomware_use`, `forensic_triage` (00004), `notes`. Mirrors the feed on each sync: new entries inserted, changed ones updated, removed ones deleted.

### `epss` and `epss_history`

- `epss`: `cve_id` PK, `score`, `percentile`, `score_date`. Replaced with `TRUNCATE` + `INSERT` in one transaction when a new score date appears.
- `epss_history`: `(cve_id, score_date)` PK, `score`, `percentile`. A row is written only when a CVE's score changes by ≥ 0.01 from its last history row, keeping growth bounded (a full daily snapshot would be ~100M rows/year).

### `exploit`

`id` PK, `cve_id`, `source` (`exploitdb`/`metasploit`/`nuclei`), `source_ref`, `title`, `url`, `published_at`. Unique on `(source, source_ref, cve_id)` because one exploit or module can cover several CVEs; upserts use that key.

### Foreign keys

Only `cve_affected` references `cve` (with `ON DELETE CASCADE`). The enrichment tables (`kev`, `epss`, `epss_history`, `exploit`) deliberately have **no** foreign key: a source can mention a CVE before the cvelist sync has stored it, and bulk `COPY` loads must not fail on that. Joins to `cve` are plain `LEFT JOIN`s.

### `sync_state` and `sync_run`

- `sync_state`: `source` PK, `cursor` (text; meaning is source-specific, e.g. last delta timestamp or NVD `lastModified`), `last_success_at`.
- `sync_run`: `id`, `source`, `kind` (`bootstrap`/`incremental`), `started_at`, `finished_at`, `status` (`running`/`success`/`failed`), `inserted`, `updated`, `deleted`, `error`.

### Snapshot safety

KEV, EPSS, and each exploit source are full snapshots: a run makes the stored rows equal to the feed. Before replacing, the job refuses (fails the run, keeps the old data) if the feed has fewer than half as many rows as are stored, which catches truncated downloads and silent format changes.

### Vendor and product stats (materialized views, migration 00005)

| View | Key | Contents |
|---|---|---|
| `vendor_stats` | `vendor` | products, distinct CVEs, counts per severity, KEV count, latest publish date. Trigram index for search |
| `product_stats` | `(vendor, product)` | same counts per product |
| `vendor_year_stats` | `(vendor, year)` | distinct published CVEs per year |

Only published CVEs and non-empty vendors count. Vendor totals are distinct CVEs across products, not sums. Computing these live over `cve_affected` takes 0.4–3.4 s; the views make vendor pages ~2–30 ms. They are refreshed `CONCURRENTLY` (~15 s, readers unaffected) by the `stats` sync source, which runs at startup, every `STATS_REFRESH_INTERVAL` (6 h), and is triggered automatically after any cvelist, NVD, or KEV run that changed rows. A product page's per-year chart is computed live (single product, fast enough).

### Derived, not stored

- **Timeline** on the detail endpoint, oldest first: `reserved`, `published`, `kev_added`, `kev_due`, one `exploit_published` per dated exploit, `epss_spike` (score up ≥ 0.1 between consecutive history points), `updated`. Assembled per request in `internal/api/cves.go`.
- **Has public exploit** = `cve.exploit_ref` OR KEV-listed OR any `exploit` row (`hasExploitExpr` in `internal/db/cve_read.go`).

## 7. Sync design

### Principles

- **Idempotent:** every job is an upsert; re-running a job or replaying a window is safe.
- **Cursor-based:** incremental jobs read their cursor from `sync_state` and only advance it after a successful commit.
- **One job per source, never concurrent with itself:** a Postgres advisory lock keyed on the source name guards each run.
- **Failures are isolated:** a failing source does not block others; the error is recorded in `sync_run` and retried on the next tick with exponential backoff (capped).
- **Bulk loads use `COPY`** into a temp staging table, then a single `INSERT ... ON CONFLICT DO UPDATE`.
- **Serialized CVE writes:** each `cve` batch (1000 records) runs in one transaction that takes a transaction-scoped advisory lock (`pahredar:cve-write`) and `SELECT ... FOR UPDATE`s the existing rows. Every writer derives the full row from *both* raw records (the incoming one plus the stored other one), so the cvelist and NVD jobs can never overwrite each other's contribution with stale data.
- **Newer-only:** a cvelist record is skipped when its `dateUpdated` is not after the stored one. Re-applying a cumulative delta therefore costs a read, not a write. Consequence: after a change to derivation logic, stored rows only pick it up when their upstream record changes or on `pahredar sync cvelist --bootstrap`.
- **Stale runs:** after taking a source's lock, the runner marks any leftover `running` rows for that source as `failed` (the lock proves their process is gone).
- **Retries:** a failed run is retried after 5 min, doubling per consecutive failure, capped at the source's interval.

### Bootstrap (first run, empty DB)

1. **cvelistV5:** take the latest release's `YYYY-MM-DD_all_CVEs_at_midnight.zip.zip` (~615 MB; a zip whose single entry `cves.zip`, ~700 MB, holds one JSON file per CVE). The outer zip is inflated while streaming, so only `cves.zip` is written to `DATA_DIR`, and it is deleted afterwards. Records load in batches of 1000. The cursor is set to `<day> 0000Z`, then the incremental step runs immediately to apply that day's hourly delta.
2. **NVD:** full paginated pull (~160+ pages of 2000) respecting the rate limit; set cursor to the newest `lastModified` seen.
3. **KEV, EPSS, exploits:** normal full runs.
4. Recompute derived columns (`severity`, `search`).

Bootstrap is triggered automatically when `sync_state` has no row for a source, or manually via `pahredar sync <source> --bootstrap`.

### NVD

- **Bootstrap:** no date filter, all ~208 pages of 2000. NVD takes ~3–40 s per page, so 4 pages are fetched concurrently (well under the 50 requests / 30 s keyed limit; requests are also spaced ≥ 700 ms apart, ≥ 6.5 s without a key). Pages are written as they arrive, in any order.
- **Incremental:** `lastModStartDate = cursor − 5 min`, `lastModEndDate = run start`, one page at a time. If the cursor is older than the API's 120-day window, re-bootstrap.
- **Cursor:** the RFC 3339 time the run *started*, so anything modified during a long pull is read again next run.
- **Retries:** network errors, 403 (NVD's throttling response), 429, and 5xx are retried up to 6 times per page with backoff from 10 s, doubling.
- **Skip:** a record whose `lastModified` is not after the stored `nvd_last_modified` is not rewritten.

### Incremental

| Source | Schedule | Mechanism |
|---|---|---|
| cvelist | hourly | See "cvelist release layout" below. If the cursor is more than 14 days old, re-bootstrap instead. |
| nvd | every 2 h | See "NVD" above. |
| kev | every 6 h | Snapshot; cursor is the catalog version. |
| epss | every 6 h | Snapshot when the file's score date differs from the cursor; history rows appended first. `sync_run.updated` = current scores loaded, `inserted` = history rows added. |
| exploitdb / metasploit / nuclei | daily | Snapshot per source, keyed `(source, source_ref, cve_id)`; cursor is the run time. |

Every source also runs once at startup (all concurrently; CVE writes serialize on the `cve-write` lock) and on demand via `POST /api/v1/sync/{source}`. Intervals: `CVELIST_SYNC_INTERVAL`, `NVD_SYNC_INTERVAL`, `KEV_SYNC_INTERVAL`, `EPSS_SYNC_INTERVAL`, `EXPLOITS_SYNC_INTERVAL`.

### cvelist release layout and cursor

cvelistV5 publishes a release roughly every hour, tagged `cve_YYYY-MM-DD_HHMMZ`. Each carries the day's midnight baseline and `YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip`, which contains **every record changed since 00:00 UTC that day** (cumulative, not just the last hour). Shortly after midnight a `cve_YYYY-MM-DD_at_end_of_day` release adds `..._delta_CVEs_at_end_of_day.zip` covering the whole previous day.

The cursor is `"<day> <hour>"`, for example `2026-10-28 0700Z`, or `2026-10-27 eod` once a day's end-of-day delta is applied. An incremental run:

1. For each day before today that is not yet `eod`: fetch that day's end-of-day release (by tag) and apply it. If it is not published yet, apply the day's newest hourly delta instead and stop; the next run finishes the day.
2. For today: apply the newest hourly delta if its hour is after the cursor's.
3. Advance and save the cursor after each applied archive.

Delta zips are a few MB and are read in memory. GitHub API usage is 1–3 unauthenticated calls per run, well inside the 60/hour anonymous limit.

## 8. HTTP API

JSON over REST under `/api/v1`. Read-only except sync triggers.

| Method & path | Purpose |
|---|---|
| `GET /healthz` | Liveness + DB connectivity |
| `GET /api/v1/cves` | Search/list. Params: `q`, `severity` (comma list), `state`, `vendor`, `product`, `cwe`, `published_from`, `published_to` (inclusive, `YYYY-MM-DD`), `kev` / `exploit` (`true`/`false`), `epss_min` (0–1), `sort` (`relevance`, `published`, `updated`, `cvss`, `epss`), `order` (`asc`/`desc`, default `desc`), `page`, `page_size` (1–100, default 25). Items carry `kev`, `epss_score`, `epss_percentile`, `has_exploit` |
| `GET /api/v1/cves/{id}` | Detail: core fields, effective CVSS per version, all per-provider metrics, SSVC, `kev` (or null), `epss` with `history`, `exploits`, `has_exploit`, `timeline`, affected products, references |
| `GET /api/v1/stats/dashboard` | Counts and series for the dashboard (milestone 5) |
| `GET /api/v1/vendors` | `{items}` of vendor summaries by CVE count. `q` = case-insensitive substring (exact match first), `page_size` 1–100 (default 25) |
| `GET /api/v1/vendors/{vendor}` | Vendor summary, `years` (CVEs per year), `top_products` (top 200 by CVE count). 404 if unknown |
| `GET /api/v1/vendors/{vendor}/products/{product}` | Product summary and `years`. The CVE list itself is `/cves?vendor=&product=`. Names are lower-case and URL-encoded |
| `GET /api/v1/sync/status` | Per-source state and the 20 most recent runs (implemented) |
| `POST /api/v1/sync/{source}` | Queue an immediate run: 202 `{status: queued}`, 404 unknown source, 409 if `SYNC_ENABLED=false`. Repeated triggers while one is pending collapse |

Search behaviour: if `q` matches a CVE ID pattern (case-insensitive), it becomes an exact ID filter; otherwise it is `websearch_to_tsquery('english', q)` against `search`, and the default sort becomes `relevance` (`ts_rank`, then recency). Without `q`, the default sort is `published`.

Errors are `{"error": "<message>"}` with 400 for invalid parameters, 404 for an unknown CVE, 500 (details only in the server log) otherwise. List responses are `{items, total, page, page_size}`; list items carry a description truncated to 300 characters.

The list query runs in two steps: an inner `SELECT cve.id … ORDER BY … LIMIT` that touches only sort and filter columns, then a fetch of display columns (truncated description, KEV/EPSS, has-exploit) for just that page's IDs via `unnest(ARRAY(…)) WITH ORDINALITY`. Doing both at once made Postgres read every candidate's TOASTed description before the top-N sort. For the selective filters `kev=true` and `epss_min`, the matching IDs are built first in a `MATERIALIZED` CTE, because the planner otherwise walks the date index hoping to fill a page and scans most of the table (matching CVEs are old).

Measured on the full corpus (415,607 IDs, local, warm cache): default list, `sort=cvss`, `kev=true`, `epss_min=0.9` ~15–40 ms; `sort=epss`, `exploit=true`, full-text with ~20k matches, `vendor=microsoft` ~170–290 ms; `epss_min` with a very low threshold (fence over ~390k rows) ~600 ms; `GET /cves/{id}` ~5 ms. `order=asc` is not index-backed and sorts in memory.

Pagination is offset-based, capped at offset 10,000 (single user; narrow the filters instead of paging deep). Revisit keyset pagination if needed.

## 9. Frontend

Implemented in `frontend/` (details, routes, and conventions in `frontend/README.md`).

| Page | Route | Content |
|---|---|---|
| Dashboard (milestone 5) | `/` | New CVEs today / 7 d / 30 d, severity distribution, recently KEV-added, highest EPSS, newest critical CVEs, publish-volume trend. Until then `/` redirects to `/cves` |
| CVE list | `/cves` | Filter sidebar (keywords, severity, KEV, exploit, min EPSS, vendor, product, CWE, published range, state), sort control, paginated table (ID, severity + score, EPSS, KEV/exploit tags, title + description, published) |
| CVE detail | `/cves/:id` | Badges; description and CWE links; CVSS per version with vector breakdown and every provider's score; affected products with version ranges and links to vendor/product pages; exploits; references with tags; KEV block; EPSS score and history chart; SSVC; timeline; record metadata with cve.org / NVD links |
| Vendors | `/vendors` | Vendor search and ranking with severity mix bars |
| Vendor | `/vendors/:vendor` | Severity counts, CVEs per year chart, top products table |
| Product | `/vendors/:vendor/products/:product` | Severity counts, CVEs per year, the CVE list fixed to the product |
| Sync | `/sync` | Each source's last success, latest run, cursor, "Run now"; recent runs with counts and errors |

Filter state lives in the URL query string using the API's parameter names, so every view is linkable. The header search box jumps straight to a CVE when given an ID.

## 10. Runtime and configuration

Docker Compose services:

| Service | Image | Port (host) | Notes |
|---|---|---|---|
| `postgres` | `postgres:17` | `127.0.0.1:${POSTGRES_HOST_PORT:-5433}` | Named volume `pgdata`; published on localhost so the backend can also run outside Docker. 5433 avoids clashing with a host Postgres |
| `backend` | built from `backend/` (distroless, non-root) | `127.0.0.1:${BACKEND_HOST_PORT:-8080}` | Applies migrations, then serves the API and runs the sync scheduler. Named volume `workdir` at `/var/lib/pahredar` (`DATA_DIR`) holds download scratch. Container health check runs `/pahredar healthcheck` |
| `frontend` | built from `frontend/` (Node 22 build, `nginx:1.29-alpine` runtime) | `127.0.0.1:${FRONTEND_HOST_PORT:-3001}` | Serves the static build with SPA fallback, proxies `/api/` and `/healthz` to the backend. Default 3001 because 3000 is commonly taken on the dev machine |

All host ports bind to `127.0.0.1` because there is no authentication. For development, the frontend can run with `npm run dev` (Vite proxy to the backend) instead of the container.

Configuration is environment-only, documented in `.env.example`. Secrets (`NVD_API_KEY`, optional `GITHUB_TOKEN`) are copied from the user's local credential store into the gitignored `.env`; they are never committed.

## 11. Future phases

1. **Stack matching:** a watchlist of vendor/product/version and package manifests (`package-lock.json`, `go.mod`, `requirements.txt`) matched against `cve_affected` (CPE + version ranges) and OSV/GitHub Advisory data; "affects me" view ranked KEV → EPSS → CVSS.
2. **Alerts:** notify on new matches, KEV additions, EPSS spikes (Telegram / ntfy / email).
3. **Deployment:** move to the OCI free-tier VM with HTTPS, authentication, and backups.
4. **Search engine:** only if Postgres FTS proves insufficient.

## 12. Decision log

| Date | Decision |
|---|---|
| 2026-10-28 | Project named **Pahredar**. |
| 2026-10-28 | Store the full CVE corpus, not a recent subset. |
| 2026-10-28 | v1 is the CVE application only; stack matching deferred. |
| 2026-10-28 | Postgres as sole datastore; Elasticsearch rejected for now (heavier, not a source of truth, Postgres FTS sufficient at ~300k records). |
| 2026-10-28 | Go backend, React + Vite frontend, local Docker Compose. |
| 2026-10-28 | No foreign keys from enrichment tables to `cve` (sources can lead the cvelist sync). |
| 2026-10-28 | Repository is personal (GitHub `SHIVAM-SHARMA-766`), not office. |
| 2026-10-28 | cvelist sync uses GitHub release archives (baseline + cumulative daily deltas + end-of-day), not per-file raw fetches or a git clone. |
| 2026-10-28 | CISA ADP affected products are stored (`source = 'adp'`); `cve_affected.cpe` became `cpes text[]`. |
| 2026-10-28 | Per-provider metrics and SSVC are derived from raw JSON at read time rather than stored. |
| 2026-10-28 | Sort indexes declared `DESC NULLS LAST, id DESC` to match the API; plain `DESC` indexes went unused (300 ms → 11 ms). |
| 2026-10-28 | NVD bootstrap fetches 4 pages concurrently (~14 min for 208 pages with a key, vs ~2 h sequential). |
| 2026-10-28 | KEV/EPSS/exploit snapshots refuse feeds under half the stored size rather than mirroring a broken download. |
| 2026-10-28 | Each exploit index is its own sync source (isolated failures) sharing one interval. |
| 2026-10-28 | Vendor/product aggregates are materialized views refreshed by a `stats` source after data changes, not live queries (seconds → milliseconds). |
| 2026-10-28 | UI routes lazy-load chart pages (initial JS 327 KB instead of 762 KB). |

### Corpus after first full sync (2026-10-28)

415,607 CVE IDs (396,936 published, 18,671 rejected). Severity: 38,577 critical, 154,937 high, 182,315 medium, 16,348 low, 110 none, 23,320 unknown (the rejected IDs plus ~4.6k new CVEs NVD has not analysed). Severity source: NVD 212k, CNA 180k. 1.59M affected rows (NVD 953k, CNA 516k, ADP 126k). KEV 1,760; EPSS 396,257; exploit rows: Exploit-DB 30,392, Nuclei 4,541, Metasploit 3,536. Database ~4.5 GB.

## 13. Implementation milestones

| # | Milestone | Status |
|---|---|---|
| 1 | Repo skeleton, Compose (Postgres + backend), schema migration, `/healthz` | ✅ Done 2026-10-28 |
| 2 | cvelistV5 bootstrap + incremental sync, scheduler, advisory locks, `sync_run` logging, CVE list/detail + sync status API | ✅ Done 2026-10-28 |
| 3 | NVD, KEV, EPSS, Exploit-DB, Metasploit, Nuclei; NVD CPE affected rows; `kev`/`exploit`/`epss` filters and `sort=epss`; enriched detail + timeline; `POST /sync/{source}` | ✅ Done 2026-10-28 |
| 4 | Frontend: list, detail, vendor, product, sync pages; `frontend` Compose service; vendor API and stats views | ✅ Done 2026-10-28 |
| 5 | Dashboard (`/api/v1/stats/dashboard` + `/` page), polish | Next |
