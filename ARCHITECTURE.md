# Pahredar — Architecture

> Status: **milestone 1 done** (2026-10-28): Compose stack, Postgres schema, and backend skeleton with `/healthz`. Sync, API, and frontend are not implemented yet. See §13. This document is the source of truth for the design and is updated in the same change as any code, schema, or decision it describes.

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

## 3. Repository layout (planned)

```
pahredar/
├── README.md               user-facing: what it is, how to run it
├── ARCHITECTURE.md         this file
├── docker-compose.yml      postgres + backend + frontend
├── .env.example            every config variable, documented
├── backend/                Go module
│   ├── cmd/pahredar/       main; subcommands: serve, migrate, healthcheck (sync <source> planned)
│   ├── internal/config/    env parsing and validation
│   ├── internal/db/        migrations (embedded SQL) and query code
│   ├── internal/sources/   one package per source: fetch + parse into domain types
│   ├── internal/sync/      scheduler, job runner, run logging, locking
│   └── internal/api/       HTTP handlers, request validation, JSON shapes
└── frontend/               React + Vite + TypeScript app
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
| Routing (UI) | React Router | Standard. |
| Styling | Tailwind CSS | Fast iteration, no component-library lock-in. |
| Charts | Recharts | Sufficient for dashboard trends and distributions. |
| Runtime | Docker Compose | One command to run locally; same images move to a VM later. |

## 5. Data sources

All sources are free. Only NVD needs an API key (free, raises rate limit).

| Source | Provides | Format / access | Cadence |
|---|---|---|---|
| **CVEProject/cvelistV5** | Canonical CVE records (CNA data): description, affected products/versions, references, CWE, CNA CVSS, and CISA ADP "Vulnrichment" (CVSS, SSVC, KEV flag) | GitHub releases: daily full baseline zip + hourly delta zips | Hourly |
| **NVD API 2.0** | NVD analysis: CVSS v2/v3.x/v4 scores, CPE match configurations, CWE, `vulnStatus` | REST, `resultsPerPage` ≤ 2000, `lastModStartDate`/`lastModEndDate` window ≤ 120 days, rate limit 50 req / 30 s with key | Every 2 hours |
| **CISA KEV** | Known-exploited vulnerabilities: date added, due date, required action, ransomware use | Single JSON feed (~1.5k entries) | Daily |
| **EPSS (FIRST)** | Exploit-prediction score and percentile per CVE | Daily gzipped CSV of all scored CVEs | Daily |
| **Exploit-DB** | Public exploits mapped to CVE IDs | `files_exploits.csv` from the exploitdb repo | Daily |
| **Metasploit** | Modules referencing CVEs | `modules_metadata_base.json` from metasploit-framework | Daily |
| **Nuclei templates** | Detection templates per CVE | `cves.json` index from nuclei-templates | Daily |

Exact URLs live in config defaults in `backend/internal/sources/*` and must be verified at implementation time (EPSS in particular has changed hosts before).

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
| `cwe_ids` | text[] | Union of CNA and NVD CWEs |
| `cvss_v4_score`, `cvss_v4_vector` | numeric, text | Effective (see precedence) |
| `cvss_v3_score`, `cvss_v3_vector` | numeric, text | Effective (v3.1 preferred over v3.0) |
| `cvss_v2_score`, `cvss_v2_vector` | numeric, text | Legacy, NVD only |
| `severity` | text | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`/`UNKNOWN`, derived |
| `severity_source` | text | Which metric/provider `severity` came from |
| `nvd_status` | text | NVD `vulnStatus` (e.g. `Analyzed`, `Awaiting Analysis`) |
| `nvd_last_modified` | timestamptz | Drives incremental NVD sync |
| `refs` | jsonb | `[{url, name, tags[]}]`, merged and de-duplicated. Named `refs` because `references` is a reserved word in SQL |
| `raw_cvelist` | jsonb | Original cvelistV5 record |
| `raw_nvd` | jsonb | Original NVD record, nullable |
| `search` | tsvector | id + title + description + vendor/product names, GIN index. Maintained by the sync code, not a generated column, because it draws on `cve_affected` |
| `created_at`, `updated_at` | timestamptz | Local bookkeeping |

Raw source JSON is kept so derived columns can be recomputed after a logic change without re-downloading (estimated a few GB in total).

**Severity precedence** (first available wins): CNA CVSS v4 → NVD CVSS v4 → CNA CVSS v3.1/3.0 → NVD CVSS v3.x → CISA ADP CVSS → NVD CVSS v2. `severity_source` records the winner so the UI can show provenance.

### `cve_affected` — affected products (normalized)

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `cve_id` | text FK → `cve` | |
| `source` | text | `cna` or `nvd` |
| `vendor`, `product` | text | Lower-cased, trimmed; indexed with `pg_trgm` |
| `cpe` | text | CPE 2.3 string when available |
| `versions` | jsonb | Version ranges as provided (`version`, `lessThan`, `lessThanOrEqual`, `status`) |

Rows for a CVE are replaced as a whole on each upsert of that source. This table powers vendor/product pages now and stack matching later.

### `kev`

`cve_id` (PK), `vendor_project`, `product`, `vulnerability_name`, `short_description`, `required_action`, `date_added`, `due_date`, `known_ransomware_use`, `notes`. Full replace on each sync (entries are never expected to disappear, but a removed entry is deleted to mirror the feed).

### `epss` and `epss_history`

- `epss`: `cve_id` PK, `score`, `percentile`, `score_date`. Full replace daily.
- `epss_history`: `(cve_id, score_date)` PK, `score`, `percentile`. A row is written only when a CVE's score changes by ≥ 0.01 from its last history row, keeping growth bounded (a full daily snapshot would be ~100M rows/year).

### `exploit`

`id` PK, `cve_id`, `source` (`exploitdb`/`metasploit`/`nuclei`), `source_ref`, `title`, `url`, `published_at`. Unique on `(source, source_ref, cve_id)` because one exploit or module can cover several CVEs; upserts use that key.

### Foreign keys

Only `cve_affected` references `cve` (with `ON DELETE CASCADE`). The enrichment tables (`kev`, `epss`, `epss_history`, `exploit`) deliberately have **no** foreign key: a source can mention a CVE before the cvelist sync has stored it, and bulk `COPY` loads must not fail on that. Joins to `cve` are plain `LEFT JOIN`s.

### `sync_state` and `sync_run`

- `sync_state`: `source` PK, `cursor` (text; meaning is source-specific, e.g. last delta timestamp or NVD `lastModified`), `last_success_at`.
- `sync_run`: `id`, `source`, `kind` (`bootstrap`/`incremental`), `started_at`, `finished_at`, `status` (`running`/`success`/`failed`), `inserted`, `updated`, `deleted`, `error`.

### Derived, not stored

- **Timeline** on the detail page (reserved → published → NVD analyzed → KEV added → first exploit → EPSS spikes) is assembled at query time from the tables above.
- **Has public exploit** = exists in `exploit` OR KEV-listed OR a reference tagged `Exploit`.

## 7. Sync design

### Principles

- **Idempotent:** every job is an upsert; re-running a job or replaying a window is safe.
- **Cursor-based:** incremental jobs read their cursor from `sync_state` and only advance it after a successful commit.
- **One job per source, never concurrent with itself:** a Postgres advisory lock keyed on the source name guards each run.
- **Failures are isolated:** a failing source does not block others; the error is recorded in `sync_run` and retried on the next tick with exponential backoff (capped).
- **Bulk loads use `COPY`** into a temp staging table, then a single `INSERT ... ON CONFLICT DO UPDATE`.

### Bootstrap (first run, empty DB)

1. **cvelistV5:** download the latest daily baseline zip, stream-parse each record, load in batches of ~5k. Set cursor to the baseline's timestamp.
2. **NVD:** full paginated pull (~160+ pages of 2000) respecting the rate limit; set cursor to the newest `lastModified` seen.
3. **KEV, EPSS, exploits:** normal full runs.
4. Recompute derived columns (`severity`, `search`).

Bootstrap is triggered automatically when `sync_state` has no row for a source, or manually via `pahredar sync <source> --bootstrap`.

### Incremental

| Source | Schedule | Mechanism |
|---|---|---|
| cvelist | hourly | Fetch delta zip(s) newer than cursor; if the gap exceeds 24 h, fall back to a fresh baseline. |
| nvd | every 2 h | `lastModStartDate = cursor`, `lastModEndDate = now`, split into ≤ 120-day windows. |
| kev | daily | Full feed replace. |
| epss | daily | Full CSV via `COPY`, then history diff. |
| exploitdb / metasploit / nuclei | daily | Full index re-read, upsert by `(source, source_ref, cve_id)`. |

Schedules are configurable via environment variables.

## 8. HTTP API

JSON over REST under `/api/v1`. Read-only except sync triggers.

| Method & path | Purpose |
|---|---|
| `GET /healthz` | Liveness + DB connectivity |
| `GET /api/v1/cves` | Search/list. Params: `q`, `severity`, `kev`, `exploit`, `vendor`, `product`, `cwe`, `published_from`, `published_to`, `epss_min`, `state`, `sort` (`published`, `updated`, `cvss`, `epss`), `page`, `page_size` (≤ 100) |
| `GET /api/v1/cves/{id}` | Full detail: core fields, metrics, affected, references, KEV, EPSS (+ history), exploits, timeline |
| `GET /api/v1/stats/dashboard` | Counts and series for the dashboard |
| `GET /api/v1/vendors?q=` | Vendor autocomplete / list with CVE counts |
| `GET /api/v1/vendors/{vendor}` | Vendor summary + products |
| `GET /api/v1/vendors/{vendor}/products/{product}` | Product summary (CVE list via `/cves?vendor=&product=`) |
| `GET /api/v1/sync/status` | Per-source state and recent runs |
| `POST /api/v1/sync/{source}` | Trigger a run now |

Search behaviour: if `q` matches a CVE ID pattern, return an exact lookup; otherwise use `websearch_to_tsquery` against `search`, ranked by `ts_rank` then recency.

Pagination is offset-based (single user, bounded page size); revisit keyset pagination if deep pages become slow.

## 9. Frontend

| Page | Content |
|---|---|
| Dashboard | New CVEs today / 7 d / 30 d, severity distribution, recently KEV-added, highest EPSS movers, newest critical CVEs, publish-volume trend chart |
| CVE list | Search box, filter sidebar, sortable paginated table (ID, title, severity, CVSS, EPSS, KEV, exploit, published) |
| CVE detail | Header badges (severity, KEV, exploit), description, CVSS vector breakdown per version with provenance, EPSS score + history chart, KEV block, affected products/versions, CWE, references grouped by tag, exploits, timeline |
| Vendor / product | CVE counts by severity and year, product list, link into filtered CVE list |
| Sync status | Per-source last success, cursor, recent runs with counts and errors |

Filter state lives in the URL query string so every view is linkable.

## 10. Runtime and configuration

Docker Compose services:

| Service | Image | Port (host) | Notes |
|---|---|---|---|
| `postgres` | `postgres:17` | `127.0.0.1:${POSTGRES_HOST_PORT:-5433}` | Named volume `pgdata`; published on localhost so the backend can also run outside Docker. 5433 avoids clashing with a host Postgres |
| `backend` | built from `backend/` (distroless, non-root) | `127.0.0.1:${BACKEND_HOST_PORT:-8080}` | Applies migrations on start, then serves the API (scheduler planned). Container health check runs `/pahredar healthcheck` |
| `frontend` (planned) | built from `frontend/` (nginx) | `127.0.0.1:${FRONTEND_HOST_PORT:-3001}` | Serves static build, proxies `/api` to backend. Default is 3001 because 3000 is commonly taken on the dev machine |

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

## 13. Implementation milestones

| # | Milestone | Status |
|---|---|---|
| 1 | Repo skeleton, Compose (Postgres + backend), schema migration, `/healthz` | ✅ Done 2026-10-28 |
| 2 | cvelistV5 bootstrap + incremental sync, `sync_run` logging, CVE list/detail API | Next |
| 3 | NVD, KEV, EPSS, exploit sources; scheduler with advisory locks; severity and search recompute | Planned |
| 4 | Frontend: list, detail, vendor, sync status pages; `frontend` Compose service | Planned |
| 5 | Dashboard stats and charts, polish | Planned |
