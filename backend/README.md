# backend

Go module for the Pahredar backend: one binary that applies database migrations, serves the HTTP API, and runs the sync scheduler. See [../ARCHITECTURE.md](../ARCHITECTURE.md) for the overall design (data model §6, sync §7, API §8).

## Layout

| Path | Role |
|---|---|
| `cmd/pahredar/` | Entry point and subcommand dispatch. Owns process lifecycle: signal handling, HTTP server timeouts, graceful shutdown (10 s for HTTP and the scheduler). |
| `internal/config/` | Reads all configuration from environment variables and validates it. |
| `internal/cverecord/` | Pure parsing and derivation, no I/O. `Parse` (CVE JSON 5), `ParseNVD` (NVD API 2.0 `cve` object), `Derive` (effective CVSS, severity, CWEs, merged references, normalized affected products, search text), `Metrics` (all per-provider CVSS, best first), `CISASSVC`. Unit-tested with real records in `testdata/`. |
| `internal/sources/cvelist/` | GitHub client for CVEProject/cvelistV5 releases: release lookup (latest, by tag, recent) and record iteration over the baseline (streamed, nested zip) and delta zips. |
| `internal/sources/nvd/` | NVD CVE API 2.0 pager: request spacing for the rate limit, concurrent page fetches, retry with backoff on 403/429/5xx/network errors. |
| `internal/sources/kev/`, `epss/`, `exploits/`, `cwe/` | Single-file feeds: CISA KEV JSON, EPSS gzip CSV, the Exploit-DB / Metasploit / Nuclei / PoC-in-GitHub indexes (each mapped to `(CVE, source_ref)` entries), and MITRE's CWE CSV. |
| `internal/sources/reports/` | On-demand per-CVE fetchers, normalized into Pahredar's own shapes: OSV (CVE plus GHSA/PYSEC/GO/… aliases, at most 4), Red Hat, Ubuntu (`reports.go`); MSRC, vendor advisory page previews, Google News, Hacker News (`news.go`); NVD history (`history.go`); GitHub fix commits (`commits.go`); AlienVault OTX, ThreatFox, Bluesky (`intel.go`, each needs its key and otherwise returns `ErrNotConfigured`). Advisory previews use `safeClient`, which refuses non-public IPs after DNS resolution. Not a sync source |
| `internal/sources/vulncheck/` | VulnCheck KEV client (cursor-paged index API, needs a free token) |
| `internal/sources/euvd/` | ENISA EUVD exploited-list client (paged search API) |
| `internal/sources/attack/` | CTID KEV→ATT&CK mapping files and the MITRE CAPEC CSV parser |
| `internal/sources/debian/` | Debian Security Tracker JSON, stream-decoded per package |
| `internal/sources/detection/` | Sigma (repository archive), Suricata ET Open, and Nmap script-index parsers producing rules with the CVEs they name |
| `internal/sources/feeds/` | The feed list (`All`: key, name, URL, kind, whether to read article pages) a lenient RSS 2.0 / RDF / Atom parser with CVE ID extraction, readers for GitHub repository security advisories (`FormatGitHub`) and CERT-In's note list (`FormatCERTIn`), and `ArticleText`, which keeps only an article page's own text (uses `golang.org/x/net/html`) |
| `internal/sources/fetch/` | Shared HTTP client and `Get` (User-Agent, non-200 → `StatusError`). |

Source packages know nothing about the database.
| `internal/db/` | Connection pool, embedded goose migrations, and every SQL query: `WriteCVEBatch` (locked, staged `COPY` upsert of `cve` and `cve_affected`), `ReplaceKEV` / `ReplaceExploits` (generic staged snapshot replace with a shrink guard), `ReplaceEPSS` (history diff + truncate/load), `ListCVEs` / `GetCVE`, `ListVendors` / `GetVendor` / `GetProduct` and `RefreshStats` (materialized views), sync cursor and run bookkeeping, advisory locks. |
| `internal/db/migrations/` | Versioned SQL, `NNNNN_name.sql`, each with `-- +goose Up` and `-- +goose Down`. |
| `internal/syncer/` | `Runner` (per-source advisory lock, stale-run cleanup, `sync_run` logging, `OnChange` hook), `Scheduler` (per-task interval loop, failure backoff, on-demand `Trigger`), `buildRow` (derived record → `db.CVERow`), and the jobs: `CVEList`, `NVD`, `Enrichment` (KEV, EPSS, exploit sources, stats refresh). `serve` wires `OnChange` so a cvelist/NVD/KEV run that changed rows triggers `stats`. |
| `internal/api/` | HTTP handlers on the stdlib `ServeMux`: parameter validation, JSON response shapes. `cves.go`, `vendors.go`, `sync.go`. |

Dependency direction: `api` and `syncer` → `db`, `cverecord`; `syncer` → `sources/*`. `cverecord` and `sources/*` depend on nothing internal.

## Subcommands

| Command | Behaviour |
|---|---|
| `pahredar serve` | Applies pending migrations, starts the scheduler (unless `SYNC_ENABLED=false`), listens on `HTTP_ADDR`. Every source runs once at startup; on an empty database that bootstraps everything in the background (~5 min cvelist, ~15 min NVD, seconds for the rest) while the API is already up. |
| `pahredar migrate` | Applies pending migrations and exits. |
| `pahredar sync <source> [--bootstrap]` | Runs one sync in the foreground and exits. Sources: `cvelist`, `nvd`, `kev`, `epss`, `exploitdb`, `metasploit`, `nuclei`, `github`, `trickest`, `sigma`, `suricata`, `nmap`, `euvd`, `debian`, `attack`, `capec`, `vulncheck` (only with `VULNCHECK_API_TOKEN`), `cwe`, `feeds`, `stats`. `--bootstrap` (cvelist, nvd) re-imports everything even when a cursor exists; use after changing derivation logic. Safe while `serve` is up: the per-source lock makes one of them skip. |
| `pahredar recheck-articles` | Re-reads the article pages of `FetchPage` feeds and replaces their CVE IDs. Run after changing how pages are read (`feeds.ArticleText`); under a minute |
| `pahredar rederive` | Rewrites every CVE's derived fields and affected rows from the stored raw JSON, then refreshes stats. Use after changing anything in `cverecord`. ~10 min on the full corpus; safe while `serve` runs (it takes the cvelist and NVD locks) |
| `pahredar healthcheck` | GETs `http://127.0.0.1:8080/healthz`; exit 0 on HTTP 200. Used by the Compose health check because the distroless image has no curl. Assumes the default port. |

Inside Compose: `docker compose exec backend /pahredar sync cvelist`.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | none | Postgres connection string. The pool defaults to 32 connections unless the URL sets `pool_max_conns` |
| `HTTP_ADDR` | no | `:8080` | Listen address |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` (`debug` logs each invalid upstream record) |
| `DATA_DIR` | no | system temp dir | Download scratch; a bootstrap needs ~700 MB free here, briefly |
| `SYNC_ENABLED` | no | `true` | Run the scheduler inside `serve` |
| `CVELIST_SYNC_INTERVAL` | no | `1h` | Go duration, minimum `1m` (all intervals) |
| `NVD_SYNC_INTERVAL` | no | `2h` | |
| `KEV_SYNC_INTERVAL` | no | `6h` | |
| `EPSS_SYNC_INTERVAL` | no | `6h` | Runs are no-ops until a new score date appears |
| `EXPLOITS_SYNC_INTERVAL` | no | `24h` | Shared by exploitdb, metasploit, nuclei |
| `STATS_REFRESH_INTERVAL` | no | `6h` | Fallback; stats also refresh after data-changing cvelist/NVD/KEV runs |
| `CWE_SYNC_INTERVAL` | no | `168h` | MITRE CWE names |
| `FEEDS_SYNC_INTERVAL` | no | `1h` | News, research, PSIRT, and government feeds |
| `DETECTION_SYNC_INTERVAL` | no | `24h` | Sigma, Suricata (ET Open), and Nmap rules |
| `CONTEXT_SYNC_INTERVAL` | no | `24h` | ENISA EUVD, Debian tracker, and VulnCheck KEV; ATT&CK mappings and CAPEC run every 7× this |
| `NVD_API_KEY` | strongly recommended | none | Without it requests are spaced 6.5 s apart instead of 0.7 s |
| `GITHUB_TOKEN` | no | none | Raises the GitHub API limit above 60 requests/hour (cvelist downloads, fix-commit diffs) |
| `VULNCHECK_API_TOKEN` | no | none | Enables the `vulncheck` sync (free Community account at vulncheck.com) |
| `OTX_API_KEY` | no | none | Enables the `otx` report source (otx.alienvault.com → Settings) |
| `ABUSECH_AUTH_KEY` | no | none | Enables the `threatfox` report source (auth.abuse.ch) |
| `BLUESKY_HANDLE`, `BLUESKY_APP_PASSWORD` | no | none | Enable the `bluesky` report source; handle without `@`, an app password, not the account password |

## Endpoints

| Method & path | Notes |
|---|---|
| `GET /healthz` | `200 {"status":"ok","database":"ok"}`, or `503` if Postgres does not answer a ping within 2 s |
| `GET /api/v1/cves` | Search and filter; parameters in ARCHITECTURE.md §8. Example: `/api/v1/cves?vendor=cisco,citrix&kev=true&sort=kev_added&page_size=10` |
| `GET /api/v1/cves/{id}` | Full detail: `cvss`, `metrics`, `ssvc`, `kev`, `epss` (+ `history`), `exploits`, `has_exploit`, `timeline`, `affected`, `references` |
| `GET /api/v1/cves/{id}/reports` | On-demand third-party material, `?sources=` to pick (`internal/api/reports.go`) |
| `GET /api/v1/cves/{id}/related` | CVEs sharing an advisory/patch URL, and same-product CVEs within ±30 days (`internal/api/related.go`) |
| `GET /api/v1/stats/series` | Daily metric series (`published`, `kev_added`, `exploits`) for the dashboard chart (`internal/db/series_read.go`) |
| `GET /api/v1/stats/dashboard` | Landing-page aggregates (`internal/db/dashboard_read.go`; field list in ARCHITECTURE.md §8) |
| `GET /api/v1/cves/{id}/attack` | CTID ATT&CK mappings and CAPEC patterns for a CVE (`internal/db/context.go`) |
| `GET /api/v1/cves/{id}/detection` | Detection rules naming a CVE (`internal/api/feeds.go`, `internal/db/detection.go`) |
| `GET /api/v1/cves/{id}/articles` | Feed articles mentioning a CVE (`internal/api/feeds.go`) |
| `GET /api/v1/stats/trending` | CVEs ranked by distinct feeds mentioning them |
| `GET /api/v1/feeds`, `/api/v1/feeds/advisories` | Feed list with counts; newest vendor/government advisories |
| `GET /api/v1/news` | News page list: filters, top/newest sort, paging, and a badge per named CVE (`internal/api/news.go`, `db.NewsArticles`) |
| `GET /api/v1/vendors` | Vendor ranking/search (`q`, `page_size`) from `vendor_stats` |
| `GET /api/v1/products` | Product ranking/search across vendors (`q`, `page_size`) from `product_stats` |
| `GET /api/v1/vendors/{vendor}` | Vendor summary, CVEs per year, top 200 products |
| `GET /api/v1/vendors/{vendor}/products/{product}` | Product summary and CVEs per year |
| `GET /api/v1/sync/status` | `scheduler_enabled`, `sources` (cursor, last success), `recent_runs` |
| `POST /api/v1/sync/{source}` | Queue a run now (202); 404 unknown source; 409 when the scheduler is disabled |

## Invariants

- CVE IDs are upper-case everywhere; the API upper-cases input.
- Only `db.WriteCVEBatch` writes `cve` / `cve_affected`, always under the `pahredar:cve-write` advisory lock, deriving from both raw records.
- Snapshot replaces (KEV, EPSS, exploits) refuse a feed with fewer than half the stored rows.
- A source's cursor advances only after the archive it describes is fully committed.
- Never edit an applied migration; add the next numbered file.

## Migrations

| File | Change |
|---|---|
| `00001_init.sql` | Full v1 schema (ARCHITECTURE.md §6) |
| `00002_affected_adp_cpes.sql` | `cve_affected.source` allows `adp`; single `cpe` column replaced by `cpes text[]` |
| `00003_sort_indexes.sql` | Sort indexes rebuilt as `DESC NULLS LAST, id DESC` (and a COALESCE CVSS expression index) to match the list API's `ORDER BY` |
| `00004_enrichment.sql` | `kev.forensic_triage`; `cve.exploit_ref` with a backfill from `refs` (~10 s on the full corpus); `kev (date_added DESC, cve_id)` index |
| `00005_vendor_stats.sql` | Materialized views `vendor_stats`, `product_stats`, `vendor_year_stats` with unique indexes (required for `REFRESH … CONCURRENTLY`); ~12 s to create on the full corpus |
| `00013_vulncheck_threat_intel.sql` | `vulncheck_kev`; `otx` / `threatfox` / `bluesky` report sources |
| `00012_attack_exploited_debian.sql` | `euvd_exploited`, `attack_mapping`, `capec`, `debian_status`; `trickest` exploit source; `history` / `commits` report sources |
| `00011_detection.sql` | `detection_rule` (Sigma / Suricata / Nmap rules; GIN on `cve_ids`); `exploit.meta` (Metasploit and Nuclei fields for scan commands) |
| `00010_feed_article.sql` | `feed_article` (feed items with the CVE IDs they mention; GIN on `cve_ids`) |
| `00009_news_advisories_related.sql` | `external_report` allows the `msrc`, `advisories`, `news`, `discussions` sources; GIN `jsonb_path_ops` index on `cve.refs` for related-CVE lookup |
| `00008_external_report.sql` | `external_report` cache for on-demand OSV / Red Hat / Ubuntu reports |
| `00007_labels_cwe_github.sql` | `exploit.source` allows `github`; `cwe` table; `cve_affected.vendor_label` / `product_label`; stats views recreated with a `label` column and a product trigram index. Run `pahredar rederive` afterwards so existing rows get canonical names and real labels |
| `00006_epss_delta.sql` | `epss.score_7d_ago` and generated, indexed `epss.delta_7d` for the dashboard's EPSS movers |

Applied automatically by `serve`, `migrate`, and `sync`; tracked in `goose_db_version`.

After a bulk import, run `VACUUM ANALYZE cve` once (autovacuum gets there eventually) so planner statistics and the visibility map are current.

## Development

```bash
# Postgres from Compose, backend on the host
docker compose up -d postgres
export DATABASE_URL='postgres://pahredar:<password>@127.0.0.1:5433/pahredar?sslmode=disable'
go run ./cmd/pahredar serve

go test ./... && go vet ./... && gofmt -l .
```

## Image

Multi-stage `Dockerfile`: builds a static binary (`CGO_ENABLED=0`) on `golang:1.26-alpine` and runs it on `gcr.io/distroless/static-debian12:nonroot`. `/var/lib/pahredar` is created owned by the nonroot user (65532) so the `workdir` named volume inherits writable ownership.
