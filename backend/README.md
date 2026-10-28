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
| `internal/sources/kev/`, `epss/`, `exploits/` | Single-file feeds: CISA KEV JSON, EPSS gzip CSV, and the Exploit-DB / Metasploit / Nuclei indexes (each mapped to `(CVE, source_ref)` entries). |
| `internal/sources/fetch/` | Shared HTTP client and `Get` (User-Agent, non-200 → `StatusError`). |

Source packages know nothing about the database.
| `internal/db/` | Connection pool, embedded goose migrations, and every SQL query: `WriteCVEBatch` (locked, staged `COPY` upsert of `cve` and `cve_affected`), `ReplaceKEV` / `ReplaceExploits` (generic staged snapshot replace with a shrink guard), `ReplaceEPSS` (history diff + truncate/load), `ListCVEs` / `GetCVE`, sync cursor and run bookkeeping, advisory locks. |
| `internal/db/migrations/` | Versioned SQL, `NNNNN_name.sql`, each with `-- +goose Up` and `-- +goose Down`. |
| `internal/syncer/` | `Runner` (per-source advisory lock, stale-run cleanup, `sync_run` logging), `Scheduler` (per-task interval loop, failure backoff, on-demand `Trigger`), `buildRow` (derived record → `db.CVERow`), and the jobs: `CVEList`, `NVD`, `Enrichment` (KEV, EPSS, exploit sources). |
| `internal/api/` | HTTP handlers on the stdlib `ServeMux`: parameter validation, JSON response shapes. |

Dependency direction: `api` and `syncer` → `db`, `cverecord`; `syncer` → `sources/*`. `cverecord` and `sources/*` depend on nothing internal.

## Subcommands

| Command | Behaviour |
|---|---|
| `pahredar serve` | Applies pending migrations, starts the scheduler (unless `SYNC_ENABLED=false`), listens on `HTTP_ADDR`. Every source runs once at startup; on an empty database that bootstraps everything in the background (~5 min cvelist, ~15 min NVD, seconds for the rest) while the API is already up. |
| `pahredar migrate` | Applies pending migrations and exits. |
| `pahredar sync <source> [--bootstrap]` | Runs one sync in the foreground and exits. Sources: `cvelist`, `nvd`, `kev`, `epss`, `exploitdb`, `metasploit`, `nuclei`. `--bootstrap` (cvelist, nvd) re-imports everything even when a cursor exists; use after changing derivation logic. Safe while `serve` is up: the per-source lock makes one of them skip. |
| `pahredar healthcheck` | GETs `http://127.0.0.1:8080/healthz`; exit 0 on HTTP 200. Used by the Compose health check because the distroless image has no curl. Assumes the default port. |

Inside Compose: `docker compose exec backend /pahredar sync cvelist`.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | none | Postgres connection string |
| `HTTP_ADDR` | no | `:8080` | Listen address |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` (`debug` logs each invalid upstream record) |
| `DATA_DIR` | no | system temp dir | Download scratch; a bootstrap needs ~700 MB free here, briefly |
| `SYNC_ENABLED` | no | `true` | Run the scheduler inside `serve` |
| `CVELIST_SYNC_INTERVAL` | no | `1h` | Go duration, minimum `1m` (all intervals) |
| `NVD_SYNC_INTERVAL` | no | `2h` | |
| `KEV_SYNC_INTERVAL` | no | `6h` | |
| `EPSS_SYNC_INTERVAL` | no | `6h` | Runs are no-ops until a new score date appears |
| `EXPLOITS_SYNC_INTERVAL` | no | `24h` | Shared by exploitdb, metasploit, nuclei |
| `NVD_API_KEY` | strongly recommended | none | Without it requests are spaced 6.5 s apart instead of 0.7 s |
| `GITHUB_TOKEN` | no | none | Raises the GitHub API limit above 60 requests/hour; not needed at the default interval |

## Endpoints

| Method & path | Notes |
|---|---|
| `GET /healthz` | `200 {"status":"ok","database":"ok"}`, or `503` if Postgres does not answer a ping within 2 s |
| `GET /api/v1/cves` | Search and filter; parameters in ARCHITECTURE.md §8. Example: `/api/v1/cves?kev=true&sort=epss&page_size=10` |
| `GET /api/v1/cves/{id}` | Full detail: `cvss`, `metrics`, `ssvc`, `kev`, `epss` (+ `history`), `exploits`, `has_exploit`, `timeline`, `affected`, `references` |
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
